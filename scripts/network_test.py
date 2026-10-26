#!/usr/bin/env python3
"""Boot QEMU with an e1000 NIC and exercise the kernel's TCP echo server."""

import argparse
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time


READY_MARKER = b"TCP echo listening on 10.0.2.15:1234"
PAYLOAD = bytes(range(256)) * 1280  # 320 KiB exceeds both NIC and socket rings.
FRAGMENTS = (1, 7, 63, 257, 1448, 4093)


def positive_timeout(value: str) -> float:
    timeout = float(value)
    if not 0 < timeout < float("inf"):
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return timeout


def remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("network test exceeded its total time limit")
    return seconds


def check_process(process: subprocess.Popen) -> None:
    status = process.poll()
    if status is not None:
        raise RuntimeError(f"QEMU exited unexpectedly with status {status}")


def stop_qemu(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def show_logs(serial_path: Path, stderr_path: Path) -> None:
    for label, path in (("QEMU serial output", serial_path),
                        ("QEMU stderr", stderr_path)):
        if path.exists():
            output = path.read_text(encoding="utf-8", errors="replace").strip()
            if output:
                print(f"{label}:\n{output}", file=sys.stderr)


def launch_qemu(args: argparse.Namespace, serial_path: Path,
                stderr_path: Path, deadline: float) -> tuple[subprocess.Popen, int]:
    # QEMU needs to bind the port itself. Keep the reservation until just before
    # spawning it, and retry its specific bind failure to cover the small race.
    for attempt in range(3):
        remaining(deadline)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        command = [
            args.qemu,
            "-machine", "pc",
            "-accel", "tcg",
            "-m", "128M",
            "-smp", "1",
            "-kernel", str(args.kernel),
            "-display", "none",
            "-serial", "stdio",
            "-monitor", "none",
            "-no-reboot",
            "-no-shutdown",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-10.0.2.15:1234",
            "-device", "e1000,netdev=net0",
        ]
        with serial_path.open("wb") as serial, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=serial, stderr=stderr)
        try:
            while True:
                remaining(deadline)
                if process.poll() is not None:
                    error = stderr_path.read_text(encoding="utf-8", errors="replace")
                    port_conflict = ("Could not set up host forwarding rule" in error
                                     or "Address already in use" in error)
                    if port_conflict and attempt < 2:
                        break
                    check_process(process)
                if READY_MARKER in serial_path.read_bytes():
                    return process, port
                time.sleep(min(0.02, remaining(deadline)))
        except BaseException:
            stop_qemu(process)
            raise
        stop_qemu(process)
    raise RuntimeError("QEMU could not reserve a TCP forwarding port after three tries")


def connect(port: int, deadline: float) -> socket.socket:
    connection = socket.create_connection(("127.0.0.1", port), remaining(deadline))
    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connection.setblocking(False)
    return connection


def exchange(connection: socket.socket, payload: bytes, deadline: float,
             process: subprocess.Popen, *, half_close: bool) -> None:
    """Send and receive together so a full TCP receive window cannot deadlock."""
    sent = received = fragment = 0
    write_closed = False
    while True:
        check_process(process)
        if sent == len(payload) and half_close and not write_closed:
            connection.shutdown(socket.SHUT_WR)
            write_closed = True
        if not half_close and received == len(payload):
            return
        readable, writable, exceptional = select.select(
            [connection], [connection] if sent < len(payload) else [],
            [connection], min(0.1, remaining(deadline)),
        )
        if exceptional:
            raise RuntimeError("TCP socket reported an exceptional condition")
        if writable:
            length = FRAGMENTS[fragment % len(FRAGMENTS)]
            try:
                count = connection.send(payload[sent:sent + length])
            except BlockingIOError:
                count = 0
            sent += count
            if count:
                fragment += 1
        if readable:
            try:
                data = connection.recv(65536)
            except BlockingIOError:
                continue
            if not data:
                if received != len(payload):
                    raise RuntimeError(
                        f"TCP closed after echoing {received} of {len(payload)} bytes"
                    )
                if not write_closed:
                    raise RuntimeError("TCP closed before the client's write half-close")
                return
            expected = payload[received:received + len(data)]
            if data != expected:
                raise RuntimeError(f"TCP echo differs at or after byte {received}")
            received += len(data)


def run_network_checks(port: int, deadline: float, process: subprocess.Popen) -> None:
    with connect(port, deadline) as connection:
        exchange(connection, PAYLOAD, deadline, process, half_close=True)
    print(f"TCP binary echo and half-close passed ({len(PAYLOAD):,} bytes).")

    # Every connection must finish with EOF, and the listener must reopen.
    for payload in (b"", b"hello kernel\n", b"\x00\xff\x80\r\n" * 97):
        with connect(port, deadline) as connection:
            exchange(connection, payload, deadline, process, half_close=True)
    print("Repeated TCP connections and empty-stream close passed.")

    # Wait for an echo before resetting, proving that the guest accepted this
    # connection. SO_LINGER with a zero timeout makes close send an RST.
    with connect(port, deadline) as connection:
        exchange(connection, b"reset this connection\x00\xff", deadline, process,
                 half_close=False)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                              struct.pack("ii", 1, 0))
    with connect(port, deadline) as connection:
        exchange(connection, b"listener recovered after reset\n", deadline,
                 process, half_close=True)
    print("TCP reset and listener recovery passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="QEMU executable name or path")
    parser.add_argument("kernel", type=Path, help="normal kernel binary to boot")
    parser.add_argument("--timeout", type=positive_timeout, default=30.0,
                        help="total boot and network time limit in seconds (default: 30)")
    args = parser.parse_args()
    process = None
    deadline = time.monotonic() + args.timeout
    with tempfile.TemporaryDirectory(prefix="kernel-network-test-") as directory:
        serial_path = Path(directory) / "serial.log"
        stderr_path = Path(directory) / "stderr.log"
        try:
            process, port = launch_qemu(args, serial_path, stderr_path, deadline)
            run_network_checks(port, deadline, process)
            check_process(process)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"QEMU network test failed: {error}", file=sys.stderr)
            stop_qemu(process)
            show_logs(serial_path, stderr_path)
            return 1
        finally:
            stop_qemu(process)
    print("QEMU e1000/IPv4/TCP integration test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
