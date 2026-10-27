#!/usr/bin/env python3
"""Boot QEMU and exercise the userspace HTTP server through its e1000 NIC."""

import argparse
from contextlib import ExitStack
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

from network_test import (check_process, positive_timeout, remaining, show_logs,
                          stop_qemu)


USERSPACE_MARKER = b"Userspace web server: CPL=3"
READY_MARKER = b"HTTP listening on 10.0.2.15:80"
MAX_RESPONSE = 65536
REQUEST = b"GET /healthz HTTP/1.1\r\nHost: kernel\r\n\r\n"


def launch_qemu(args: argparse.Namespace, serial_path: Path,
                stderr_path: Path, deadline: float) -> tuple[subprocess.Popen, int]:
    # QEMU must bind the port itself. Retry the narrow reservation-release race.
    for attempt in range(3):
        remaining(deadline)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        command = [
            args.qemu, "-machine", "q35", "-device", "intel-iommu,intremap=off", "-accel", "tcg", "-cpu", "max,-apic", "-m", "128M",
            "-smp", "1", "-kernel", str(args.kernel), "-display", "none",
            "-serial", "stdio", "-monitor", "none", "-no-reboot", "-no-shutdown",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-10.0.2.15:80",
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
                serial_output = serial_path.read_bytes()
                ready_index = serial_output.find(READY_MARKER)
                if ready_index >= 0:
                    if USERSPACE_MARKER not in serial_output[:ready_index].splitlines():
                        raise RuntimeError("HTTP became ready without a preceding userspace CPL=3 marker")
                    return process, port
                time.sleep(min(0.02, remaining(deadline)))
        except BaseException:
            stop_qemu(process)
            raise
        stop_qemu(process)
    raise RuntimeError("QEMU could not reserve an HTTP forwarding port after three tries")


def operation_deadline(deadline: float, seconds: float = 4.0) -> float:
    remaining(deadline)
    return min(deadline, time.monotonic() + seconds)


def connect(port: int, deadline: float) -> socket.socket:
    connection = socket.create_connection(("127.0.0.1", port), remaining(deadline))
    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return connection


def send(connection: socket.socket, data: bytes, deadline: float) -> None:
    connection.settimeout(remaining(deadline))
    connection.sendall(data)


def read_response(connection: socket.socket, deadline: float,
                  process: subprocess.Popen) -> bytes:
    response = bytearray()
    while True:
        check_process(process)
        try:
            connection.settimeout(min(0.1, remaining(deadline)))
        except TimeoutError as error:
            raise TimeoutError(
                f"HTTP response timed out before EOF after {len(response)} bytes: "
                f"{bytes(response[:200])!r}"
            ) from error
        try:
            data = connection.recv(4096)
        except socket.timeout:
            continue
        if not data:
            return bytes(response)
        response.extend(data)
        if len(response) > MAX_RESPONSE:
            raise RuntimeError("HTTP response exceeded 64 KiB")


def validate(response: bytes, status: int, content_type: str = "text/plain",
             *, body: bytes | None = None,
             head_length: int | None = None) -> tuple[dict[str, str], bytes]:
    try:
        header, received_body = response.split(b"\r\n\r\n", 1)
        lines = header.decode("ascii").split("\r\n")
        version, code, _reason = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            name = name.lower()
            if name in headers:
                raise ValueError(f"duplicate {name} header")
            headers[name] = value.strip()
        length = int(headers["content-length"])
    except (ValueError, KeyError, UnicodeDecodeError) as error:
        raise RuntimeError(f"malformed HTTP response: {response[:300]!r}") from error
    if version not in ("HTTP/1.0", "HTTP/1.1") or code != str(status):
        raise RuntimeError(f"expected HTTP {status}, got {lines[0]!r}")
    if headers.get("connection", "").lower() != "close":
        raise RuntimeError("HTTP response did not declare Connection: close")
    if headers.get("content-type", "").split(";", 1)[0] != content_type:
        raise RuntimeError(f"unexpected HTTP content type: {headers.get('content-type')}")
    if length < 0 or (head_length is None and length != len(received_body)):
        raise RuntimeError("HTTP Content-Length does not match the response body")
    if head_length is not None and (length != head_length or received_body):
        raise RuntimeError("HEAD must preserve GET Content-Length without sending a body")
    if body is not None and received_body != body:
        raise RuntimeError(f"unexpected HTTP body: {received_body[:100]!r}")
    return headers, received_body


def exchange(port: int, request: bytes, deadline: float,
             process: subprocess.Popen, *, half_close: bool = False,
             timeout: float = 4.0) -> bytes:
    limit = operation_deadline(deadline, timeout)
    try:
        with connect(port, limit) as connection:
            send(connection, request, limit)
            if half_close:
                connection.shutdown(socket.SHUT_WR)
            return read_response(connection, limit, process)
    except (OSError, RuntimeError) as error:
        request_line = request.split(b"\r\n", 1)[0]
        raise RuntimeError(
            f"{request_line!r} ({len(request)} request bytes, "
            f"half_close={half_close}): {error}"
        ) from error


def expect_no_response(connection: socket.socket, deadline: float,
                       process: subprocess.Popen) -> None:
    check_process(process)
    readable, _, _ = select.select([connection], [], [], min(0.1, remaining(deadline)))
    if readable:
        raise RuntimeError("HTTP server replied or closed before the header was complete")


def check_concurrency(port: int, deadline: float, process: subprocess.Popen) -> None:
    limit = operation_deadline(deadline)
    with ExitStack() as stack:
        # Keep a third connection incomplete while two other clients finish.
        slow = stack.enter_context(connect(port, limit))
        first = stack.enter_context(connect(port, limit))
        second = stack.enter_context(connect(port, limit))
        send(slow, b"GET / HTTP/1.1\r\nHost: ", limit)
        for connection in (first, second):
            send(connection, REQUEST[:-2], limit)
            expect_no_response(connection, limit, process)
        for connection in (first, second):
            send(connection, b"\r\n", limit)
        for connection in (first, second):
            validate(read_response(connection, limit, process), 200, body=b"ok\n")
        send(slow, b"kernel\r\n\r\n", limit)
        validate(read_response(slow, limit, process), 200, "text/html")
    print("Fragmented headers and parallel requests with an incomplete client passed.")


def check_request_deadline(port: int, deadline: float,
                           process: subprocess.Popen) -> None:
    limit = operation_deadline(deadline, 8.0)
    with connect(port, limit) as connection:
        send(connection, b"GET / HTTP/1.1\r\nHost: ", limit)
        started = time.monotonic()
        while True:
            check_process(process)
            readable, _, _ = select.select([connection], [], [],
                                            min(0.75, remaining(limit)))
            try:
                if readable:
                    connection.settimeout(remaining(limit))
                    if connection.recv(4096):
                        raise RuntimeError("incomplete request unexpectedly received a response")
                    break
                # Progress must not let a slow client extend the absolute deadline.
                send(connection, b"a", limit)
            except (ConnectionResetError, BrokenPipeError):
                break
        if time.monotonic() - started < 3.0:
            raise RuntimeError("incomplete HTTP request closed before its request deadline")
    validate(exchange(port, REQUEST, deadline, process), 200, body=b"ok\n")
    print("Slow request deadline and subsequent listener recovery passed.")


def run_http_checks(port: int, deadline: float, process: subprocess.Popen) -> None:
    # On a cold slirp backend, initial ARP discovery can delay forwarding the
    # first SYN by over six seconds. Later requests retain the four-second limit.
    headers, page = validate(exchange(port, b"GET / HTTP/1.1\r\nHost: kernel\r\n\r\n",
                                      deadline, process, timeout=10.0), 200, "text/html")
    if b"Rust kernel" not in page:
        raise RuntimeError("root page does not identify the Rust kernel")
    if b"userspace process running in ring 3" not in page:
        raise RuntimeError("root page does not identify the ring-3 userspace server")
    validate(exchange(port, b"HEAD / HTTP/1.1\r\nHost: kernel\r\n\r\n", deadline, process),
             200, "text/html", head_length=int(headers["content-length"]))
    validate(exchange(port, REQUEST, deadline, process), 200, body=b"ok\n")
    validate(exchange(port, REQUEST.replace(b"GET", b"HEAD", 1), deadline, process),
             200, head_length=3)
    validate(exchange(port, REQUEST.replace(b"/healthz", b"/healthz?probe=1"),
                      deadline, process), 200, body=b"ok\n")
    validate(exchange(port, b"GET /healthz HTTP/1.0\r\n\r\n", deadline, process),
             200, body=b"ok\n")
    validate(exchange(port, REQUEST.replace(b"/healthz", b"/missing"), deadline, process),
             404)
    headers, _ = validate(exchange(port, REQUEST.replace(b"GET", b"POST", 1),
                                   deadline, process), 405)
    if headers.get("allow") != "GET, HEAD":
        raise RuntimeError("405 response did not advertise Allow: GET, HEAD")
    for request in (b"GET / HTTP/1.1\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost: kernel\r\nInvalid-header\r\n\r\n",
                    b"bad request\r\n\r\n"):
        validate(exchange(port, request, deadline, process), 400)
    oversized = b"GET / HTTP/1.1\r\nHost: kernel\r\nX-Padding: " + b"x" * 2048 + b"\r\n\r\n"
    validate(exchange(port, oversized, deadline, process), 431)
    validate(exchange(port, b"GET / HTTP/1.1\r\nHost:", deadline, process, half_close=True),
             400)
    print("GET, HEAD, query routing, HTTP/1.0, errors, and half-close passed.")

    for _ in range(16):
        validate(exchange(port, REQUEST, deadline, process), 200, body=b"ok\n")
    print("Sixteen repeated HTTP connections passed.")
    check_concurrency(port, deadline, process)

    limit = operation_deadline(deadline)
    with connect(port, limit) as connection:
        send(connection, REQUEST, limit)
        connection.settimeout(remaining(limit))
        if not connection.recv(1):
            raise RuntimeError("HTTP connection closed before the reset test response")
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    validate(exchange(port, REQUEST, deadline, process), 200, body=b"ok\n")
    print("Abrupt HTTP reset and listener recovery passed.")
    check_request_deadline(port, deadline, process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="QEMU executable name or path")
    parser.add_argument("kernel", type=Path, help="normal kernel binary to boot")
    parser.add_argument("--timeout", type=positive_timeout, default=45.0,
                        help="total boot and HTTP time limit in seconds (default: 45)")
    args = parser.parse_args()
    process = None
    deadline = time.monotonic() + args.timeout
    with tempfile.TemporaryDirectory(prefix="kernel-http-test-") as directory:
        serial_path = Path(directory) / "serial.log"
        stderr_path = Path(directory) / "stderr.log"
        try:
            process, port = launch_qemu(args, serial_path, stderr_path, deadline)
            run_http_checks(port, deadline, process)
            check_process(process)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"QEMU HTTP test failed: {error}", file=sys.stderr)
            stop_qemu(process)
            show_logs(serial_path, stderr_path)
            return 1
        finally:
            stop_qemu(process)
    print("QEMU e1000/IPv4/TCP/HTTP integration test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
