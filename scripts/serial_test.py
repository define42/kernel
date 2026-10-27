#!/usr/bin/env python3
"""Exercise serial commands, live NIC configuration, and HTTP in private QEMU."""

import argparse
from contextlib import ExitStack
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

from http_test import REQUEST, exchange, validate
from network_test import (check_process, connect as echo_connect, exchange as echo_exchange,
                          positive_timeout, remaining, show_logs, stop_qemu)


PROMPT = b"kernel> "
HTTP_READY = b"HTTP listening on port 80"
REFUSAL = b"Network isolation unavailable:"


def check_guest(process, serial):
    check_process(process)
    output = serial.read_bytes() if serial.exists() else b""
    if b"KERNEL PANIC" in output:
        raise RuntimeError("kernel panicked during serial test")
    return output


def launch(args, root, deadline, *, iommu):
    serial = root / ("normal.log" if iommu else "no-iommu.log")
    stderr = serial.with_suffix(".err")
    for attempt in range(3):
        remaining(deadline)
        with ExitStack() as reservations:
            ports = {}
            for name in ("console", "http15", "http16", "echo15", "echo16"):
                reserve = reservations.enter_context(socket.socket())
                reserve.bind(("127.0.0.1", 0))
                ports[name] = reserve.getsockname()[1]
        forwards = ",".join(
            f"hostfwd=tcp:127.0.0.1:{ports[name]}-10.0.2.{address}:{guest_port}"
            for name, address, guest_port in (("http15", 15, 80), ("http16", 16, 80),
                                              ("echo15", 15, 1234), ("echo16", 16, 1234))
        )
        command = [
            args.qemu, "-machine", "q35", "-accel", "tcg", "-cpu", "max,-apic",
            "-m", "128M", "-smp", "1", "-kernel", str(args.kernel),
            "-display", "none", "-monitor", "none", "-no-reboot", "-no-shutdown",
            "-chardev", f"socket,id=com1,host=127.0.0.1,port={ports['console']},"
            f"server=on,wait=off,logfile={serial},logappend=off",
            "-serial", "chardev:com1", "-device", "e1000,netdev=net0",
            "-netdev", "user,id=net0," + forwards,
        ]
        if iommu:
            command += ["-device", "intel-iommu,intremap=off"]
        with stderr.open("wb") as errors:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=errors)
        try:
            while True:
                if process.poll() is not None:
                    message = stderr.read_text(errors="replace")
                    if attempt < 2 and ("Address already in use" in message
                                        or "Could not set up host forwarding rule" in message):
                        break
                output = check_guest(process, serial)
                if PROMPT in output and (HTTP_READY if iommu else REFUSAL) in output:
                    return process, ports, serial, stderr
                time.sleep(min(0.01, remaining(deadline)))
        except BaseException:
            stop_qemu(process)
            show_logs(serial, stderr)
            raise
        stop_qemu(process)
    raise RuntimeError("could not reserve serial/HTTP ports after three attempts")


class Console:
    def __init__(self, port, process, serial, deadline):
        self.process = process
        self.serial = serial
        self.deadline = deadline
        self.pending = bytearray()
        self.socket = socket.create_connection(("127.0.0.1", port), remaining(deadline))
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.setblocking(False)

    def close(self):
        self.socket.close()

    def read(self, seconds=0.05):
        check_guest(self.process, self.serial)
        readable, _, _ = select.select([self.socket], [], [], min(max(0.0, seconds), remaining(self.deadline)))
        if readable:
            data = self.socket.recv(4096)
            if not data:
                raise RuntimeError("serial connection unexpectedly closed")
            self.pending.extend(data)
            if len(self.pending) > 65536:
                raise RuntimeError("serial response exceeded 64 KiB")

    def send(self, data, *, chunk_size=4):
        # Keep each burst well below the 16-byte UART FIFO. Reading between
        # bursts also prevents output backpressure during long input lines.
        for offset in range(0, len(data), chunk_size):
            chunk = memoryview(data)[offset:offset + chunk_size]
            while chunk:
                check_guest(self.process, self.serial)
                _, writable, _ = select.select([], [self.socket], [], min(0.1, remaining(self.deadline)))
                if writable:
                    try:
                        sent = self.socket.send(chunk)
                    except BlockingIOError:
                        continue
                    chunk = chunk[sent:]
            until = time.monotonic() + 0.015
            while time.monotonic() < until:
                self.read(min(0.01, until - time.monotonic()))

    def command(self, data, *, chunk_size=4):
        self.send(data, chunk_size=chunk_size)
        while True:
            end = self.pending.find(PROMPT)
            if end >= 0:
                response = bytes(self.pending[:end])
                del self.pending[:end + len(PROMPT)]
                return response
            self.read()

    def quiet(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.read(min(0.02, end - time.monotonic()))
        output = bytes(self.pending)
        self.pending.clear()
        return output


def require_help(output):
    lower = output.lower()
    if not all(word in lower for word in (b"help", b"pci", b"uptime", b"nic")):
        raise RuntimeError(f"help response is incomplete: {output!r}")


def require_nic(output):
    lower = output.lower()
    if b"8086:100e" not in lower or not re.search(rb"\b(?:0000:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b", lower):
        raise RuntimeError(f"PCI listing did not identify e1000 and its BDF: {output!r}")


def shell_checks(console):
    # wait=off may discard the initial prompt before the socket attaches.
    console.command(b"\x03")
    require_help(console.command(b"help\r"))
    devices = console.command(b"pci\n")
    require_nic(devices)
    if b"host bridge" not in devices.lower():
        raise RuntimeError("full PCI listing omitted QEMU's host bridge")
    nic_row = next(line for line in devices.splitlines() if b"8086:100e" in line.lower())
    print("Serial PCI: " + nic_row.decode("ascii", errors="replace"))
    require_nic(console.command(b"lspci\r\n"))
    if PROMPT in console.quiet(0.1):
        raise RuntimeError("CRLF executed a second empty command")
    network_devices = console.command(b"pci net\r")
    require_nic(network_devices)
    if b"host bridge" in network_devices.lower():
        raise RuntimeError("network PCI filter included the host bridge")
    # Five bytes fit one UART FIFO burst: begin a scan, then cancel it before
    # its bounded continuation runs. A fresh help command must work immediately.
    cancelled_scan = console.command(b"pci\r\x03", chunk_size=8)
    if b"^C" not in cancelled_scan or b"PCI segment" not in cancelled_scan:
        raise RuntimeError(f"PCI scan cancellation was not acknowledged: {cancelled_scan!r}")
    if b"PCI device(s)" in cancelled_scan + console.quiet(0.1):
        raise RuntimeError("cancelled PCI scan completed instead of stopping")
    require_help(console.command(b"help\r"))
    for corrupt in (b"he\x1b[Alp\r", b"\xffhelp\n"):
        rejected = console.command(corrupt)
        if b"invalid serial input" not in rejected.lower() or b"Show commands" in rejected:
            raise RuntimeError(f"corrupt input was not discarded: {rejected!r}")
        require_help(console.command(b"help\r"))
    require_help(console.command(b"helX\x08p\r"))
    require_help(console.command(b"helpX\x7f\n"))
    cancelled = console.command(b"not-a-command\x03")
    if b"unknown command" in cancelled.lower():
        raise RuntimeError("Ctrl-C executed the cancelled command")
    unknown = console.command(b"not-a-command\r")
    if b"unknown command" not in unknown.lower():
        raise RuntimeError(f"unknown command was not rejected: {unknown!r}")
    require_help(console.command(b"help\n"))
    require_help(console.command(b"help" + b" " * 2044 + b"\r"))  # Exactly 2048 bytes.
    # Byte 2049 must reject the whole line; a truncating parser would run 'help'.
    overflow = console.command(b"help" + b" " * 2045 + b"\r")
    if b"line too long" not in overflow.lower():
        raise RuntimeError(f"overlong serial line was not rejected: {overflow!r}")
    require_help(console.command(b"help\r\n"))
    uptime = console.command(b"uptime\n")
    if not re.search(rb"\b[0-9]+(?:\.[0-9]+)?\s*(?:ms|s|seconds|milliseconds)\b", uptime.lower()):
        raise RuntimeError(f"uptime did not report elapsed time: {uptime!r}")


def health(port, deadline, process, *, timeout=4):
    validate(exchange(port, REQUEST, deadline, process, timeout=timeout), 200, body=b"ok\n")



def require_config(output, address, gateway, echo, *, state=None):
    expected = (f"IPv4: {address}", f"Gateway: {gateway}", f"Echo: {echo}")
    if state is not None:
        expected += (f"NIC: {state}",)
    if any(value.encode() not in output for value in expected):
        raise RuntimeError(f"unexpected NIC status, wanted {expected!r}: {output!r}")


def nic_status(console, address, gateway, echo, *, state="up"):
    output = console.command(b"nic show\r")
    require_config(output, address, gateway, echo, state=state)
    return output


def nic_action(console, command):
    output = console.command(command + b"\r")
    if b"NIC error:" in output or b"NIC:" not in output:
        raise RuntimeError(f"NIC action failed: {output!r}")


def wait_health(port, console, *, seconds=12):
    deadline = min(console.deadline, time.monotonic() + seconds)
    last_error = None
    while time.monotonic() < deadline:
        check_guest(console.process, console.serial)
        try:
            health(port, deadline, console.process, timeout=2)
            return
        except (OSError, RuntimeError) as error:
            last_error = error
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise RuntimeError(f"HTTP did not recover after NIC action: {last_error}")


def require_silent(port, payload, console, description):
    # slirp accepts the host connection even when the guest port is closed.
    # Check actual application bytes rather than connect() success.
    deadline = min(console.deadline, time.monotonic() + 1.25)
    try:
        with socket.create_connection(("127.0.0.1", port), remaining(deadline)) as connection:
            connection.settimeout(remaining(deadline))
            connection.sendall(payload)
            while time.monotonic() < deadline:
                check_guest(console.process, console.serial)
                connection.settimeout(min(0.1, remaining(deadline)))
                try:
                    data = connection.recv(4096)
                except socket.timeout:
                    continue
                if data:
                    raise RuntimeError(f"{description} still returned application data: {data[:100]!r}")
                break
    except (ConnectionError, TimeoutError):
        pass
    check_guest(console.process, console.serial)


def binary_echo(port, console):
    deadline = min(console.deadline, time.monotonic() + 4)
    with echo_connect(port, deadline) as connection:
        echo_exchange(connection, bytes(range(256)) * 3, deadline,
                      console.process, half_close=True)


def nic_checks(console, ports):
    initial = console.command(b"nic\r")
    require_config(initial, "10.0.2.15/24", "10.0.2.2", "on", state="up")
    if not re.search(rb"mac: (?:[0-9a-f]{2}:){5}[0-9a-f]{2}", initial.lower()):
        raise RuntimeError(f"NIC status omitted its MAC address: {initial!r}")
    if not re.search(rb"PCI: (?:0000:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", initial):
        raise RuntimeError(f"NIC status omitted its PCI BDF: {initial!r}")
    binary_echo(ports["echo15"], console)
    for invalid in (
        b"nic set 10.0.2.16/0 10.0.2.2",
        b"nic set 10.0.2.0/24 10.0.2.2",
        b"nic set 10.0.2.16/24 192.168.1.1",
        b"nic set 10.0.2.16/24 10.0.2.2 echo maybe",
        b"nic set 10.0.2.16 10.0.2.2",
        b"nic set 10.0.2.16/24 10.0.2.2 extra",
    ):
        rejected = console.command(invalid + b"\r")
        if b"NIC error:" not in rejected:
            raise RuntimeError(f"invalid NIC configuration was not rejected: {rejected!r}")
        nic_status(console, "10.0.2.15/24", "10.0.2.2", "on")
        health(ports["http15"], console.deadline, console.process)

    nic_action(console, b"nic set 10.0.2.16/24 10.0.2.2 echo off")
    wait_health(ports["http16"], console)
    nic_status(console, "10.0.2.16/24", "10.0.2.2", "off")
    require_silent(ports["http15"], REQUEST, console, "old IPv4 HTTP endpoint")
    require_silent(ports["echo16"], b"echo disabled", console, "disabled echo endpoint")

    nic_action(console, b"nic down")
    nic_status(console, "10.0.2.16/24", "10.0.2.2", "off", state="down")
    require_silent(ports["http16"], REQUEST, console, "administratively down HTTP endpoint")
    require_help(console.command(b"help\r"))
    # Changing a stopped NIC only updates its saved configuration. Omitted echo
    # preserves off; a missing gateway still permits local-subnet traffic.
    nic_action(console, b"nic set 10.0.2.15/24 none")
    nic_status(console, "10.0.2.15/24", "none", "off", state="down")
    require_silent(ports["http15"], REQUEST, console, "newly configured but still down HTTP endpoint")
    nic_action(console, b"nic up")
    wait_health(ports["http15"], console)
    nic_status(console, "10.0.2.15/24", "none", "off")
    require_silent(ports["http16"], REQUEST, console, "previous IPv4 HTTP endpoint")
    nic_action(console, b"nic set 10.0.2.15/24 10.0.2.2 echo on")
    wait_health(ports["http15"], console)
    nic_status(console, "10.0.2.15/24", "10.0.2.2", "on")
    binary_echo(ports["echo15"], console)
    print("Live NIC address/gateway/echo changes, atomic rejection, and down/up recovery passed.")


def normal_checks(args, root, deadline):
    process, ports, serial, stderr = launch(args, root, deadline, iommu=True)
    port, http = ports["console"], ports["http15"]
    console = None
    worker = None
    stop = threading.Event()
    successes = []
    failures = []

    def probe_http():
        while not stop.is_set():
            try:
                health(http, deadline, process)
                successes.append(time.monotonic())
            except (OSError, RuntimeError) as error:
                if not stop.is_set():
                    failures.append(error)
                return
            stop.wait(0.05)

    try:
        health(http, deadline, process, timeout=10)  # First slirp connection can take longer.
        worker = threading.Thread(target=probe_http, daemon=True)
        worker.start()
        console = Console(port, process, serial, deadline)
        shell_checks(console)
        console.send(b"partial-before-disconnect")
        console.close()
        console = None
        time.sleep(min(0.1, remaining(deadline)))
        console = Console(port, process, serial, deadline)
        console.command(b"\x03")
        require_help(console.command(b"help\r"))
        require_nic(console.command(b"pci net\n"))
        while len(successes) < 3 and not failures:
            console.command(b"uptime\r")
        if failures:
            raise RuntimeError(f"HTTP failed during serial input: {failures[0]}")
        stop.set()
        worker.join(timeout=5)
        if worker.is_alive() or failures:
            raise RuntimeError(f"concurrent HTTP worker did not stop cleanly: {failures!r}")
        check_guest(process, serial)
        print(f"Serial commands, editing, overflow, and reconnect passed; {len(successes)} concurrent HTTP checks.")
        nic_checks(console, ports)
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        stop.set()
        if console is not None:
            console.close()
        stop_qemu(process)
        if worker is not None:
            worker.join(timeout=5)


def refusal_checks(args, root, deadline):
    process, ports, serial, stderr = launch(args, root, deadline, iommu=False)
    port = ports["console"]
    console = None
    try:
        console = Console(port, process, serial, deadline)
        console.command(b"\x03")
        require_help(console.command(b"help\n"))
        require_nic(console.command(b"pci net\r"))
        for command in (b"nic up", b"nic set 10.0.2.16/24 10.0.2.2 echo off"):
            refused = console.command(command + b"\r")
            if b"NIC error:" not in refused:
                raise RuntimeError(f"NIC action bypassed unavailable isolation: {refused!r}")
            nic_status(console, "10.0.2.15/24", "10.0.2.2", "on", state="unavailable")
        output = check_guest(process, serial)
        if b"CPL=3" in output or HTTP_READY in output:
            raise RuntimeError("userspace networking started without an IOMMU")
        print("Serial shell remains usable after networking refuses startup without an IOMMU.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        if console is not None:
            console.close()
        stop_qemu(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--timeout", type=positive_timeout, default=100,
                        help="total limit for both boots in seconds (default: 100)")
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    try:
        with tempfile.TemporaryDirectory(prefix="kernel-serial-test-") as directory:
            root = Path(directory)
            normal_checks(args, root, deadline)
            refusal_checks(args, root, deadline)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Serial shell test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
