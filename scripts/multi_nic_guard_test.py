#!/usr/bin/env python3
"""Check NIC inventory limits, eight active NICs, and bridge exclusion in QEMU.

All control sockets are UNIX sockets inside a temporary directory. NICs have
no host network backend. QMP stops the guest before qtest reads PCI Command
registers, preventing CF8/CFC races with the guest's PCI scanner.
"""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

from network_test import (check_process, positive_timeout, remaining,
                          show_logs, stop_qemu)
from serial_test import Console, HTTP_READY, PROMPT, REFUSAL, check_guest, nic_action


TOO_MANY = b"more than eight assignable e1000 NICs are unsupported"
E1000_ID = 0x100E8086
BUS_MASTER = 1 << 2


def connect_unix(path, process, deadline):
    while True:
        check_process(process)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(remaining(deadline))
        try:
            connection.connect(str(path))
            return connection
        except (FileNotFoundError, ConnectionRefusedError):
            connection.close()
            time.sleep(min(0.01, remaining(deadline)))
        except BaseException:
            connection.close()
            raise


class UnixConsole(Console):
    def __init__(self, path, process, serial, deadline):
        self.process = process
        self.serial = serial
        self.deadline = deadline
        self.pending = bytearray()
        self.socket = connect_unix(path, process, deadline)
        self.socket.setblocking(False)


class Lines:
    def __init__(self, path, process, deadline):
        self.process = process
        self.deadline = deadline
        self.socket = connect_unix(path, process, deadline)
        self.pending = bytearray()

    def close(self):
        self.socket.close()

    def send(self, data):
        check_process(self.process)
        self.socket.settimeout(remaining(self.deadline))
        self.socket.sendall(data + b"\n")

    def read(self):
        while b"\n" not in self.pending:
            check_process(self.process)
            self.socket.settimeout(remaining(self.deadline))
            data = self.socket.recv(4096)
            if not data:
                raise RuntimeError("QEMU control socket closed unexpectedly")
            self.pending.extend(data)
            if len(self.pending) > 65536:
                raise RuntimeError("QEMU control response exceeded 64 KiB")
        end = self.pending.index(b"\n")
        line = bytes(self.pending[:end]).rstrip(b"\r")
        del self.pending[:end + 1]
        return line


class Monitor(Lines):
    def command(self, name):
        self.send(json.dumps({"execute": name, "id": name}).encode())
        while True:
            response = json.loads(self.read())
            if response.get("id") != name:
                if "event" in response:
                    continue
                raise RuntimeError(f"unexpected QMP response: {response!r}")
            if "error" in response:
                raise RuntimeError(f"QMP {name} failed: {response['error']!r}")
            return response["return"]

    def pause(self):
        if not getattr(self, "initialized", False):
            if "QMP" not in json.loads(self.read()):
                raise RuntimeError("missing QMP greeting")
            self.command("qmp_capabilities")
            self.initialized = True
        self.command("stop")
        status = self.command("query-status")
        if status.get("running") is not False:
            raise RuntimeError(f"guest did not stop for PCI inspection: {status!r}")


class Qtest(Lines):
    def command(self, text):
        self.send(text.encode())
        while True:
            response = self.read()
            if response.startswith(b"IRQ "):
                continue
            words = response.split()
            if not words or words[0] != b"OK":
                raise RuntimeError(f"qtest {text!r} failed: {response!r}")
            return words[1:]

    def pci(self, bus, device, offset):
        address = 0x80000000 | (bus << 16) | (device << 11) | offset
        self.command(f"outl 0xcf8 0x{address:x}")
        values = self.command("inl 0xcfc")
        if len(values) != 1:
            raise RuntimeError(f"invalid qtest PCI read result: {values!r}")
        return int(values[0], 0)

    def require_nic(self, bus, device, *, bus_master):
        identity = self.pci(bus, device, 0)
        if identity != E1000_ID:
            raise RuntimeError(f"expected e1000 at {bus:02x}:{device:02x}.0, got {identity:#x}")
        command = self.pci(bus, device, 4) & 0xffff
        if bool(command & BUS_MASTER) != bus_master:
            raise RuntimeError(f"unexpected BME at {bus:02x}:{device:02x}.0: Command={command:#06x}")
        return command


def run_case(args, root, deadline, *, case):
    excess, active = case == "nine-nics", case == "eight-active"
    name = case
    directory = root / name
    directory.mkdir()
    serial, stderr = directory / "serial.log", directory / "stderr.log"
    console_path, qmp_path, qtest_path = [directory / name for name in ("com", "qmp", "qtest")]
    command = [
        args.qemu, "-machine", "q35", "-accel", "tcg", "-cpu", "max,-apic",
        "-m", "128M", "-smp", "1", "-kernel", str(args.kernel),
        "-display", "none", "-monitor", "none", "-no-reboot", "-no-shutdown",
        "-nic", "none", "-device", "intel-iommu,intremap=off",
        "-chardev", f"socket,id=com1,path={console_path},server=on,wait=off,"
        f"logfile={serial},logappend=off", "-serial", "chardev:com1",
        "-qmp", f"unix:{qmp_path},server=on,wait=off",
        "-qtest", f"unix:{qtest_path},server=on,wait=off", "-qtest-log", "/dev/null",
    ]
    for index in range(9 if excess else 8 if active else 1):
        command += ["-device", f"e1000,bus=pcie.0,addr=0x{index + 2:x},"
                    f"mac=52:54:00:12:34:{index + 0x50:02x}"]
    if not excess and not active:
        command += ["-device", "pcie-pci-bridge,id=bridge,bus=pcie.0,addr=0x3",
                    "-device", "e1000,bus=bridge,addr=0x1,mac=52:54:00:12:34:60"]
    process = None
    try:
        with stderr.open("wb") as errors:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=errors)
        with ExitStack() as cleanup:
            console = UnixConsole(console_path, process, serial, deadline)
            cleanup.callback(console.close)
            while True:
                output = check_guest(process, serial)
                if PROMPT in output and (TOO_MANY if excess else HTTP_READY) in output:
                    break
                if not excess and REFUSAL in output:
                    raise RuntimeError(f"supported root-bus inventory was refused in {case}")
                console.read(0.01)
            # The initial prompt may have arrived after connecting; discard it
            # before synchronizing a fresh command/response with Ctrl-C.
            console.quiet(0.05)
            console.command(b"\x03")
            listing = console.command(b"nic list\r")
            if excess:
                if b"No selectable NICs." not in listing:
                    raise RuntimeError(f"excess inventory remained selectable: {listing!r}")
                rejected = console.command(b"nic up\r")
                if b"NIC error:" not in rejected:
                    raise RuntimeError("NIC up bypassed excess-inventory refusal")
            elif active:
                # All eight service groups must reach up independently at boot.
                while any(f"eth{index} 0000:00:{index + 2:02x}.0 8086:100e up".encode()
                          not in listing for index in range(8)):
                    if REFUSAL in check_guest(process, serial):
                        raise RuntimeError("eight supported NICs were refused")
                    time.sleep(min(0.02, remaining(deadline)))
                    listing = console.command(b"nic list\r")
                if listing.count(b" selected\r\n") != 1:
                    raise RuntimeError(f"NIC selection was ambiguous: {listing!r}")
            else:
                if not re.search(rb"\beth0 0000:00:02\.0 8086:100e up selected\b", listing):
                    raise RuntimeError(f"root-bus NIC is missing from inventory: {listing!r}")
                if re.search(rb"\beth[1-7]\b", listing):
                    raise RuntimeError(f"bridged NIC was admitted: {listing!r}")
                rejected = console.command(b"nic select eth1\r")
                if b"NIC error:" not in rejected:
                    raise RuntimeError("bridged NIC became selectable")
                status = console.command(b"nic show\r")
                if b"NIC: up\r\n" not in status or b"PCI: 0000:00:02.0" not in status:
                    raise RuntimeError(f"root-bus service did not remain up: {status!r}")
            monitor = Monitor(qmp_path, process, deadline)
            cleanup.callback(monitor.close)
            monitor.pause()
            probe = Qtest(qtest_path, process, deadline)
            cleanup.callback(probe.close)
            if excess:
                for device in range(2, 11):
                    probe.require_nic(0, device, bus_master=False)
                output = check_guest(process, serial)
                if b"CPL=3" in output or HTTP_READY in output:
                    raise RuntimeError("excess inventory entered ring-3 services before refusal")
                print("Nine-NIC refusal passed: no CPL3 services, no selectable NICs, all 9 BME bits clear.")
            elif active:
                for device in range(2, 10):
                    probe.require_nic(0, device, bus_master=True)
                monitor.command("cont")
                nic_action(console, b"nic select eth7")
                nic_action(console, b"nic down")
                listing = console.command(b"nic list\r")
                for index in range(8):
                    state = "down selected" if index == 7 else "up"
                    row = f"eth{index} 0000:00:{index + 2:02x}.0 8086:100e {state}\r\n".encode()
                    if row not in listing:
                        raise RuntimeError(f"stopping eth7 changed another NIC: {listing!r}")
                monitor.pause()
                for device in range(2, 10):
                    probe.require_nic(0, device, bus_master=device != 9)
                monitor.command("cont")
                nic_action(console, b"nic up")
                while b"NIC: up\r\n" not in console.command(b"nic show\r"):
                    time.sleep(min(0.02, remaining(deadline)))
                monitor.pause()
                for device in range(2, 10):
                    probe.require_nic(0, device, bus_master=True)
                print("Eight-NIC concurrency passed: all BME on; eth7 down/up leaves the other seven BME bits on.")
            else:
                probe.require_nic(0, 2, bus_master=True)
                buses = probe.pci(0, 3, 0x18)
                secondary, subordinate = (buses >> 8) & 0xff, (buses >> 16) & 0xff
                if secondary == 0 or subordinate < secondary:
                    raise RuntimeError(f"firmware did not configure the bridge bus: {buses:#x}")
                probe.require_nic(secondary, 1, bus_master=False)
                print(f"Bridge exclusion passed: root eth0 active/BME on; {secondary:02x}:01.0 excluded/BME off.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        stop_qemu(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="QEMU executable name or path")
    parser.add_argument("kernel", type=Path, help="normal kernel binary")
    parser.add_argument("--timeout", type=positive_timeout, default=90,
                        help="total time limit for three offline boots (default: 90 seconds)")
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    try:
        with tempfile.TemporaryDirectory(prefix="kernel-nic-guards-") as temporary:
            for case in ("nine-nics", "bridged-nic", "eight-active"):
                run_case(args, Path(temporary), deadline, case=case)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"NIC inventory guard test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
