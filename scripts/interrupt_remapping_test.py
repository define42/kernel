#!/usr/bin/env python3
"""Verify a real unattributed QEMU interrupt fault quarantines both NICs.

QEMU 8.2.2's e1000 DMA-to-MSI path supplies unspecified transaction attributes,
so its VT-d fault record uses SID 0xffff. It cannot safely identify one driver.
This test preserves that fault and requires global quarantine, rather than
relaxing attribution to recover an arbitrarily chosen interface.
"""

import argparse
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import time

from http_test import REQUEST
from multi_nic_guard_test import Monitor, Qtest
from multi_nic_test import interface_list, launch
from network_test import positive_timeout, remaining, show_logs, stop_qemu
from serial_test import (Console, check_guest, nic_action,
                         require_silent, wait_health)
from setup_test import configuration, export, reject, wire


GLOBAL = b"All NICs quarantined after shared VT-d failure."
DRHD = 0xFED90000  # Fixed register base of the explicitly selected QEMU q35 machine.
PRESENT = 1 << 63


def register(probe, kind, offset):
    values = probe.command(f"{kind} 0x{DRHD + offset:x}")
    if len(values) != 1:
        raise RuntimeError(f"invalid VT-d register response: {values!r}")
    return int(values[0], 0)


def run(args, root, deadline):
    args.control_dir = root
    args.interrupt_remapping = True
    process, ports, serial, stderr = launch(args, root, deadline, iommu=True)
    try:
        with ExitStack() as cleanup:
            console = Console(ports["console"], process, serial, deadline)
            cleanup.callback(console.close)
            console.command(b"\x03")
            # The injected PHY-loopback write waits for receiver initialization.
            # Establish that both interfaces were live before the shared fault.
            wait_health(ports["http1_15"], console)
            interface_list(console)
            while GLOBAL not in check_guest(process, serial):
                console.read(min(0.03, remaining(deadline)))
            if b"Injecting synthetic shared VT-d failure." in check_guest(process, serial):
                raise RuntimeError("a synthetic failure masked the required real interrupt fault")
            expected = [configuration(nic, enabled=False) for nic in range(2)]
            export(console, expected)
            for nic in range(2):
                nic_action(console, f"nic select eth{nic}".encode())
                status = console.command(b"nic show\r")
                if b"NIC: quarantined\r\n" not in status:
                    raise RuntimeError(f"eth{nic} escaped shared quarantine: {status!r}")
                for command in (b"nic up\r", b"nic set 10.0.2.16/24 none\r"):
                    if b"NIC error:" not in console.command(command):
                        raise RuntimeError("console mutation bypassed interrupt-fault quarantine")
                # JSON uses the same quarantine gate for an explicit restart
                # and for configuration-only edits that keep the NIC disabled.
                for update in (
                    {"Interface": f"eth{nic}", "Enabled": True},
                    configuration(nic, ip=16, gateway="none", echo=False, enabled=False),
                ):
                    reject(console, wire([update]))
                    export(console, expected)
                status = console.command(b"nic show\r")
                if b"NIC: quarantined\r\n" not in status:
                    raise RuntimeError(f"setup mutation cleared eth{nic} quarantine: {status!r}")
                require_silent(ports[f"http{nic}_15"], REQUEST, console, f"quarantined eth{nic} HTTP")
                require_silent(ports[f"echo{nic}_15"], b"quarantined echo", console,
                               f"quarantined eth{nic} echo")
            # A multi-interface document must also leave every saved setting
            # and Enabled flag untouched when the shared unit is quarantined.
            reject(console, wire([configuration(0, ip=16, echo=False),
                                  configuration(1, ip=16, gateway="none", echo=False)]))
            export(console, expected)
            monitor = Monitor(root / "qmp", process, deadline)
            cleanup.callback(monitor.close)
            monitor.pause()
            probe = Qtest(root / "qtest", process, deadline)
            cleanup.callback(probe.close)
            for device in (2, 3):
                probe.require_nic(0, device, bus_master=False)
            cap = register(probe, "readq", 0x08)
            fsts = register(probe, "readl", 0x34)
            if fsts != 2:
                raise RuntimeError(f"expected preserved primary fault without overflow; FSTS={fsts:#x}")
            fault_base = ((cap >> 24) & 0x3FF) * 16
            fault_count = ((cap >> 40) & 0xFF) + 1
            if fault_base < 0x80 or fault_base + fault_count * 16 > 4096:
                raise RuntimeError("invalid QEMU VT-d fault register layout")
            faults = []
            for index in range(fault_count):
                low = register(probe, "readq", fault_base + index * 16)
                high = register(probe, "readq", fault_base + index * 16 + 8)
                if high & PRESENT:
                    faults.append((low, high & 0xFFFF, (high >> 32) & 0xFF))
            if faults != [(0, 0xFFFF, 0x22)]:
                raise RuntimeError(f"unexpected interrupt-remapping fault records: {faults!r}")
            print("Real interrupt-remapping fault passed: FSTS=0x2, SID=0xffff, reason=0x22; "
                  "both NICs quarantined with BME clear, HTTP/echo silent, console/JSON restart and reconfiguration refused.")
            print("QEMU's unattributed MSI fault remains preserved; compatibility-format interrupt blocking remains unverified.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        stop_qemu(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--timeout", type=positive_timeout, default=30)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="kernel-interrupt-remapping-") as temporary:
            run(args, Path(temporary), time.monotonic() + args.timeout)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Interrupt-remapping test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
