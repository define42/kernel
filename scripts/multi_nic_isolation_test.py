#!/usr/bin/env python3
"""Prove a peer NIC keeps its TCP stream through real process and DMA faults.

The shared-failure variant additionally injects a test-only kernel fault latch,
then reads both PCI bus-master bits via QMP-paused, private qtest sockets.
"""

import argparse
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import time

from http_test import REQUEST
from isolation_test import COMPLETE, EXPECTED
from multi_nic_guard_test import Monitor, Qtest
from multi_nic_test import LiveTraffic, launch, progress
from network_test import positive_timeout, remaining, show_logs, stop_qemu
from serial_test import (Console, check_guest, health, nic_action,
                         require_silent, wait_health)
from setup_test import configuration, export, reject, wire


CROSS_CPU = b"Cross-interface process and DMA memory isolation checks passed."
CROSS_DMA = b"Cross-interface DMA write blocked by VT-d."
RECOVERED = b"Cross-interface DMA fault recovery passed."
GLOBAL = b"All NICs quarantined after shared VT-d failure."
INJECTED = b"Injecting synthetic shared VT-d failure."


def run(args, root, deadline):
    args.control_dir = root
    process, ports, serial, stderr = launch(args, root, deadline, iommu=True)
    worker = None
    try:
        with ExitStack() as cleanup:
            console = Console(ports["console"], process, serial, deadline)
            cleanup.callback(console.close)
            console.command(b"\x03")
            wait_health(ports["http1_15"], console)
            worker = LiveTraffic(1, ports, console)
            while True:
                output = check_guest(process, serial)
                worker.check()
                if GLOBAL in output:
                    raise RuntimeError("global quarantine preceded cross-NIC recovery")
                if COMPLETE in output:
                    missing = [marker.decode() for marker in (*EXPECTED, CROSS_CPU, CROSS_DMA, RECOVERED)
                               if marker not in output]
                    if missing:
                        raise RuntimeError(f"completion without required isolation checks: {missing}")
                    break
                console.read(min(0.03, remaining(deadline)))
            progress(console, worker)
            if worker.rounds < 10:
                raise RuntimeError("insufficient established peer traffic during fault probes")
            wait_health(ports["http0_15"], console)
            health(ports["http1_15"], deadline, process)
            worker.close()
            rounds = worker.rounds
            worker = None
            print(f"Cross-NIC CPU/DMA isolation and recovery passed; peer held stream/HTTP survived {rounds} rounds.")
            if not args.shared_failure:
                if INJECTED in check_guest(process, serial):
                    raise RuntimeError("unexpected shared-failure injection in recovery build")
                return
            while GLOBAL not in check_guest(process, serial):
                console.read(min(0.03, remaining(deadline)))
            if INJECTED not in check_guest(process, serial):
                raise RuntimeError("shared quarantine was not caused by the required test injection")
            expected = [configuration(nic, enabled=False) for nic in range(2)]
            export(console, expected)
            for nic in range(2):
                nic_action(console, f"nic select eth{nic}".encode())
                status = console.command(b"nic show\r")
                if b"NIC: quarantined\r\n" not in status:
                    raise RuntimeError(f"eth{nic} did not remain quarantined: {status!r}")
                for command in (b"nic up\r", b"nic set 10.0.2.16/24 none\r"):
                    if b"NIC error:" not in console.command(command):
                        raise RuntimeError("console mutation bypassed shared-unit quarantine")
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
                require_silent(ports[f"http{nic}_15"], REQUEST, console, f"quarantined eth{nic}")
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
            print("Synthetic shared-unit failure passed: both NICs quarantined, both BME bits clear, console/JSON cannot restart or reconfigure them.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        if worker is not None:
            worker.stop.set()
            worker.thread.join(timeout=6)
        stop_qemu(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--shared-failure", action="store_true")
    parser.add_argument("--timeout", type=positive_timeout, default=50)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="kernel-multi-isolation-") as temporary:
            run(args, Path(temporary), time.monotonic() + args.timeout)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Multi-NIC isolation test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
