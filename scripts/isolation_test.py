#!/usr/bin/env python3
"""Check QEMU service fault containment, recovery, and fail-closed device access."""

import argparse
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

from network_test import (
    check_process, connect, exchange, launch_qemu, positive_timeout,
    remaining, show_logs, stop_qemu,
)


COMPLETE = b"Service isolation and recovery checks passed."
EXPECTED = (
    b"Contained NIC DMA fault:",
    b"NIC interrupt-aperture containment passed.",
    b"IPC capability checks passed.",
    b"Network IPC validation checks passed.",
    b"Pending RPC reply validation checks passed.",
    b"Process address-space and SIMD isolation checks passed.",
    b"Service web stopped:",
    b"Service network stopped:",
    b"Service driver stopped:",
    b"Service driver restarted",
    COMPLETE,
)


def check_guest(process: subprocess.Popen, serial: Path) -> bytes:
    check_process(process)
    output = serial.read_bytes()
    if b"KERNEL PANIC" in output:
        raise RuntimeError("kernel panicked during service isolation checks")
    return output


def check_recovery(args: argparse.Namespace, directory: Path, deadline: float) -> None:
    serial = directory / "recovery-serial.log"
    stderr = directory / "recovery-stderr.log"
    process = None
    attempts = successes = recovered = 0
    try:
        process, port = launch_qemu(args, serial, stderr, deadline)
        while recovered < 3:
            remaining(deadline)
            output = check_guest(process, serial)
            started_after_completion = COMPLETE in output
            attempts += 1
            payload = (b"isolated services binary echo\x00\xff"
                       + attempts.to_bytes(8, "little") + bytes(range(256)) * 4)
            client = None
            try:
                attempt_deadline = min(deadline, time.monotonic() + 2.0)
                client = connect(port, attempt_deadline)
                exchange(client, payload, attempt_deadline, process, half_close=True)
            except (OSError, RuntimeError) as error:
                check_guest(process, serial)
                # Corrupt data is never an expected consequence of a restart.
                if "TCP echo differs" in str(error):
                    raise
                if client is not None:
                    # Do not leave a failed probe occupying the single echo
                    # listener while the next recovery probe is attempted.
                    try:
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                          struct.pack("ii", 1, 0))
                    except OSError:
                        pass
                recovered = 0
            else:
                successes += 1
                if started_after_completion:
                    recovered += 1
            finally:
                if client is not None:
                    client.close()
            output = check_guest(process, serial)
            if COMPLETE in output:
                missing = [marker.decode() for marker in EXPECTED if marker not in output]
                if missing:
                    raise RuntimeError(f"completion without required checks: {missing}")
            if recovered < 3:
                time.sleep(min(0.03, remaining(deadline)))
        print(f"Service recovery passed: {successes}/{attempts} binary echo exchanges, "
              f"including {recovered} after all fault checks.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        stop_qemu(process)


def check_fail_closed(args: argparse.Namespace, directory: Path, deadline: float,
                      *, apic_present: bool = False) -> None:
    scenario = "apic-present" if apic_present else "no-iommu"
    serial = directory / f"{scenario}-serial.log"
    stderr = directory / f"{scenario}-stderr.log"
    # Each boot violates exactly one production requirement: either remove
    # VT-d or retain VT-d but instantiate a local APIC on the max CPU model.
    cpu = "max" if apic_present else args.cpu
    command = [
        args.qemu, "-machine", "q35", "-cpu", cpu, "-accel", "tcg",
        "-m", "128M", "-smp", "1",
        "-kernel", str(args.kernel), "-display", "none", "-serial", "stdio",
        "-monitor", "none", "-no-reboot", "-no-shutdown",
        "-netdev", "user,id=net0", "-device", "e1000,netdev=net0",
    ]
    if apic_present:
        command += ["-device", "intel-iommu,intremap=off"]
    process = None
    try:
        remaining(deadline)
        with serial.open("wb") as serial_output, stderr.open("wb") as error_output:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=serial_output, stderr=error_output)
        refused_at = None
        while True:
            output = check_guest(process, serial)
            if b"CPL=3" in output:
                raise RuntimeError("a userspace service started without required DMA isolation")
            if b"Network isolation unavailable:" in output and refused_at is None:
                refused_at = time.monotonic()
            # Continue observing briefly: refusal must not be followed by an
            # accidental fall-through into device assignment or userspace.
            if refused_at is not None and time.monotonic() - refused_at >= 0.5:
                break
            time.sleep(min(0.02, remaining(deadline)))
        if apic_present and b"max,-apic" not in output:
            raise RuntimeError("APIC-present boot failed for an unrelated platform condition")
        print(f"{scenario} check passed: device access refused before userspace starts.")
    except BaseException:
        show_logs(serial, stderr)
        raise
    finally:
        stop_qemu(process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="QEMU executable name or path")
    parser.add_argument("kernel", type=Path, help="isolation-test kernel image")
    parser.add_argument("--cpu", default="max,-apic",
                        help="QEMU CPU model with APIC disabled (default: max,-apic)")
    parser.add_argument("--timeout", type=positive_timeout, default=30.0,
                        help="total deadline for all three boots in seconds (default: 30)")
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    with tempfile.TemporaryDirectory(prefix="kernel-service-isolation-") as name:
        directory = Path(name)
        try:
            check_recovery(args, directory, deadline)
            check_fail_closed(args, directory, deadline)
            check_fail_closed(args, directory, deadline, apic_present=True)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"Service isolation test failed: {error}", file=sys.stderr)
            return 1
    print("QEMU service isolation and recovery integration test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
