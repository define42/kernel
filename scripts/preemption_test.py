#!/usr/bin/env python3
"""Prove TCP echo remains live during a busy user loop and a syscall-only loop."""
import argparse
from pathlib import Path
import sys
import tempfile
import time
from network_test import launch_qemu, connect, exchange, stop_qemu, show_logs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    args = parser.parse_args()
    process = None
    deadline = time.monotonic() + 25
    with tempfile.TemporaryDirectory(prefix="kernel-preemption-") as directory:
        serial, stderr = Path(directory) / "serial.log", Path(directory) / "stderr.log"
        try:
            process, port = launch_qemu(args, serial, stderr, deadline)
            spin = flood = 0
            while True:
                output = serial.read_bytes()
                if any(marker in output for marker in (b"KERNEL PANIC", b"Userspace fault:", b"Web process stopped", b"Service restart scheduled", b"Networking quarantined")):
                    raise RuntimeError("guest failure during preemption test")
                in_flood = b"Preemption test: syscall loop" in output
                with connect(port, deadline) as client:
                    exchange(client, b"kernel made progress while ring 3 was busy\x00\xff", deadline,
                             process, half_close=True)
                if in_flood:
                    flood += 1
                else:
                    spin += 1
                if b"Preemption fairness checks passed." in serial.read_bytes() and flood >= 3:
                    if spin < 3:
                        raise RuntimeError("insufficient echo checks during the pure busy loop")
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("preemption test deadline")
                time.sleep(0.05)
            print(f"Preemption passed: {spin} echo sessions during busy loop, {flood} during syscall loop.")
        except (OSError, RuntimeError) as error:
            print(f"Preemption test failed: {error}", file=sys.stderr)
            show_logs(serial, stderr)
            return 1
        finally:
            stop_qemu(process)
    return 0


if __name__ == "__main__":
    sys.exit(main())
