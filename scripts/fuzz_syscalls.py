#!/usr/bin/env python3
"""Run seeded ring-3 syscall checks in a child QEMU; preserve full logs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from network_test import positive_timeout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--timeout", type=positive_timeout, default=120)
    parser.add_argument("--artifacts", type=Path, default=Path("build/fuzz"))
    args = parser.parse_args()
    directory = args.artifacts / f"syscalls-{time.time_ns()}"
    directory.mkdir(parents=True)
    command = [args.qemu, "-machine", "q35", "-device", "intel-iommu,intremap=off", "-accel", "tcg", "-cpu", "max,-apic", "-m", "128M",
               "-smp", "1", "-kernel", str(args.kernel), "-display", "none", "-monitor", "none",
               "-serial", "stdio", "-no-reboot", "-no-shutdown", "-device", "e1000,netdev=net0",
               "-netdev", "user,id=net0,restrict=on", "-device", "isa-debug-exit,iobase=0xf4,iosize=4"]
    started = time.monotonic()
    passed = False
    try:
        with (directory / "serial.log").open("wb") as serial, (directory / "stderr.log").open("wb") as stderr:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=serial, stderr=stderr,
                                    timeout=args.timeout, check=False)
        output = (directory / "serial.log").read_text(errors="replace")
        passed = result.returncode == 33 and "Syscall fuzz passed:" in output
        if not passed:
            print(output[-6000:], file=sys.stderr)
            print(f"QEMU syscall campaign exit status: {result.returncode}", file=sys.stderr)
        else:
            print(output.splitlines()[-1])
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Syscall campaign failed: {error}", file=sys.stderr)
    finally:
        (directory / "summary.json").write_text(json.dumps({"passed": passed,
            "seconds": round(time.monotonic() - started, 3), "kernel": str(args.kernel)}, indent=2) + "\n")
    print(f"Artifacts: {directory}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
