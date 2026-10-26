#!/usr/bin/env python3
"""Boot the test kernel in QEMU and verify its serial result and exit status."""

import argparse
from pathlib import Path
import subprocess
import sys


SUCCESS_MARKER = "Boot checks passed."
SUCCESS_STATUS = (0x10 << 1) | 1


def positive_timeout(value: str) -> float:
    timeout = float(value)
    if not 0 < timeout < float("inf"):
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return timeout


def show_output(stdout: str | bytes | None, stderr: str | bytes | None) -> None:
    for label, output in (("QEMU stdout", stdout), ("QEMU stderr", stderr)):
        if output:
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            print(f"{label}:\n{output.rstrip()}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="QEMU executable name or path")
    parser.add_argument("kernel", type=Path, help="kernel binary to boot")
    parser.add_argument("--timeout", type=positive_timeout, default=15.0,
                        help="maximum boot time in seconds (default: 15)")
    args = parser.parse_args()

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
        "-nic", "none",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]

    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        print(f"QEMU boot timed out after {args.timeout:g} seconds.", file=sys.stderr)
        show_output(error.stdout, error.stderr)
        return 1
    except OSError as error:
        print(f"Unable to start QEMU ({args.qemu}): {error}", file=sys.stderr)
        return 1

    if result.returncode != SUCCESS_STATUS or SUCCESS_MARKER not in result.stdout:
        print(
            f"QEMU boot failed: exit status {result.returncode} "
            f"(expected {SUCCESS_STATUS}); serial success marker "
            f"{'found' if SUCCESS_MARKER in result.stdout else 'missing'}.",
            file=sys.stderr,
        )
        show_output(result.stdout, result.stderr)
        return 1

    print(result.stdout.rstrip())
    print("QEMU boot smoke test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
