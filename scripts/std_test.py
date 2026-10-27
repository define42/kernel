#!/usr/bin/env python3
"""Verify the Rust std userspace backend and process failure containment in QEMU."""

import argparse
from pathlib import Path
import subprocess
import sys


SUCCESS_MARKER = "Userspace std isolation and restart checks passed."
ENTROPY_REFUSAL_MARKER = "Userspace std entropy refusal checks passed."
SUCCESS_STATUS = (0x10 << 1) | 1
REQUIRED_MARKERS = (
    "Kernel WP/NX fault checks passed.",
    "std System allocation checks passed.",
    "std thread park token and zero timeout checks passed.",
    "std Vec/String/HashMap checks passed:",
    "std thread-local/Mutex/OnceLock checks passed.",
    "std Instant and yielding sleep checks passed.",
    "std unavailable OS operations return Unsupported.",
    "std random/stdio syscall boundary checks passed.",
    "std stdout Write checks passed.",
    "std stderr checks passed.",
    "intentional std panic containment probe",
    "Ring-3 std probe 1: passed (exit 1)",
    "memory allocation of 524289 bytes failed",
    "Ring-3 std probe 2: passed (exit 1)",
    "Ring-3 std probe 3: passed (exit 7)",
)


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
    parser.add_argument("--cpu", default="max", help="QEMU CPU model")
    parser.add_argument("--no-entropy", action="store_true",
                        help="disable RDRAND/RDSEED and verify failure without weak seed fallback")
    args = parser.parse_args()
    cpu = "max,-rdrand,-rdseed" if args.no_entropy else args.cpu

    command = [
        args.qemu,
        "-machine", "pc",
        "-accel", "tcg",
        "-cpu", cpu,
        "-m", "128M",
        "-smp", "1",
        "-kernel", str(args.kernel),
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-no-reboot",
        "-no-shutdown",
        "-device", "e1000,netdev=net0",
        "-netdev", "user,id=net0,restrict=on",
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

    if args.no_entropy:
        success_marker = ENTROPY_REFUSAL_MARKER
        required = (
            "Kernel WP/NX fault checks passed.",
            "std unavailable entropy leaves output unchanged.",
            "kernel randomness unavailable",
        )
        missing = [marker for marker in required if marker not in result.stdout]
        for marker in (
            "Ring-3 std probe 4: passed (exit 1)",
            "std unavailable entropy leaves output unchanged.",
            "kernel randomness unavailable",
        ):
            if result.stdout.count(marker) != 2:
                missing.append(f"entropy refusal before and after restart: {marker}")
    else:
        success_marker = SUCCESS_MARKER
        missing = [marker for marker in REQUIRED_MARKERS if marker not in result.stdout]
        if result.stdout.count("Ring-3 std probe 0: passed (exit 0)") != 2:
            missing.append("ordinary std program succeeded before and after panic/OOM/exit restart")
        if result.stdout.count("Userspace std checks passed.") != 2:
            missing.append("complete std checks passed twice")
    if result.returncode != SUCCESS_STATUS or success_marker not in result.stdout or missing:
        print(
            f"QEMU boot failed: exit status {result.returncode} "
            f"(expected {SUCCESS_STATUS}); serial success marker "
            f"{'found' if success_marker in result.stdout else 'missing'}.",
            file=sys.stderr,
        )
        if missing:
            print(f"Missing required checks: {missing}", file=sys.stderr)
        show_output(result.stdout, result.stderr)
        return 1

    print(result.stdout.rstrip())
    print("QEMU userspace std entropy refusal test passed." if args.no_entropy
          else "QEMU userspace std test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
