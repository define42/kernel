#!/usr/bin/env python3
"""Verify GRUB/UEFI handoff using a private writable OVMF variable store."""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from network_test import check_process, show_logs, stop_qemu


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    parser.add_argument("image", type=Path)
    parser.add_argument("--code", type=Path, default=Path("/usr/share/OVMF/OVMF_CODE_4M.fd"))
    parser.add_argument("--vars", type=Path, default=Path("/usr/share/OVMF/OVMF_VARS_4M.fd"))
    parser.add_argument("--hardware-refusal", action="store_true",
                        help="boot the hardware image and require refusal of the emulated platform")
    args = parser.parse_args()
    for path in (args.image, args.code, args.vars):
        if not path.is_file():
            parser.error(f"missing firmware test input: {path}")
    with tempfile.TemporaryDirectory(prefix="kernel-uefi-") as directory:
        variables = Path(directory) / "vars.fd"
        shutil.copyfile(args.vars, variables)
        command = [
            args.qemu, "-machine", "q35", "-accel", "tcg", "-cpu", "max,vendor=GenuineIntel",
            "-m", "256M", "-smp", "1", "-display", "none", "-serial", "stdio",
            "-monitor", "none", "-no-reboot", "-no-shutdown", "-nic", "none",
            "-drive", f"if=pflash,format=raw,readonly=on,file={args.code}",
            "-drive", f"if=pflash,format=raw,file={variables}",
            "-cdrom", str(args.image), "-boot", "d",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        if args.hardware_refusal:
            command += ["-device", "intel-iommu,intremap=on", "-device", "e1000,netdev=net0",
                        "-netdev", "user,id=net0"]
            serial = Path(directory) / "serial.log"
            stderr = Path(directory) / "stderr.log"
            process = None
            try:
                with serial.open("wb") as out, stderr.open("wb") as err:
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                               stdout=out, stderr=err)
                deadline = time.monotonic() + 45
                marker = b"hardware isolation refuses hypervisors"
                while marker not in serial.read_bytes():
                    check_process(process)
                    if time.monotonic() >= deadline or b"KERNEL PANIC" in serial.read_bytes():
                        raise RuntimeError("hardware image failed before the intended hypervisor guard")
                    time.sleep(0.02)
                time.sleep(0.2)
                output = serial.read_bytes()
                for required in (b"Multiboot2:", b"ACPI: validated", b"Timer: xAPIC"):
                    if required not in output:
                        raise RuntimeError(f"missing firmware component check: {required!r}")
                if b"CPL=3" in output:
                    raise RuntimeError("hardware image incorrectly started a service in QEMU")
                print(output.decode(errors="replace"))
                print("UEFI hardware image validated firmware/APIC, then refused emulated assignment.")
                return
            except BaseException:
                show_logs(serial, stderr)
                raise
            finally:
                stop_qemu(process)
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    errors="replace", timeout=45, check=False)
        except subprocess.TimeoutExpired as error:
            raise SystemExit(f"UEFI handoff timed out:\n{error.stdout!r}\n{error.stderr!r}") from error
        print(result.stdout)
        if result.returncode != 33 or "Boot checks passed." not in result.stdout:
            raise SystemExit(f"UEFI handoff failed: exit {result.returncode}\n{result.stderr}")
        if "Multiboot2" not in result.stdout:
            raise SystemExit("UEFI test did not verify the Multiboot2 path")
        print("UEFI/GRUB/Multiboot2 handoff passed (not physical hardware validation).")


if __name__ == "__main__":
    main()
