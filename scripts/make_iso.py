#!/usr/bin/env python3
"""Package a flat Multiboot2 kernel with the locally installed GRUB platforms."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--grub-mkrescue", default="grub-mkrescue")
    parser.add_argument("--grub-file", default="grub-file")
    args = parser.parse_args()
    subprocess.run([args.grub_file, "--is-x86-multiboot2", str(args.kernel)], check=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kernel-iso-") as directory:
        root = Path(directory)
        boot = root / "boot"
        (boot / "grub").mkdir(parents=True)
        shutil.copyfile(args.kernel, boot / "kernel.bin")
        (boot / "grub/grub.cfg").write_text(
            "set timeout=0\nset default=0\n"
            "serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\n"
            "terminal_output console serial\n"
            "menuentry 'Rust kernel (experimental hardware port)' {\n"
            "    multiboot2 /boot/kernel.bin\n    boot\n}\n",
            encoding="ascii",
        )
        subprocess.run([args.grub_mkrescue, "-o", str(args.output), str(root)], check=True)
    manifest = {
        "status": "experimental; not approved for public production",
        "boot_protocol": "Multiboot2",
        "kernel_sha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest(),
        "image_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "firmware_support": "depends on installed GRUB platform modules; see build output",
    }
    args.output.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Created {args.output}; manifest: {args.output.with_suffix('.json')}")


if __name__ == "__main__":
    main()
