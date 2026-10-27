#!/usr/bin/env python3
"""Build the native userspace std port with an isolated, pinned Rust toolchain."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TOOLCHAIN = "nightly-2026-04-15"
HOST = "x86_64-unknown-linux-gnu"
COMPILER = "rustc 1.97.0-nightly (a5c825cd8 2026-04-14)"
PRIVATE = ROOT / "target/std-toolchain"
RUSTUP = PRIVATE / "rustup"
INSTALLED = RUSTUP / "toolchains" / f"{TOOLCHAIN}-{HOST}"
PORT = ROOT / "userspace/std-port"
TARGET = ROOT / "userspace/x86_64-unknown-kernel.json"


def run(command, **kwargs):
    subprocess.run([str(arg) for arg in command], cwd=ROOT, check=True, **kwargs)


def prepare():
    environment = os.environ.copy()
    environment["RUSTUP_HOME"] = str(RUSTUP)
    compiler = INSTALLED / "bin/rustc"
    library = INSTALLED / "lib/rustlib/src/rust/library"
    if not compiler.is_file() or not library.is_dir():
        run(["rustup", "toolchain", "install", f"{TOOLCHAIN}-{HOST}",
             "--profile", "minimal", "--component", "rust-src", "--no-self-update"],
            env=environment)
    version = subprocess.check_output([str(compiler), "--version"], text=True).strip()
    if version != COMPILER:
        raise RuntimeError(f"unexpected compiler {version!r}, expected {COMPILER!r}")
    pristine = PRIVATE / "library-pristine"
    if not pristine.exists():
        if (library / "std/src/sys/pal/kernel").exists():
            raise RuntimeError("patched std source exists without pristine backup")
        # An interrupted copy must never become the next build's pristine source.
        with tempfile.TemporaryDirectory(prefix=".library-pristine-", dir=PRIVATE) as temporary:
            snapshot = Path(temporary) / "library"
            shutil.copytree(library, snapshot, symlinks=True)
            snapshot.rename(pristine)
    digest = hashlib.sha256(COMPILER.encode())
    for path in sorted(PORT.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digest.update(str(path.relative_to(PORT)).encode())
            digest.update(path.read_bytes())
    stamp = PRIVATE / "port.sha256"
    fingerprint = digest.hexdigest()
    if not stamp.exists() or stamp.read_text().strip() != fingerprint:
        # This compiler and its sources belong solely to this checkout. Never
        # patch the user's rustup installation or its normal stable toolchain.
        shutil.rmtree(library)
        shutil.copytree(pristine, library, symlinks=True)
        run([sys.executable, PORT / "apply.py", library])
        stamp.write_text(fingerprint + "\n")
    return environment, compiler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup-only", action="store_true")
    args = parser.parse_args()
    PRIVATE.mkdir(parents=True, exist_ok=True)
    # Cargo locks its artifacts only after preparation. Protect the private
    # compiler sources too, including against another setup-only invocation.
    with (PRIVATE / "build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return build(args.setup_only)


def build(setup_only):
    environment, compiler = prepare()
    if setup_only:
        return 0
    # subprocess does not inherit make's jobserver descriptors. Do not pass
    # stale descriptor numbers to Cargo/rustc when invoked through make -j.
    for name in ("MAKEFLAGS", "MFLAGS", "CARGO_MAKEFLAGS"):
        environment.pop(name, None)
    environment["RUSTC"] = str(compiler)
    environment["RUSTDOC"] = str(INSTALLED / "bin/rustdoc")
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
        "-Crelocation-model=static", "-Ccode-model=small",
        f"-Clinker={INSTALLED / 'lib/rustlib' / HOST / 'bin/rust-lld'}",
        f"-Clink-arg=-T{ROOT / 'userspace/linker.ld'}",
        "-Clink-arg=--build-id=none",
    ])
    run([INSTALLED / "bin/cargo", "build", "--release", "--locked",
         "-Zbuild-std=std,panic_abort", "-Zbuild-std-features=compiler-builtins-mem",
         "-Zjson-target-spec", "--target", TARGET,
         "--manifest-path", ROOT / "userspace/std-demo/Cargo.toml",
         "--target-dir", ROOT / "target/std-demo"], env=environment)
    artifact = ROOT / "target/std-demo/x86_64-unknown-kernel/release/std-demo"
    destination = ROOT / "build/std/std-demo.elf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Kernel builds read the ELF after releasing this script's lock. Publish
    # complete files by rename so they never observe a partially copied image.
    with tempfile.TemporaryDirectory(prefix=".publish-", dir=destination.parent) as temporary:
        image = Path(temporary) / destination.name
        manifest = Path(temporary) / "toolchain.json"
        shutil.copy2(artifact, image)
        manifest.write_text(json.dumps({
            "toolchain": TOOLCHAIN, "compiler": COMPILER,
            "port_sha256": (PRIVATE / "port.sha256").read_text().strip(),
            "elf_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        }, indent=2) + "\n")
        image.replace(destination)
        manifest.replace(destination.parent / manifest.name)
    print(f"Built {destination.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"std build failed: {error}", file=sys.stderr)
        sys.exit(1)
