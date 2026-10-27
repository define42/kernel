#!/usr/bin/env python3
"""Patch a disposable COPY of nightly-2026-04-15's Rust library sources.

Usage: python3 userspace/std-port/apply.py PATH/TO/COPIED/rust/library

The caller must restore the pristine copy before each application. Every edited
upstream file is hash checked before any file is changed. Never invoke this on
a shared rustup installation: build_std.py supplies a private compiler sysroot.
"""

import argparse
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"expected exactly one upstream patch anchor: {old!r}")
    return source.replace(old, new, 1)


def branch(source: str, body: str) -> str:
    pattern = r"^cfg_select! \{\n"
    if len(re.findall(pattern, source, re.MULTILINE)) != 1:
        raise ValueError("unexpected upstream platform dispatch")
    return re.sub(pattern, lambda _: "cfg_select! {\n" + body, source, count=1, flags=re.MULTILINE)


def patched_sources(library: Path) -> dict[str, str]:
    result = {}
    reexports = {
        "pal": "        mod kernel;\n        pub use self::kernel::*;\n",
        "alloc": "        mod kernel;\n",
        "stdio": "        mod kernel;\n        pub use kernel::*;\n",
        "random": "        mod kernel;\n        pub use kernel::fill_bytes;\n",
        "time": "        mod kernel;\n        use kernel as imp;\n",
        "env": "        mod kernel;\n        pub use kernel::*;\n",
        "io/error": "        mod kernel;\n        pub use kernel::*;\n",
        "sync/thread_parking": "        mod kernel;\n        pub use kernel::Parker;\n",
        "thread": (
            "        mod kernel;\n"
            "        pub use kernel::{available_parallelism, sleep, yield_now};\n"
            "        #[expect(dead_code)]\n"
            "        mod unsupported;\n"
            "        pub use unsupported::{Thread, current_os_id, set_name, DEFAULT_MIN_STACK_SIZE};\n"
        ),
    }
    for name, body in reexports.items():
        path = f"std/src/sys/{name}/mod.rs"
        source = (library / path).read_text()
        result[path] = branch(source, '    target_os = "kernel" => {\n' + body + "    }\n")

    path = "std/src/sys/thread_local/mod.rs"
    source = (library / path).read_text()
    # Exactly the no_threads implementation selector and the no-op exit guard.
    if source.count('target_os = "uefi",') != 2:
        raise ValueError("unexpected upstream TLS dispatch")
    source = source.replace('target_os = "uefi",', 'target_os = "kernel", target_os = "uefi",')
    result[path] = source

    path = "std/src/sys/exit.rs"
    source = (library / path).read_text()
    source = replace_once(source, "pub fn exit(code: i32) -> ! {\n    cfg_select! {\n", (
        "pub fn exit(code: i32) -> ! {\n    cfg_select! {\n"
        '        target_os = "kernel" => {\n'
        "            crate::sys::pal::exit(code)\n"
        "        }\n"
    ))
    result[path] = source

    path = "std/build.rs"
    result[path] = replace_once((library / path).read_text(),
        '    if target_os == "linux"\n',
        '    if target_os == "kernel"\n        || target_os == "linux"\n')

    path = "std/src/sys/env_consts.rs"
    result[path] = replace_once((library / path).read_text(), 'cfg_unordered! {\n', '''cfg_unordered! {

#[cfg(target_os = "kernel")]
pub mod os {
    pub const FAMILY: &str = "";
    pub const OS: &str = "kernel";
    pub const DLL_PREFIX: &str = "";
    pub const DLL_SUFFIX: &str = "";
    pub const DLL_EXTENSION: &str = "";
    pub const EXE_SUFFIX: &str = ".elf";
    pub const EXE_EXTENSION: &str = "elf";
}
''')
    return result


def apply(library: Path) -> None:
    library = library.resolve(strict=True)
    expected = {}
    for line in (HERE / "upstream.sha256").read_text().splitlines():
        digest, path = line.split("  ", 1)
        expected[path] = digest
    for path, digest in expected.items():
        actual = hashlib.sha256((library / path).read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"upstream source mismatch: {path}; restore pinned pristine sources")
    sources = patched_sources(library)
    if set(sources) != set(expected):
        raise ValueError("patched-file manifest does not match hash manifest")
    overlays = list((HERE / "overlay").rglob("*.rs"))
    for overlay in overlays:
        destination = library / overlay.relative_to(HERE / "overlay")
        if destination.exists():
            raise ValueError(f"overlay already exists: {destination}; restore pristine sources")
    for path, source in sources.items():
        (library / path).write_text(source)
    for overlay in overlays:
        destination = library / overlay.relative_to(HERE / "overlay")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(overlay.read_bytes())
    print(f"Applied kernel std port: {len(sources)} dispatch patches, {len(overlays)} overlays")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path, help="disposable copied Rust library source directory")
    arguments = parser.parse_args()
    try:
        apply(arguments.library)
    except (OSError, ValueError) as error:
        parser.exit(1, f"std port: {error}\n")
