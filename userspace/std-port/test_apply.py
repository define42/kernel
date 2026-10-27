#!/usr/bin/env python3
"""Check fail-closed patching against the pinned pristine source tree."""

import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("std_port_apply", HERE / "apply.py")
assert SPEC is not None and SPEC.loader is not None
PORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PORT)


class PatchTests(unittest.TestCase):
    source: Path

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kernel-std-port-")
        self.addCleanup(self.temporary.cleanup)
        self.library = Path(self.temporary.name)
        self.originals = {}
        for line in (HERE / "upstream.sha256").read_text().splitlines():
            _, relative = line.split("  ", 1)
            contents = (self.source / relative).read_bytes()
            self.originals[relative] = contents
            destination = self.library / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(contents)

    def test_patches_real_dispatch_and_copies_overlays(self):
        PORT.apply(self.library)
        for relative, original in self.originals.items():
            self.assertNotEqual((self.library / relative).read_bytes(), original)
        for overlay in (HERE / "overlay").rglob("*.rs"):
            destination = self.library / overlay.relative_to(HERE / "overlay")
            self.assertEqual(destination.read_bytes(), overlay.read_bytes())
        with self.assertRaisesRegex(ValueError, "upstream source mismatch"):
            PORT.apply(self.library)

    def test_modified_upstream_fails_before_any_mutation(self):
        changed = "std/src/sys/thread_local/mod.rs"
        (self.library / changed).write_bytes(self.originals[changed] + b"\n// unexpected\n")
        before = {p: (self.library / p).read_bytes() for p in self.originals}
        with self.assertRaisesRegex(ValueError, "upstream source mismatch"):
            PORT.apply(self.library)
        self.assertEqual(before, {p: (self.library / p).read_bytes() for p in self.originals})
        self.assertFalse((self.library / "std/src/sys/pal/kernel/mod.rs").exists())

    def test_existing_overlay_fails_before_dispatch_mutation(self):
        destination = self.library / "std/src/sys/pal/kernel/mod.rs"
        destination.parent.mkdir(parents=True)
        destination.write_text("unexpected overlay\n")
        with self.assertRaisesRegex(ValueError, "overlay already exists"):
            PORT.apply(self.library)
        for relative, original in self.originals.items():
            self.assertEqual((self.library / relative).read_bytes(), original)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    args, remaining = parser.parse_known_args()
    PatchTests.source = args.library.resolve(strict=True)
    unittest.main(argv=[__file__, *remaining])
