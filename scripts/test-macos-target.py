#!/usr/bin/env python3
"""Synthetic deployment-target regression tests; no Apple tooling required."""

import runpy
import unittest
from pathlib import Path

check = runpy.run_path(str(Path(__file__).with_name("check-macos-target.py")))["check_load_commands"]


def slice_output(minos="13.0", platform="1"):
    return f"Load command 0\n      cmd LC_BUILD_VERSION\n  cmdsize 32\n platform {platform}\n    minos {minos}\n      sdk 15.0\n"


class DeploymentTargetTests(unittest.TestCase):
    def test_thin_and_universal(self):
        self.assertEqual(check(slice_output()), ["13.0"])
        self.assertEqual(check(slice_output() + slice_output("13.0.0", "MACOS")), ["13.0", "13.0.0"])

    def test_rejects_incompatible_slice(self):
        for target in ("14.0", "13.1", "12.0", "garbage"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                check(slice_output() + slice_output(target))

    def test_rejects_missing_or_wrong_platform(self):
        for output in ("", slice_output(platform="2"), slice_output().replace("LC_BUILD_VERSION", "LC_VERSION_MIN_MACOSX"), slice_output() + "Load command 0\n      cmd LC_UUID\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                check(output)


if __name__ == "__main__":
    unittest.main()
