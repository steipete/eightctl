#!/usr/bin/env python3
"""Check every Mach-O slice against the documented macOS 13 minimum."""

import argparse
import re
import subprocess


def check_load_commands(output):
    targets = []
    slices = len(re.findall(r"(?m)^Load command 0$", output))
    for block in re.split(r"(?m)^Load command \d+\s*$", output)[1:]:
        if not re.search(r"(?m)^\s*cmd LC_BUILD_VERSION$", block):
            continue
        if not re.search(r"(?m)^\s*platform (?:1|MACOS)$", block):
            raise ValueError("expected macOS platform")
        match = re.search(r"(?m)^\s*minos (\d+\.\d+(?:\.\d+)?)$", block)
        if not match or tuple(map(int, match[1].split("."))) not in ((13, 0), (13, 0, 0)):
            raise ValueError("expected LC_BUILD_VERSION minos 13.0")
        targets.append(match[1])
    if not slices or len(targets) != slices:
        raise ValueError("expected one LC_BUILD_VERSION per Mach-O slice")
    return targets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("goos", choices=("darwin", "linux", "windows"))
    args = parser.parse_args()
    if args.goos != "darwin":
        return
    try:
        output = subprocess.check_output(["otool", "-arch", "all", "-l", args.binary], text=True)
        targets = check_load_commands(output)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise SystemExit(f"macOS deployment-target check failed: {error}") from error
    print(f"{args.binary}: all {len(targets)} slices have minos 13.0")


if __name__ == "__main__":
    main()
