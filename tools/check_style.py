#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 b00t0x

"""Check the repository's pinned C++ format and basic source hygiene."""

import argparse
import ast
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def find_formatter():
    candidate = os.environ.get("CLANG_FORMAT") or shutil.which("clang-format")
    if not candidate:
        try:
            candidate = subprocess.check_output(["xcrun", "--find", "clang-format"], text=True).strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            sys.exit("clang-format 17 is required; set CLANG_FORMAT to its executable")
    version = subprocess.check_output([candidate, "--version"], text=True)
    if not re.search(r"version 17\.", version):
        sys.exit("Use clang-format 17 so local and CI formatting agree")
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="apply C++ formatting before checking")
    arguments = parser.parse_args()
    formatter = find_formatter()
    cpp_files = sorted((ROOT / "AMFIAnchor").glob("*.cpp")) + sorted((ROOT / "AMFIAnchor").glob("*.hpp"))
    if arguments.fix:
        subprocess.run([formatter, "-i", *map(str, cpp_files)], check=True)
    subprocess.run([formatter, "--dry-run", "--Werror", *map(str, cpp_files)], check=True)

    python_files = sorted((ROOT / "tools").glob("*.py")) + sorted((ROOT / "tests").glob("*.py"))
    failures = []
    for path in cpp_files + python_files:
        source = path.read_text()
        relative = path.relative_to(ROOT)
        if "SPDX-License-Identifier: BSD-3-Clause" not in "\n".join(source.splitlines()[:4]):
            failures.append(f"{relative}: missing SPDX header")
        if not source.endswith("\n"):
            failures.append(f"{relative}: missing final newline")
        for number, line in enumerate(source.splitlines(), 1):
            if line.rstrip() != line:
                failures.append(f"{relative}:{number}: trailing whitespace")
            if path.suffix == ".py" and ("\t" in line or len(line) > 120):
                failures.append(f"{relative}:{number}: Python tabs or line longer than 120 columns")
        if path.suffix == ".py":
            ast.parse(source, filename=str(relative))
    if failures:
        sys.exit("\n".join(failures))
    print(f"Style checks passed ({len(cpp_files)} C++ and {len(python_files)} Python files)")


if __name__ == "__main__":
    main()
