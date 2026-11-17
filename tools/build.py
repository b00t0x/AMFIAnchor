#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 b00t0x

"""Build the x86_64 kext using explicit, existing Lilu and MacKernelSDK trees."""

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    # Keep compiler working-directory metadata inside the mapped source root,
    # even when the script is invoked from another directory.
    subprocess.run([str(argument) for argument in command], check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lilu", type=Path, default=ROOT / "Lilu" / "Lilu")
    parser.add_argument("--sdk", type=Path, default=ROOT / "MacKernelSDK")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    arguments = parser.parse_args()

    lilu = arguments.lilu.resolve()
    sdk = arguments.sdk.resolve()
    if (lilu / "Lilu" / "Headers").is_dir():
        lilu = lilu / "Lilu"
    lilu_bootstrap = lilu / "Library" / "plugin_start.cpp"
    if not (lilu / "Headers" / "plugin_start.hpp").is_file() or not lilu_bootstrap.is_file():
        parser.error("--lilu must identify the Lilu source directory containing Headers and Library/plugin_start.cpp")
    if not (sdk / "Library" / "x86_64" / "libkmod.a").is_file():
        parser.error("--sdk must identify a MacKernelSDK checkout with x86_64 libkmod.a")

    source_directory = ROOT / "AMFIAnchor"
    info_path = source_directory / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    output = ROOT / "build" / arguments.configuration
    contents = output / "AMFIAnchor.kext" / "Contents"
    (contents / "MacOS").mkdir(parents=True, exist_ok=True)

    # Prefix maps keep the public artifact independent of private checkout paths.
    flags = [
        "xcrun", "clang++", "-arch", "x86_64", "-std=c++14", "-O2", "-g",
        "-mkernel", "-fapple-kext", "-fno-exceptions", "-fno-rtti",
        "-fno-stack-protector", "-fno-builtin", "-mno-red-zone", "-nostdinc",
        "-DKERNEL", "-DKERNEL_PRIVATE", "-D__APPLE__", "-D__MACH__",
        f"-DDEBUG={int(arguments.configuration == 'Debug')}", "-DLILU_CUSTOM_IOKIT_INIT",
        "-DPRODUCT_NAME=AMFIAnchor", f"-DMODULE_VERSION={info['CFBundleVersion']}",
        "-isystem", str(sdk / "Headers"), "-isystem", str(lilu),
        "-mmacosx-version-min=10.15", "-Wall", "-Wextra", "-Werror",
        "-Wno-deprecated-declarations", "-Wno-unused-parameter",
    ]
    for path, label in [(ROOT, "AMFIAnchor"), (lilu, "Lilu"), (sdk, "MacKernelSDK")]:
        flags.extend([f"-fdebug-prefix-map={path}={label}", f"-ffile-prefix-map={path}={label}"])

    objects = []
    for source in sorted(source_directory.glob("*.cpp")) + [lilu_bootstrap]:
        object_path = output / f"{source.stem}.o"
        run(flags + ["-c", source, "-o", object_path])
        objects.append(object_path)

    binary = contents / "MacOS" / "AMFIAnchor"
    run([
        "xcrun", "ld", "-arch", "x86_64", "-kext", "-undefined", "dynamic_lookup",
        "-no_fixup_chains", "-macos_version_min", "10.15", "-o", binary,
        "-oso_prefix", str(ROOT) + "/",
        *objects, sdk / "Library" / "x86_64" / "libkmod.a",
    ])
    shutil.copyfile(info_path, contents / "Info.plist")

    uuid = subprocess.check_output(["dwarfdump", "--uuid", str(binary)], text=True).split()[1]
    bundle = contents.parent
    source_files = sorted(source_directory.glob("*.cpp")) + sorted(source_directory.glob("*.hpp"))
    source_files.append(info_path)
    manifest = {
        "version": info["CFBundleVersion"],
        "configuration": arguments.configuration,
        "uuid": uuid,
        "binary_sha256": sha256(binary),
        "lilu_bootstrap_sha256": sha256(lilu_bootstrap),
        "source_files": {str(path.relative_to(ROOT)): sha256(path) for path in source_files},
        "files": {str(path.relative_to(bundle)): sha256(path) for path in bundle.rglob("*") if path.is_file()},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({key: manifest[key] for key in ["version", "configuration", "uuid", "binary_sha256"]}, indent=2))


if __name__ == "__main__":
    main()
