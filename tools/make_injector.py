#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 b00t0x

"""Create an AMFIAnchor codeless provider from a public CA certificate."""

import argparse
import os
from pathlib import Path
import plistlib
import re
import subprocess


ENGINE_IDENTIFIER = "org.b00t0x.AMFIAnchor"
MINIMUM_ENGINE_VERSION = "0.1.0"


def openssl(*arguments, input_data=None):
    environment = dict(os.environ, LC_ALL="C")
    return subprocess.check_output(["openssl", *map(str, arguments)], input=input_data, env=environment)


def valid_identifier(value):
    return re.fullmatch(r"[A-Za-z0-9._-]{1,63}", value) is not None


def read_anchor(certificate):
    contents = certificate.read_bytes()
    if b"PRIVATE KEY" in contents:
        raise ValueError("Supply a public CA certificate without private-key material")
    encoding = "PEM" if contents.lstrip().startswith(b"-----BEGIN") else "DER"
    prefix = ["x509", "-inform", encoding, "-in", certificate]
    description = openssl(*prefix, "-noout", "-text").decode()
    match = re.search(r"X509v3 Subject Key Identifier:\s*\n\s*([0-9A-Fa-f:]+)", description)
    if "CA:TRUE" not in description or not match:
        raise ValueError("A public CA certificate with a subject key identifier is required")
    key_identifier = bytes.fromhex(match[1].replace(":", ""))
    public_key_pem = openssl(*prefix, "-pubkey", "-noout")
    public_key = openssl("pkey", "-pubin", "-outform", "DER", input_data=public_key_pem)
    if len(key_identifier) != 20 or not any(key_identifier) or not 64 <= len(public_key) <= 1024:
        raise ValueError("Unsupported public-key or subject-key-identifier size")
    return {"Enabled": True, "SPKI": public_key, "SKID": key_identifier}


def make_injector(bundle, bundle_identifier, anchor_identifier, certificate):
    if not valid_identifier(bundle_identifier) or not valid_identifier(anchor_identifier):
        raise ValueError("IDs must contain 1-63 ASCII letters, digits, periods, underscores or hyphens")
    if bundle.exists():
        raise ValueError("Output bundle already exists")
    anchor = read_anchor(certificate)
    personality = {
        "CFBundleIdentifier": ENGINE_IDENTIFIER,
        "IOClass": "AMFIAnchorProvider",
        "IOProviderClass": "IOResources",
        "IOResourceMatch": "IOKit",
        "IOMatchCategory": bundle_identifier,
        "AMFIAnchorProviderID": bundle_identifier,
        "AMFIAnchorConfig": {"SchemaVersion": 1, "Anchors": {anchor_identifier: anchor}},
    }
    info = {
        "CFBundleIdentifier": bundle_identifier,
        "CFBundleName": bundle.stem,
        "CFBundleVersion": "1.0.0",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundlePackageType": "KEXT",
        "OSBundleRequired": "Root",
        "OSBundleLibraries": {ENGINE_IDENTIFIER: MINIMUM_ENGINE_VERSION},
        "IOKitPersonalities": {bundle_identifier: personality},
    }
    (bundle / "Contents").mkdir(parents=True)
    (bundle / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--anchor-id", required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        make_injector(arguments.bundle, arguments.bundle_id, arguments.anchor_id, arguments.certificate)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(arguments.bundle)


if __name__ == "__main__":
    main()
