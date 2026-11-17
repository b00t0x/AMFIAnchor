#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 b00t0x

"""Exercise the public-certificate boundary and codeless-provider contract."""

import hashlib
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("make_injector", ROOT / "tools" / "make_injector.py")
injector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(injector)


class InjectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.certificate = cls.create_certificate("root", True)
        cls.other_certificate = cls.create_certificate("other", True)
        cls.leaf = cls.create_certificate("leaf", False)
        cls.der = cls.directory / "root.der"
        cls.der.write_bytes(injector.openssl("x509", "-in", cls.certificate, "-outform", "DER"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def create_certificate(cls, name, is_ca):
        configuration = cls.directory / f"{name}.cnf"
        configuration.write_text(
            "[req]\nprompt=no\ndistinguished_name=subject\nx509_extensions=extensions\n"
            f"[subject]\nCN=Ephemeral {name}\n[extensions]\n"
            f"basicConstraints=critical,CA:{'TRUE' if is_ca else 'FALSE'}\n"
            "subjectKeyIdentifier=hash\n"
        )
        key = cls.directory / f"{name}.key"
        certificate = cls.directory / f"{name}.pem"
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-config", str(configuration), "-keyout", str(key), "-out", str(certificate)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return certificate

    def test_pem_and_der_preserve_the_same_public_anchor(self):
        anchor = injector.read_anchor(self.certificate)
        self.assertEqual(anchor, injector.read_anchor(self.der))
        self.assertEqual(len(anchor["SKID"]), 20)
        self.assertGreater(len(anchor["SPKI"]), 64)
        self.assertTrue(anchor["Enabled"])

    def test_separate_injectors_match_independently(self):
        providers = []
        with tempfile.TemporaryDirectory() as directory:
            for name, certificate in [("First", self.certificate), ("Second", self.other_certificate)]:
                bundle = Path(directory) / f"{name}.kext"
                identifier = f"org.example.{name}"
                injector.make_injector(bundle, identifier, name, certificate)
                info = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes())
                self.assertNotIn("CFBundleExecutable", info)
                self.assertEqual(info["OSBundleLibraries"], {injector.ENGINE_IDENTIFIER: "0.1.0"})
                provider = info["IOKitPersonalities"][identifier]
                self.assertEqual(provider["CFBundleIdentifier"], injector.ENGINE_IDENTIFIER)
                self.assertEqual(provider["IOClass"], "AMFIAnchorProvider")
                self.assertEqual(provider["IOMatchCategory"], identifier)
                self.assertEqual(provider["AMFIAnchorProviderID"], identifier)
                self.assertEqual(provider["AMFIAnchorConfig"]["SchemaVersion"], 1)
                self.assertEqual(provider["AMFIAnchorConfig"]["Anchors"][name], injector.read_anchor(certificate))
                providers.append(provider)
            self.assertNotEqual(providers[0]["IOMatchCategory"], providers[1]["IOMatchCategory"])

    def test_private_keys_and_combined_pem_are_rejected(self):
        combined = self.directory / "combined.pem"
        key = self.directory / "root.key"
        combined.write_bytes(self.certificate.read_bytes() + key.read_bytes())
        for path in [key, combined]:
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "public CA certificate"):
                injector.read_anchor(path)

    def test_non_ca_certificate_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "public CA certificate"):
            injector.read_anchor(self.leaf)

    def test_invalid_identifier_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Invalid.kext"
            for identifier in ["", "a" * 64, "contains space", "slash/name", "nonascii-\u00e9"]:
                with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                    injector.make_injector(bundle, identifier, "Anchor", self.certificate)
                self.assertFalse(bundle.exists())

    def test_existing_bundle_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Existing.kext"
            bundle.mkdir()
            marker = bundle / "keep.txt"
            marker.write_text("existing content")
            with self.assertRaisesRegex(ValueError, "already exists"):
                injector.make_injector(bundle, "org.example.Existing", "Anchor", self.certificate)
            self.assertEqual(marker.read_text(), "existing content")
            self.assertFalse((bundle / "Contents").exists())

    def test_bundled_injector_keeps_the_wex_signing_anchor(self):
        bundle = ROOT / "Injectors" / "AMFIAnchor-b00t0x.kext"
        info_path = bundle / "Contents" / "Info.plist"
        self.assertEqual([path for path in bundle.rglob("*") if path.is_file()], [info_path])
        info = plistlib.loads(info_path.read_bytes())
        identifier = info["CFBundleIdentifier"]
        provider = info["IOKitPersonalities"][identifier]
        config = provider["AMFIAnchorConfig"]
        self.assertNotIn("CFBundleExecutable", info)
        self.assertEqual(info["CFBundleName"], bundle.stem)
        self.assertEqual(info["OSBundleLibraries"], {injector.ENGINE_IDENTIFIER: "0.1.0"})
        self.assertEqual(provider["CFBundleIdentifier"], injector.ENGINE_IDENTIFIER)
        self.assertEqual(provider["IOClass"], "AMFIAnchorProvider")
        self.assertEqual(provider["IOMatchCategory"], identifier)
        self.assertEqual(config["SchemaVersion"], 1)
        self.assertEqual(list(config["Anchors"]), ["b00t0x"])
        anchor = config["Anchors"]["b00t0x"]
        self.assertTrue(anchor["Enabled"])
        self.assertEqual(anchor["SKID"].hex(), "55dc97886cd4a8562408947435b8e5c3d0e1b0c0")
        self.assertEqual(
            hashlib.sha256(anchor["SPKI"]).hexdigest(),
            "19212ca6a6bf9658617d493cd851f34b3f542aed3b6a95a455143b477e032c7b",
        )


if __name__ == "__main__":
    unittest.main()
