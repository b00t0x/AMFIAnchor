# Sign your own modules

Use a dedicated RSA chain for modules you want AMFIAnchor to trust. The
tested profile uses a 4096-bit root and intermediate, a 2048-bit signing leaf,
and a 20-byte root subject key identifier. The intermediate and leaf both
carry the Code Signing EKU and the platform marker
`1.2.840.113635.100.6.22` as a DER NULL. Keep the CA and signing keys private.

## Create a signing chain

Run from the AMFIAnchor checkout with OpenSSL installed. Skip this section if
you already have a chain with the same profile. Use certificate names that
identify your project or public handle.

```sh
profile="$PWD/Docs/signing-ca.cnf"
umask 077
mkdir "$HOME/my-anchor-signing"
cd "$HOME/my-anchor-signing"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out root.key.pem
openssl req -new -x509 -sha256 -days 3650 -key root.key.pem \
  -subj '/CN=Example Root CA' -config "$profile" -extensions root_ca -out root.cert.pem

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out intermediate.key.pem
openssl req -new -sha256 -key intermediate.key.pem \
  -subj '/CN=Example Code Signing CA' -config "$profile" -out intermediate.csr.pem
openssl x509 -req -sha256 -days 1825 -in intermediate.csr.pem \
  -CA root.cert.pem -CAkey root.key.pem -CAcreateserial \
  -extfile "$profile" -extensions intermediate_ca -out intermediate.cert.pem

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf.key.pem
openssl req -new -sha256 -key leaf.key.pem \
  -subj '/CN=Example Software Signing' -config "$profile" -out leaf.csr.pem
openssl x509 -req -sha256 -days 365 -in leaf.csr.pem \
  -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial \
  -extfile "$profile" -extensions code_signing -out leaf.cert.pem

openssl verify -CAfile root.cert.pem -untrusted intermediate.cert.pem leaf.cert.pem
```

## Generate the codeless kext

From the checkout, generate an injector with Python 3.9 or later and OpenSSL
on your PATH. Supply the **public root certificate** in PEM or DER format.
Choose unique bundle and anchor IDs for your CA.

```sh
python3 tools/make_injector.py \
  --certificate "$HOME/my-anchor-signing/root.cert.pem" \
  --bundle ExampleAnchor.kext --bundle-id org.example.ExampleAnchor \
  --anchor-id org.example.code-signing
```

Install the resulting kext using the [OpenCore order](../README.md#install-with-opencore).
You can install several of these kexts together. Each generated bundle contains
an `Info.plist` with the root's public key and SKID.

## Sign a module

Use [rcodesign 0.29.0](https://github.com/indygreg/apple-platform-rs/releases/tag/apple-codesign%2F0.29.0).
Run from the signing directory. This example creates a separate signed copy
of a standalone Mach-O. Supply the leaf key and the entire certificate chain
including the root.

```sh
rcodesign sign -C /dev/null --timestamp-url none \
  --pem-file leaf.key.pem --pem-file leaf.cert.pem \
  --pem-file intermediate.cert.pem --pem-file root.cert.pem \
  /path/to/MyModule.dylib /path/to/MyModule-signed.dylib

rcodesign verify /path/to/MyModule-signed.dylib
rcodesign print-signature-info /path/to/MyModule-signed.dylib
```

Check for `signature_verifies: true` and all three certificates in the CMS.
For bundles, pass the bundle as input and output so the resource seal is built
too. Preserve required entitlements and review which nested code is signed.
Then test the actual module on a boot that has your anchor registered. A
successful cryptographic check alone does not establish CoreTrust acceptance.
