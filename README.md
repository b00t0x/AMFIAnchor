# AMFIAnchor

AMFIAnchor is a Lilu plugin that adds explicitly configured signing anchors to
CoreTrust. Anchor data lives in separate codeless injector kexts, so updating the
engine does not require editing its `Info.plist`.

The initial public source supports **x86_64 macOS Tahoe / Darwin 25**. Earlier
private prototypes covered other kernel generations; that does not qualify this
provider-based implementation for those systems.

## Usage

- For independently signed components, use Lilu, AMFIAnchor, and your anchor
  injector(s). AMFIPass and `-amfipassbeta` are not required for this use.
- To also use unmodified OCLP, add stock AMFIPass **after AMFIAnchor** in
  OpenCore's `Kernel -> Add`. AMFIPass 1.4.1 needs its own `-amfipassbeta` on Tahoe.
  AMFIAnchor does not change OCLP detection or AMFIPass's version acceptance.

Keep AMFI enabled. AMFIAnchor preserves native root evaluation and adds the
configured roots; it does not disable AMFI globally. It contains no default
anchor, including Dortania's, and does not change boot arguments.

An accepted anchor grants the supported signing hierarchy platform trust; it
is **not restricted to a GPU bundle or a bundle identifier**. Treat control of
that CA's signing key accordingly. The engine uses private CoreTrust structures
and must be revalidated for each new kernel generation.

## Build

Use macOS with Xcode command-line tools, Python 3.9 or later, and existing source
checkouts of [Lilu](https://github.com/acidanthera/Lilu) and
[MacKernelSDK](https://github.com/acidanthera/MacKernelSDK). Tested dependency
revisions are recorded in [NOTICES.md](NOTICES.md).

```sh
python3 tools/build.py --lilu /path/to/Lilu/Lilu --sdk /path/to/MacKernelSDK
```

The bundle is `build/Release/AMFIAnchor.kext`; `manifest.json` records its UUID,
hashes, and source hashes. Add `--configuration Debug` for a debug build. The
script does not download dependencies or sign the resulting bundle.

## Create an anchor injector

Supply a **public CA certificate** in PEM or DER format, with a 20-byte subject
key identifier. The tool extracts the SPKI and SKID; private keys stay outside
the kext.

```sh
python3 tools/make_injector.py \
  --certificate /path/to/public-ca.pem \
  --bundle /path/to/MyAnchor.kext \
  --bundle-id org.example.MyAnchor \
  --anchor-id MySigningCA
```

Add the engine and each injector to OpenCore. Injectors have no executable and
depend on `org.b00t0x.AMFIAnchor` version 0.1.0 or later. Multiple injectors and
multiple anchors per injector are supported; use unique provider categories
and anchor IDs. See [the schema](Docs/ProviderSchema.md) for the exact contract,
limits, duplicate handling, and diagnostics.

## Development and provenance

Read [the coding standard](Docs/CodingStyle.md), [design](Docs/Design.md), and
[validation record](Docs/Validation.md). Run the checks in
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

AMFIAnchor is independently implemented following compatibility analysis of
AMFIPass 1.4.1 and CoreTrust. This was **not a clean-room process**. No AMFIPass
binary or decompiled source is distributed here. This is not an official
Acidanthera or Dortania project. Original code is BSD-3-Clause; dependency
licenses and research attribution are in [NOTICES.md](NOTICES.md).
