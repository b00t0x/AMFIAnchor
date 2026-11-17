# AMFIAnchor

AMFIAnchor is a Lilu plugin for running components signed by an explicitly
trusted CA on **x86_64 macOS Big Sur through Tahoe** with AMFI enabled.

`AMFIAnchor.kext` loads anchors from separate codeless kexts. The bundled
`AMFIAnchor-b00t0x.kext` provides the signing anchor used by WEX and other
b00t0x components signed under the same CA. Each anchor grants platform trust
to the supported signing hierarchy across the system. Install only anchors
whose signer you trust.

## Install with OpenCore

1. Copy `AMFIAnchor.kext` and the anchor kext or kexts you need to `EFI/OC/Kexts`.
   Use Lilu 1.7.2 or later.
2. Add and enable the entries in `Kernel -> Add` in this order:

   | Order | BundlePath | ExecutablePath |
   | --- | --- | --- |
   | 1 | `Lilu.kext` | `Contents/MacOS/Lilu` |
   | 2 | `AMFIAnchor.kext` | `Contents/MacOS/AMFIAnchor` |
   | 3 | `AMFIAnchor-b00t0x.kext` or your own anchor kext | Empty string |
   | 4 | `AMFIPass.kext` (optional, for OCLP) | `Contents/MacOS/AMFIPass` |

   Set `PlistPath` to `Contents/Info.plist` for each entry. Keep AMFI enabled.
   For AMFIAnchor and its anchor kexts, set `MinKernel` to `20.0.0` and
   `MaxKernel` to `25.99.99`. For OCLP on Tahoe with stock AMFIPass 1.4.1,
   make sure its entry allows Darwin 25 and add `-amfipassbeta` to `boot-args`.
   AMFIAnchor runs without that flag or AMFIPass.
   When migrating from the older WEX injector, replace its entry with
   `AMFIAnchor-b00t0x.kext`. Enable only one injector for the same CA.
3. Reboot. To confirm registration, run `ioreg -r -c AMFIAnchor -l` and check
   that `InstallStatus` is 1 and `LoadedAnchors` contains your anchor.

## Development

- [Generate your own anchor kext and sign a module](Docs/Signing.md).
- [Build from source and run the checks](CONTRIBUTING.md).
- [Provider schema](Docs/ProviderSchema.md), [implementation](Docs/Design.md),
  and [tested configurations](Docs/Validation.md).

AMFIAnchor is independently implemented following compatibility analysis of
AMFIPass 1.4.1 and CoreTrust. See [NOTICES.md](NOTICES.md) for research
attribution, build dependencies, and license notices.
