# Validation

## Local checks

Version 0.1.2 passed clang-format 17 and the repository whitespace, SPDX, and
Python syntax checks, all six injector tests, and Release and Debug builds
against the dependency revisions in `NOTICES.md`.

## Version 0.1.2: Big Sur through Tahoe

On 2026-11-16, the same Release artifact passed the signing controls and ten GPU
checks in each of twelve configurations on an Intel Core i7-12700H / Iris Xe
system with Lilu 1.7.2 and the existing WEX graphics payload. Each OS was tested
with AMFIAnchor alone and with stock AMFIPass 1.4.1 loaded after it. Two separate
codeless injectors and their SPKI/SKID bytes were unchanged throughout.

- Implementation commit: `588c4c5`.
- Loaded UUID: `D14CFC01-5538-3540-9987-1D0ABD2B08E6`.
- Binary SHA-256: `33f627ccae6ba142424abb9e84939192163f83fe0d84356708d6173044b8d4f2`.
- Every engine source-file hash in the frozen build manifest matches that commit.
  These identify the tested artifact; linker metadata may change on a rebuild.

| OS | Build | Standalone runtime controls | Stock AMFIPass runtime controls | Native NULL no-op recognised |
| --- | --- | --- | --- | --- |
| Big Sur | 20G1443 | Passed | Passed | No |
| Monterey | 21H1320 | Passed | Passed | No |
| Ventura | 22H730 | Passed | Passed | No |
| Sonoma | 23J631 | Passed after power recovery | Passed | No |
| Sequoia | 24H232 | Passed | Passed | Yes |
| Tahoe | 25G332 | Passed | Passed | No |

**Restart stability remains unresolved.** After the successful Sonoma coexistence
run, a normal restart froze during graphics-driver shutdown, before BIOS or the
next standalone boot. The display showed a GPU register dump and `Trying to
restart GPU`. The retained kernel log records shutdown beginning and an
`IOAccelEventMachine2::waitForStamp` timeout. The running kernel still had both
plugins loaded; the next EFI configuration had not taken effect. A power cycle
recovered Sonoma, where the standalone runtime controls then passed. This does
not establish the cause of the shutdown failure or qualify every restart path.

### Signing and graphics controls

| Control, on all six OS builds | Standalone | Stock AMFIPass, manual `-amfipassbeta` |
| --- | --- | --- |
| Two registered CA libraries, Library Validation enabled | Accepted | Accepted |
| Apple-signed library | Accepted | Accepted |
| Dortania-signed library | Rejected | Accepted |
| Unregistered CA library | Rejected | Rejected |
| Modified registered CA libraries and executables | Killed | Killed |
| Registered CA executables | Platform flag set | Platform flag set |
| Unregistered CA executable | Platform flag absent | Platform flag absent |
| GPU/API suite, ten tests per configuration | Passed | Passed |

The collector matched each OS's installed graphics-file inventory, loaded kext
UUIDs, WindowServer's Metal-driver mapping, engine and injector hashes, raw
IORegistry anchor dictionaries, personality publishers, and increases in each
anchor's match counters. Library and executable controls ran as the unprivileged
logged-in user. Ordinary executable launch alone was not used as proof of trust.

The root-omitted signing sample was accepted on Big Sur and Monterey and rejected
on Ventura through Tahoe in both modes. These results match the earlier
OS-specific controls, including the Sequoia Mod AMFIPass baseline; they do not
establish support for every signing hierarchy.

GPU checks covered Metal compute/render, MPS, OpenCL, OpenGL, hardware H.264
encoding and decoding, HEVC decoding, and pixel comparisons. Recovery/reset
counters stayed at zero and WindowServer's PID stayed unchanged during each
suite. The later Sonoma shutdown failure is recorded separately above.

AMFI remained enabled. Standalone loaded neither AMFIPass nor a beta argument.
Runtime boot arguments matched configuration and NVRAM; there was no runtime
mutation. The WEX, graphics bundles, Lilu, and kernel collections were unchanged.

### Runtime NULL-path observations

Sequoia standalone recognised the native NULL no-op and counted 659 NULL calls,
all handled without entering the native trampoline. With AMFIPass installed
after AMFIAnchor, the latter received no NULL calls: AMFIPass's Darwin 24-or-later
NULL guard intercepts them first.

Tahoe did not match the recognised entry prefix. Its NULL test begins 21 bytes
into the function, beyond the stack prologue copied for routing. Standalone
counted 675 NULL calls, all forwarded normally, and passed the same controls.
The implementation therefore follows loaded instructions rather than assuming
that every kernel at or above Darwin 24 requires the Sequoia workaround.

Raw host evidence and deployed CA material remain outside this repository.
These results cover the stated hardware, builds, and configurations, not every
third-party hook, OCLP patch set, or future OS update.

## Historical initial source validation: version 0.1.0

On 2026-11-15, the initial source refactor passed both standalone and stock
AMFIPass signing/GPU controls on Tahoe 25G332 with the same hardware, Lilu 1.7.2,
and two independently signed injectors. It used UUID
`AD1E1A18-250D-3924-9B4A-93B3FDDCE8FA` and binary SHA-256
`11796e25fe14e6bf1361cb478e8499a02e6d82251600f7d280cf2a27bd90e6d4`.
That record qualified the initial Tahoe artifact, not later source revisions.
