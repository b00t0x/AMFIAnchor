# Validation

The initial source refactor separates the anchor registry, CoreTrust routing,
and IOKit lifecycle. It changes the former private prototype's class and bundle
names to AMFIAnchor and replaces timed diagnostic sampling with on-demand
IORegistry snapshots. Trust policy and anchor matching remain the same.

## Local checks

- clang-format 17 and repository whitespace/SPDX/Python syntax checks.
- Injector tests: PEM/DER equivalence, independent matching categories, public
  key extraction, non-CA and private-key rejection, invalid IDs, and preservation
  of an existing output bundle. All keys are temporary test material.
- Release and Debug builds against the dependency revisions in `NOTICES.md`.

## Live acceptance

The final Release candidate passed checks on an Intel Core i7-12700H / Iris Xe
system with macOS 26.7.2 (25G332), Lilu 1.7.2, two independently signed anchor
injectors, and the existing WEX graphics payload on 2026-11-15. Both configurations
used the same binary and unchanged SPKI/SKID bytes.

- Loaded UUID: `AD1E1A18-250D-3924-9B4A-93B3FDDCE8FA`.
- Binary SHA-256: `11796e25fe14e6bf1361cb478e8499a02e6d82251600f7d280cf2a27bd90e6d4`.
- The source hashes in the build manifest match the current implementation.
  Linker metadata can change UUIDs on a rebuild; these identify the actual tested
  artifact, not a promise of byte-for-byte reproducible output.

| Control | Standalone | Stock AMFIPass 1.4.1, manual `-amfipassbeta` |
| --- | --- | --- |
| Two independently signed CA libraries, Library Validation enabled | Accepted | Accepted |
| Apple-signed library | Accepted | Accepted |
| Dortania-signed library | Rejected | Accepted |
| Unregistered CA library | Rejected | Rejected |
| Modified signed libraries and executables | Killed | Killed |
| Registered CA executables | Platform flag set | Platform flag set |
| Unregistered CA executable | Platform flag absent | Platform flag absent |
| GPU/API suite, 10 tests | Passed | Passed |

The test collector matched 92 installed graphics files, loaded kext UUIDs,
WindowServer's Metal-driver mapping, injector file hashes, raw IORegistry anchor
data, personality publishers, and per-anchor match-counter increases. Library
and executable controls ran as the logged-in unprivileged user. Ordinary
executable launch alone was not treated as proof of trusted-anchor acceptance.

GPU checks included Metal compute/render, MPS, OpenCL, hardware H.264 encoding
and decoding, HEVC decoding, and pixel comparisons. Native recovery, GPU recovery,
and GPU reset counters remained zero; WindowServer did not restart during either
test. Boot arguments matched the configuration and NVRAM without runtime mutation.
AMFI remained enabled, and standalone loaded neither AMFIPass nor a beta argument.

Raw host evidence and deployed CA material remain outside this public repository.

Older multi-OS prototype results do not establish support for this source
revision. No general claim of compatibility with all third-party hooks or all
signing hierarchies is made.
