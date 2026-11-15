# AMFIAnchor development guide

Project knowledge belongs in this repository. Keep this file short; use `Docs/`
for the coding standard, trust model, provider contract, and validation notes.

## Required conventions

- Read and follow [the coding standard](Docs/CodingStyle.md) before changing code.
- Keep trust decisions, input validation, and publication order easy to audit.
  Do not compress control flow or combine unrelated statements on one line.
- Preserve native validation and original hook calls. Do not add blanket AMFI
  bypasses, automatic trust sources, or boot-argument mutation.
- Provider key bytes and certificates must remain valid until reboot. Document
  ownership, locking, and execution context when changing these paths.
- Keep build outputs, dependencies, certificates used in deployment, private
  keys, machine access details, and raw machine logs out of Git.
- Use a public contributor identity in source and Git metadata. Never derive it
  from an OS account or an absolute filesystem path.

## Checks

```sh
python3 tools/check_style.py
python3 -m unittest discover -s tests -v
python3 tools/build.py --lilu /path/to/Lilu/Lilu --sdk /path/to/MacKernelSDK
```

Kernel changes require appropriate live validation in the owning workspace.
Keep target identification, exact loaded artifacts, and a usable predecessor.
Do not add remote access or deployment credentials to this repository.
