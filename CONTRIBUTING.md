# Contributing

Read [the coding standard](Docs/CodingStyle.md) and [the design](Docs/Design.md)
before changing the trust path. Explain the behavior and its validation in a change
description. Keep changes focused and preserve native validation.

```sh
python3 tools/check_style.py
python3 -m unittest discover -s tests -v
python3 tools/build.py --lilu /path/to/Lilu/Lilu --sdk /path/to/MacKernelSDK
```

Use clang-format 17 for C++ formatting. `python3 tools/check_style.py --fix`
formats C++ in place. Review comments and names manually as well.

Treat provider class names, property names, and schema interpretation as public
API. Preserve existing injectors across compatible engine updates; describe an
explicit migration when a compatibility break is necessary.

Kernel changes require live validation appropriate to the changed path. A build
alone is not a runtime qualification. Keep host access details, raw machine logs,
private signing material, and generated payloads outside this repository.
