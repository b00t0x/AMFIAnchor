# Coding standard

AMFIAnchor follows the common conventions visible in Acidanthera's
[Lilu headers](https://github.com/acidanthera/Lilu/blob/e4748cc081bf060302c7d3c44a643ce1d11b7e1d/Lilu/Headers/kern_patcher.hpp),
[CPUFriend startup](https://github.com/acidanthera/CPUFriend/blob/master/CPUFriend/kern_start.cpp),
and [WhateverGreen interfaces](https://github.com/acidanthera/WhateverGreen/blob/master/WhateverGreen/kern_weg.hpp).
The references were reviewed on 2026-11-15. This is a project-specific standard,
not a claim that every Acidanthera repository has one identical style.

## Formatting and names

- C++14, tabs for indentation, four-column tab width, attached opening braces,
  and a 120-column limit. `.clang-format` is authoritative for mechanical layout.
- Types, scoped enum members, and named constants use `UpperCamelCase`.
  Functions, variables, and members use `lowerCamelCase`.
- Use the `org` prefix for the original function retained by a hook and `wrap`
  for its replacement, as in Acidanthera's routing code.
- Keep `kern_*.hpp` / `kern_*.cpp` pairs and matching include guards. Include
  local interfaces explicitly; do not depend on accidental transitive includes.
- Python tools follow PEP 8 naming and four-space indentation. Use descriptive
  argument names and normal functions, not dense top-level statement chains.

## Additional auditability rules

These rules deliberately make control flow more explicit than some upstream examples.

- Always brace control statements, including one-statement branches and loops.
  One logical statement per line; no compressed condition/action chains.
- Use guard clauses for invalid inputs. Keep validation, copying, publication,
  and error reporting in an order that a reviewer can follow.
- Name limits and state values. Hex offsets are permitted for the private ABI,
  but must have a provenance comment and compile-time layout checks.
- Split by responsibility, not by arbitrary file length. Avoid generic helper
  frameworks, clever templates, or indirection that hides a trust decision.
- Preserve native validation and original hook calls. No unrelated behavior
  changes in a formatting or naming change.
- Prefer explicit types when width, signedness, or pointer provenance matters.
  `auto` is appropriate for an evident cast, allocation, iterator, or reference.

## Comments and contracts

- Public interfaces use Doxygen-style comments. Explain purpose and behavior;
  add `@param` and `@return` when their meaning is not evident from the signature.
- Document borrowed versus owned data, object lifetime, permitted execution
  context, and lock/atomic ordering at the boundary where they matter.
- Explain **why** a bound, policy value, fallback, or publication order exists.
  Do not narrate each assignment or restate a clear identifier.
- Keep CoreTrust ABI observations separate from supported Apple APIs. Explain
  the source of assumptions and the kernel generations actually validated.
- Keep the hook install status and registered anchors visible in Release builds.
  Use Debug builds for hook-call and anchor-match counters.
- Comments and identifiers are English for shared review. Repository prose may
  include translations, but behavior contracts must agree.

## Review and enforcement

Run `python3 tools/check_style.py` before committing. It uses clang-format 17,
checks whitespace and SPDX headers, and checks Python syntax.
CI runs the same formatter and the injector tests. `--fix` applies C++ formatting.

Mechanical formatting does not prove readability. Reviews must also check names,
control-flow clarity, ownership, execution context, and comments against the rules
above. New files and refactors are held to this standard, not just the initial import.
