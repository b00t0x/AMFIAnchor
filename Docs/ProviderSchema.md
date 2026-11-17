# Codeless provider contract, schema 1

Each injector is a codeless kext: only `Contents/Info.plist` is required, with no
`CFBundleExecutable`. Its top-level `CFBundleIdentifier` must be unique, and
`OSBundleLibraries` must depend on `org.b00t0x.AMFIAnchor` version `0.1.0`.

The injector's `IOKitPersonalities` contains a dictionary with these fields:

| Field | Value |
| --- | --- |
| `CFBundleIdentifier` | `org.b00t0x.AMFIAnchor` (the class owner) |
| `IOClass` | `AMFIAnchorProvider` |
| `IOProviderClass` | `IOResources` |
| `IOResourceMatch` | `IOKit` |
| `IOMatchCategory` | A unique category for this provider, usually the injector's bundle ID |
| `AMFIAnchorProviderID` | A stable provider ID, usually the injector's bundle ID |
| `AMFIAnchorConfig` | Configuration dictionary described below |

`AMFIAnchorConfig` contains integer `SchemaVersion = 1` and dictionary `Anchors`.
Each key in `Anchors` is a globally unique anchor ID. Its value is a dictionary:

| Field | Type | Contract |
| --- | --- | --- |
| `Enabled` | Boolean, optional | Defaults to true; false skips the entry |
| `SPKI` | Data | DER SubjectPublicKeyInfo, 64–1024 bytes |
| `SKID` | Data | Subject key identifier, exactly 20 bytes and not all zero |

The public tool accepts a CA certificate and constructs this dictionary. At
runtime the engine receives only public key data: it validates bounds and DER
structure, not the original CA certificate's extensions or self-signature.

## Multiple injectors and registration

Provider and anchor IDs contain 1–63 ASCII letters, digits, periods, underscores,
or hyphens. Each configuration may have at most 64 input entries. The engine
accepts at most **16 anchors across all providers**.

An already registered anchor ID, SPKI, or SKID causes a later entry to be
rejected; no entry replaces an existing one. IOKit matching and dictionary
iteration order are not an override mechanism. Avoid duplicates rather than
relying on a specific winner. Provider IDs identify diagnostics; use distinct
IDs for independently managed injectors.

Unknown schema versions or malformed configuration dictionaries reject the
provider configuration. A valid configuration can still contain rejected or
disabled entries. Registration status 1 means configuration processing completed;
check the accepted and rejected counts to establish the actual result.

Accepted bytes are copied into fixed boot-lifetime storage. Replacing or removing
an injector takes effect on the next boot. Hot removal does not revoke trust,
and the engine cannot be unloaded safely after hooks are installed.

The provider class, property names, and schema-1 interpretation form a public
compatibility contract. Compatible engine updates retain them and the 0.1.0
compatible-version floor so existing injectors can remain unchanged. An
incompatible change needs an explicit schema or provider-ABI migration.

## Diagnostics

```sh
ioreg -r -c AMFIAnchor -l
ioreg -r -c AMFIAnchorProvider -l
```

The engine exposes `Version`, `ProviderSchemaVersion`, `InstallStatus`,
`AnchorCount`, `ProviderCount`, `AnchorReady`, `RejectedAnchors`,
`DisabledAnchors`, and `LoadedAnchors`. Each loaded anchor has its ID, provider,
and SPKI byte count.

`InstallStatus` is 0 pending, 1 installed, 2 preexisting short route, 3 missing
symbol, 4 routing failure, or 5 callback registration failure. Inspect failures
before relying on the kext.

Debug builds add `FlagsCalls`, `LookupCalls`, `NativeNullPolicyNoOp`,
`NullPolicyCalls`, `NullPolicyNativeSkipped`, and per-anchor `FlagsMatches` and
`LookupMatches`. Use signed positive and negative controls to verify coexistence
with other hooks.

Each provider exposes `AnchorRegistrationStatus` (1 processed, 2 invalid),
`RegisteredAnchorCount`, `RejectedAnchorCount`, and `DisabledAnchorCount`, along
with its original configuration. Public key bytes in IORegistry are public
data, not private signing material.
