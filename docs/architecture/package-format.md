# Rootful package format (P007)

`scripts/build-rootful-package.sh` assembles a versioned package directory and deterministic USTAR/GZip archive. It only accepts the real Apple ARM64 iOS CLI, daemon, and installer-helper artifacts. The builder requires macOS inspection tools and the generated outputs; it does not fetch a toolchain or substitute host executables.

```text
ios-unsandboxed-0.1.0-rootful-arm64/
├── package-manifest
├── SHA256SUMS
└── payload/
    ├── bin/
    │   ├── ios-unsandboxed
    │   └── ios-unsandboxedd
    └── share/
        ├── manager.sh
        ├── installer-helper
        ├── paths.env
        ├── install-state.example
        └── com.ios-unsandboxed.daemon.plist
```

The archive includes normalized order, owner/group fields, file modes, and timestamps. `SHA256SUMS` records SHA-256 hashes for the package manifest and every payload file. The manifest has schema v1, project version, platform, architecture, minimum iOS target, signing status, signature-verification status, and ordered records in this bounded format:

```text
ios-unsandboxed-package
schema_version=1
project_version=0.1.0
platform=ios
architecture=arm64
minimum_ios=12.0
signing_status=unsigned
signature_verification=not_applicable
artifact_signing=payload/bin/ios-unsandboxed|unsigned|not_applicable
artifact_signing=payload/bin/ios-unsandboxedd|unsigned|not_applicable
artifact_signing=payload/share/installer-helper|unsigned|not_applicable
file=payload/bin/ios-unsandboxed|regular|0755|<64 lowercase hex digits>
```

The per-artifact signing records distinguish the CLI, daemon, and installer helper; package-level fields summarize them. The remaining file records are fixed by the package contract and order. Duplicate, unknown, absolute, or traversal paths are rejected. The installer accepts an expanded directory only; it does not process or extract untrusted archive entries. The builder validates plist syntax and fields with `plistlib`. It inspects the architecture, deployment target, and linked dependencies with `file` and `otool`.

The iOS dependency allowlist is limited to `/usr/lib/libSystem.B.dylib` and Apple's `/usr/lib/libiconv.2.dylib` from the iPhoneOS SDK. Any other linked runtime library fails package assembly.

## Signing fields

The builder records each Mach-O artifact without changing it:

| `signing_status` | Meaning |
| --- | --- |
| `unsigned` | `codesign` reports no code signature |
| `adhoc_signed` | Ad-hoc signature metadata is present; verification result is separate |
| `signed_unverified` | A signature is present but strict local verification did not pass |
| `signature_verification_passed` | A non-ad-hoc signature passed local strict host verification |
| `unknown` | Available metadata did not support a reliable classification |

`signature_verification` is `passed`, `failed`, `not_applicable`, `unknown`, or `mixed`. Neither field establishes trust by iOS, AMFI, Amethyst, Procursus, or successful startup. P007 never invokes a signing tool to alter the build.

SHA-256 records establish payload consistency with the included manifest. The package is not cryptographically signed and the hashes do not authenticate who produced it: an attacker able to replace both payloads and metadata can recompute them. Use a trusted release source and transfer path. No arbitrary package hook is supported or run.

## Assembly and checks

```sh
make package-rootful
python3 tests/packaging/rootful-package-test.py dist/ios-unsandboxed-0.1.0-rootful-arm64
```

The macOS CI job cross-compiles all three ARM64 iOS artifacts, inspects Mach-O headers, dependencies and signing metadata, assembles the package, verifies its hashes, builds it twice in isolated output directories for reproducibility, and uploads the directory and archive as a workflow artifact. Package creation and CI do not prove installation or process startup on the reference iPad.

The P012 native provenance and launch-binding objects are statically linked into the existing CLI; no packaged executable, daemon job, installation manifest entry, or IPC operation is added.
