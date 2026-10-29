# P013C implementation manifest

P013C composes P010 descriptor identity, P011 policy scope, P012 C17 descriptor preview and revalidation, P013 RustCrypto Ed25519 verification, and P013B trust transaction/generation checks in a read-only v2 authenticated preview. The command is `iu provenance plan MANIFEST ARTIFACT`.

The production provider opens the artifact once with no-follow flags, binds Rust and C17 observations to that descriptor, parses the canonical manifest, loads the production trust store through hardened descriptor traversal, checks revocation and generation/digest state, verifies Ed25519 internally, and revalidates artifact, manifest, trust snapshot, and P011/P012 policy state. C summary ABI v2 is pointer-free and 3376 bytes. P012 ABI v1 remains unchanged.

Publisher authentication does not establish source/build origin or override protected-origin policy. Build origin is `ORIGIN_UNVERIFIED`, protected origin is `UNKNOWN`, runtime is `UNVERIFIED`, the launch boundary is `NOT IMPLEMENTED`, execution activation is disabled, and operational authorization is always false. The operation creates no authorization token and does not contact the daemon.

See `docs/architecture/provenance-launch-integration.md`, `docs/architecture/authenticated-binding-v2.md`, and `docs/validation/P013C_INTEGRATION_GATES.md`. Overall P013 remains partial pending an independent provenance/protected-origin provider. Physical-device validation remains NOT RUN.
