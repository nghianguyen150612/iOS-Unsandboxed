# Authenticated binding v2 ABI

P013C adds a compact pointer-free C summary and a typed Rust composite preview. It preserves the P012 launch result ABI v1 and P010 plan ABI v1.

## C descriptor summary

`native/include/iu_launch_binding.h` defines `IU_LAUNCH_SUMMARY_ABI_VERSION_V2` (2), `IU_LAUNCH_SUMMARY_V2_SIZE` (3376), and `struct iu_launch_cli_summary_v2`. Its fields are fixed-width status values, device/inode observations, the policy-store digest, bounded path arrays, and an embedded `iu_execution_plan_v1`. It contains no pointers and is an in-process snapshot, not a persistent authorization object.

`iu_launch_binding_preview_fd_summary_v2` takes a borrowed descriptor and requested path. It validates the caller's ABI version and exact structure size, invokes P012 v1's descriptor preview with empty evidence, validates the returned enum and authorization fields, and copies only P011 scope, P003 hypothetical outcome, P012 decision/boundary, and P010 plan fields into v2. It never returns authenticated publisher evidence from the legacy C verifier. It does not close the descriptor. `iu_launch_binding_revalidate_fd_summary_v2` validates v2 fields and delegates to P012 v1 revalidation.

The C structure does not contain Ed25519 status and cannot be forged into cryptographic proof. The trusted in-process Rust entry point owns the composition and derives all cryptographic states from manifest bytes and the hardened production trust reader. The Rust result has `abi_version = 2`; its typed Rust enums are not a second serialized C ABI.

P013D-1 extends the Rust composite provider with an optional typed build-attestation result. `iu provenance attestation verify ATTESTATION ARTIFACT` retains the same opened artifact descriptor through P012/P010 inspection, Rust SHA-256, subject comparison, and final revalidation. DSSE signature verification uses the exact decoded payload bytes and an independent versioned builder provider. No attestation fields or trust booleans are added to the C ABI. The production builder provider is empty, so this integration cannot report build origin verified in production.

## Identity and revalidation contract

The Rust provider opens the artifact once using no-follow flags. P010's new `iu_execution_plan_create_fd_v2` uses that borrowed descriptor for Mach-O parsing and SHA-256, while retaining its secure path walk to obtain canonical path identity and reject replacement. P012 compares the descriptor facts with P010 and performs its normal pathname/policy revalidation. Rust uses `pread`-style `read_at` for its own digest and does not move the file offset. The Rust and C observations must agree on digest and all recorded identity metadata before manifest verification proceeds.

The manifest is separately opened with no-follow semantics, bounded, and checked for stable bytes and metadata. Its artifact digest, size, architecture, and Mach-O file type must equal the opened descriptor identity. The trust store is read from held directory descriptors and is loaded again before return. Store generation, digest, and generation-marker status must still match. Pending transaction evidence and inconsistent anchors have distinct typed failure states; other errors remain unavailable and fail closed.

P012 revalidation distinguishes same object, pathname replacement, object modification, unverified descriptor identity, stale evidence, and stale policy. Rust maps those return values to typed revalidation/failure states and independently rechecks the manifest and artifact. No positive signature result is reused against a changed trust snapshot.

## Authorization invariant

ABI v2 fixes the launch boundary to `NOT_IMPLEMENTED`; both C and Rust reject nonzero operational authorization. P003 remains operationally disabled. A `Current` revalidation means only that the snapshot survived its final checks. It cannot be reused as a bearer token or used to launch a process.

An attestation result does not change that invariant. Protected origin remains `UNKNOWN`, Amethyst runtime remains `UNVERIFIED`, `execution_activation` remains disabled, and operational authorization remains false.
