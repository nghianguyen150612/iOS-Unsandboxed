# P013D-2A builder trust validation gates

P013D-2A is the read-only storage and provider increment. It may parse
administrator-provisioned builder keys and exact policies, but it does not
enroll them or claim an independently authenticated CI identity. Production
therefore keeps `Independent trust establishment: UNVERIFIED` and
`BUILD_ORIGIN_UNVERIFIED`, even when an installed policy matches.

The host suite is `make builder-trust-test`; it checks canonical parsing,
duplicate and oversized inputs, exact root/policy mappings, revoked keys,
filesystem link/mode/symlink controls, snapshot changes, a real Ed25519 DSSE
signature, and read-only CLI diagnostics. The local test key and policy live
only in an isolated temporary directory. They are not copied into production
configuration. The ordinary P013D attestation fixtures continue to exercise
payload mutation, subject binding, unsupported schemas, parameters and source
revisions.

Linux CI runs this target directly and through `make test`. Apple ARM64 CI
cross-compiles the Rust implementation for iOS 12.0 and performs Mach-O,
dependency, package-integrity and reproducibility checks. A cross-compile
does not establish iPad runtime behavior.

No SLSA level, GitHub Actions, Sigstore, Fulcio, external PKI, source identity,
reproducible-build result, or protected-origin classification is inferred.
Publisher signatures remain separate from builder signer trust. The P013B
publisher roots cannot authorize a builder. There are no trust writes,
revocation commands, enrollment, rotation, journals, or crash recovery in
P013D-2A. Local file generations provide no adversarial rollback protection.

Protected origin remains `UNKNOWN`; Amethyst runtime remains `UNVERIFIED`;
launch boundary remains `NOT IMPLEMENTED`; execution activation remains
disabled; operational authorization remains `FALSE`. Device validation is
`NOT RUN`.
