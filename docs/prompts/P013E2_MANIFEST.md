# P013E-2 Work Manifest

**Mission:** Extend the P006 read-only device qualification workflow, implement and test missing offline/artifact/runtime evidence tooling, and collect physical iPad evidence only through an authorized SSH session with explicit temporary staging/runtime approval.

**Baseline:** Branch `feat/p013-authenticated-provenance`; starting HEAD `3371d714876cba5c5ad7d8a5724942e46375df5f`; existing Draft PR #13. Preserve P013A–P013E-1; do not merge and do not start P014.

**Implementation:** Reuse the P006 shell harness; add a versioned JSON wrapper, offline Actions-artifact inspection, ARM64 Mach-O/dependency/signature/linkage checks, secret redaction, safe runtime path/hash guards, bounded diagnostics, private-IPC gating, and deterministic host fixtures.

**Artifact evidence:** Actions run `41201769177` completed successfully on the expected starting SHA. The uploaded artifact was retrieved and inspected. Package integrity, manifest hashes, deterministic tar structure, ARM64/iOS 12.0 metadata, and production test-hook checks passed. The binaries are unsigned; Amethyst trust and device loader acceptance remain unverified.

**Physical device:** NOT RUN. No authorized SSH target/session was supplied and no separate temporary-runtime approval was available. Expected profile values are not reported as observations. No device files, services, trust state, jailbreak configuration, or kernel state were changed.

**Host fixture boundary:** Host tests validate harness logic only. They are never evidence of physical iPad behavior.
