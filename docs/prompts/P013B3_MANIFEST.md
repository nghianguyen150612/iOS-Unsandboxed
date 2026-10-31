# P013B-3 implementation manifest

## Goal

Implement durable transaction journaling, strict recovery, fail-closed Rust trust reading, and package lifecycle protection for P013B trust-store mutations.

## Boundaries

- Preserve the canonical store path and P007 installer lock.
- Keep install from enrolling keys; preserve trust data during upgrade and rollback; retain it at uninstall for review.
- Do not install a new LaunchDaemon or alter P005 activation state.
- Keep operational authorization false and execution disabled.
- Do not implement P013C launch binding or runtime authorization.

## Acceptance evidence

- Strict bounded v1 journal codec with canonical field ordering and digest/generation validation.
- Persistent `generation.v1` generation/digest marker, without claims of an external monotonic anchor.
- Stage and journal are durable before the final rename; actual bytes decide recovery.
- Pre-rename recovery completes only a fully matching transaction; post-rename recovery verifies and finalizes without replay.
- Revocation and rotation are atomic store generations and cannot be silently reversed by package rollback or stale stage data.
- Rust production reader rejects a pending or unsafe transaction without mutating it.
- Isolated interruption, corruption, lifecycle, idempotency, and shared-lock fixtures run in Linux CI; sanitizer checks run when supported.
- Apple ARM64 package and artifact inspections report separately; device validation is never inferred from CI.

## Limits

Filesystem-only generations detect local inconsistency but do not resist a privileged attacker who replaces all local trust history. `ROLLBACK_PROTECTION_UNVERIFIED` remains visible until a separately designed external monotonic anchor exists.
