# P013B-2 trust mutations

The installer helper provides read-only trust status/list/plan and explicit add-key, revoke-key and rotate-key mutations. Both apply and confirm flags are necessary for persistence. Production uses the existing installation, platform and shared installer-lock gates; fixtures use isolated roots in test-only builds.

The public-key file is exactly 64 lowercase hex digits plus LF. The codec checks encoding and derived ID, not Ed25519 curve-point usability. Enrollment is deliberate local policy, not independent build-origin evidence. Publisher scope must match for rotation. Repeated revocation is an explicit no-op. Generation starts at one and increments once per successful change; overflow is rejected.

New bytes are written to a unique exclusive temporary file, fsynced, and installed with same-directory rename after rechecking the original destination identity and bytes. Post-rename bytes are reread and compared. Unknown temporary files are preserved. Readers see complete old or new files. A post-rename sync/verification failure reports that rename committed. Crash reconciliation, recovery journals and adversarial rollback protection remain deferred to P013B-3. Operational authorization remains false.
