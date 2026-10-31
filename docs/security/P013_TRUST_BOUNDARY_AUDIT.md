# P013 trust-boundary audit

## Review result

The audit reviewed publisher signature verification, P012/P013C descriptor
binding, DSSE/in-toto/SLSA parsing and verification, builder trust validation,
the C/Rust privileged ABI, package/publisher/builder conflict guards, and the
rootful lifecycle. No critical or high-severity defect was confirmed. One
moderate fail-closed defect in directory enumeration was reproduced and fixed.

## Confirmed finding

### SEC-P013E1-001 — Directory read errors were accepted as end-of-directory

- **Affected components:** Publisher trust artifact scanner, builder trust
  reader and publisher snapshot reader, installer publisher-conflict guard,
  installer staging/backup/temporary cleanup enumeration.
- **Threat and capability:** A filesystem I/O error during `readdir()` could
  truncate a security-sensitive inventory. The trust directories are private
  and root-owned, so this is not an identified unprivileged remote attack path;
  the trigger is a storage/filesystem fault or privileged filesystem condition.
- **Reproduction:** `tests/trust/readdir-error-test.c` injects `EIO` after the
  first directory entry and calls the real publisher `scan_artifacts()`.
  Before the fix, the harness failed at
  `assert(scan_artifacts(root, &mask) != 0)`: the scanner returned success with
  a partial inventory.
- **Observed result before fix:** A null `readdir()` result was treated as
  normal EOF without checking `errno`; the helper accepted the incomplete scan.
- **Expected invariant:** Trust verification, transaction conflict checks, and
  cleanup must not treat an incomplete directory inventory as complete.
- **Severity and impact:** Moderate (P2). It could allow a partially observed
  trust directory to pass an inventory check or permit cleanup/conflict logic
  to proceed after an I/O error. No evidence indicates a direct unprivileged
  exploit under the documented ownership and mode requirements.
- **Fix:** Added `iu_readdir_checked()` for C scans and shared checked
  enumeration for Rust scans. Each scan clears `errno` before `readdir()`,
  distinguishes EOF from an error, and fails closed on enumeration or close
  errors. Cleanup enumeration also aborts on a failed scan.
- **Regression test:** The C fault-injection harness now passes against the
  corrected real scanner. Rust `directory_scan` tests verify that an injected
  `EIO` after a valid entry rejects the partial result and that `errno == 0`
  remains ordinary EOF.
- **Validation evidence:** `make p013-security-test`, strict C17 build,
  `cargo test --locked --workspace`, and full `make test` pass locally. Final
  hosted qualification is tracked by the P013E-1 validation gate.
- **Remaining risk:** The test injects a POSIX-style `readdir()` error; it does
  not emulate disk power loss, filesystem corruption, or iOS-specific storage
  behavior.

## Invariant review matrix

| Area | Review conclusion | Evidence in tree |
| --- | --- | --- |
| C/Rust builder ABI | Version, exact size, reserved word, apply bit, offsets, borrowed strings and panic boundary are checked. C and Rust agree on the 64-byte v1 request. | `iu_builder_trust_manager.h`, `iu_builder_trust_manager.c`, `builder_admin.rs`, `admin-abi-test.c` |
| Privileged gate | Mutating builder operations require root, supported production platform/path checks, verified installation, explicit confirmation and the shared P007 lock. | `iu_installer.c`, `builder_admin.rs`, lifecycle fixtures |
| Store filesystem access | Fixed names, descriptor-relative `openat`, `O_NOFOLLOW`, private owner/mode/link checks, bounded reads/writes and identity revalidation are used. | `builder_admin.rs`, `builder_trust.rs`, persistence fixtures |
| Plans and test hooks | The privileged manager reconstructs proposed stores and transaction metadata; production excludes the test entrypoint and fault flag. | `builder_admin.rs`, `Makefile`, `builder-production-test` |
| Publisher authentication | Key IDs do not provide keys; active trust records scope exact publisher identity, revoked anchors fail, manifest/artifact binding is revalidated. | `authenticated_binding.rs`, `provenance.rs`, trust fixtures |
| DSSE/builder authority | DSSE signature, signer identity, builder identity, policy and build parameters remain separate results; production local builder trust never establishes independent enrollment. | `build_attestation.rs`, `builder_trust.rs`, attestation fixtures |
| Snapshot changes | Trust generation/digest/marker and artifact/manifest snapshots are reread; changed evidence invalidates the corresponding result. | `authenticated_binding.rs`, stale-snapshot tests |
| Execution boundary | Preview output remains blocked; operational authorization is false and execution activation remains disabled. | P012 ABI validation and authenticated-binding tests |
| Lifecycle | Package rollback/uninstall preserve administrator trust; publisher, builder, and package transactions conflict under the shared lock. | `iu_installer.c`, builder lifecycle tests, trust recovery tests |
| Package linkage | Apple ARM64 package qualification inspects Mach-O outputs and the dependency allowlist; host-only tests are not claimed as Apple runtime tests. | CI workflow and package verification |

## Documented limits, not confirmed defects

- Local enrollment does not prove independent publisher or builder identity.
- `generation.v1` and `state.v1` are local consistency markers, not hardware or
  remote rollback protection.
- Signed source revision claims are checked against local policy but do not
  prove that the source tree or workflow produced the artifact.
- Protected-origin classification remains `UNKNOWN`; an incomplete catalog
  cannot justify treating unknown artifacts as known unprotected.
- Directory `fsync` portability and physical iOS durability require device
  qualification; host process interruption is not equivalent to power loss.
- The reviewed service/launch boundary does not activate execution or provide
  an authorization token.

No formal proof or independent external audit is claimed.
