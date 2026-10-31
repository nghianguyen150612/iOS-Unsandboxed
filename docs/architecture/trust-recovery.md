# Trust transaction recovery

Run `manager.sh trust recover` to inspect the observed state. It does not write. A recovery that changes files requires `manager.sh trust recover --apply --confirm`, production root privileges, a verified installed package in the disabled state, and the shared P007 installer lock.

| Observed state | Read-only result | Apply result |
| --- | --- | --- |
| No journal or transaction artifacts | No transaction | No-op |
| Valid journal, original store and matching canonical `stage.v1` | Prepared | Revalidate old bytes, journal, stage digest, generation, and operation transition; rename the verified stage into place |
| Valid journal and current store matches recorded new generation and digest | Committed | Verify the store, update or verify `generation.v1`, and finalize cleanup without replaying the mutation |
| Journal with missing stage before commit | Unresolved | Stop and preserve evidence |
| Stage artifact without a journal | Unjournaled and ambiguous | Stop and preserve evidence |
| Corrupt, unsafe, symlinked, hard-linked, wrong-owner/mode, unknown, or conflicting artifacts | Unsafe/conflicting | Stop and preserve evidence |

`phase=` alone never changes the decision. If current bytes match the recorded new digest, recovery verifies or advances `generation.v1` and finalizes cleanup. If actual current bytes match the old identity and the staged bytes match the new identity, recovery completes the intended operation. All other combinations fail closed. Recovery does not restore old bytes over a newer store, so a committed revocation cannot be undone by a stale journal or staged file.

The fixed helper recognizes `.stage.tmp`, `.transaction.tmp`, `.generation.tmp`, `stage.v1`, `transaction.v1`, and `generation.v1`. It never deletes an unjournaled stage or unknown file. A crash before a journal exists can leave an ambiguous stage; this is intentionally preserved for administrator review rather than inferred as a committed transaction.

Trust recovery and package recovery use the same installer lock and refuse to proceed while the other transaction type is unresolved. Package install, upgrade, rollback, uninstall, policy writes, and service lifecycle mutations also reject a pending or unsafe trust transaction. Uninstall reports and preserves trust metadata for administrator review.
