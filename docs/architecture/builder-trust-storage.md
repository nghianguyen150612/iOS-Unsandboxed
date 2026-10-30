# P013D-2A builder trust storage

P013D-2A adds a read-only production reader for independently scoped builder
signer roots and builder policies. It stores no private keys and creates no
trust directory or file. The production path is
`/var/lib/ios-unsandboxed/builder-trust/`; iOS opens the same location through
its `/private/var` backing path. Publisher trust remains in its separate
P013B store and cannot supply builder keys.

The directory is expected to be root-owned mode `0700`. The only allowed
settled entries are `roots.v1`, `policies.v1`, and optionally `state.v1`; each must be a root-owned regular
file, mode `0600`, with one hard link and a maximum size of 64 KiB. The reader
walks from a held `/` descriptor with `openat`, `O_NOFOLLOW`, and
`O_DIRECTORY`. It checks ownership, modes, link count, file identity and
metadata before and after bounded reads, reopens entries relative to held
descriptors, and revalidates the directory chain. Unsafe entries are rejected;
the reader does not repair them.

Both files are compact canonical JSON. Object keys are sorted by Rust's
canonical `serde_json` map ordering; whitespace, alternate number spelling,
unknown fields and duplicate fields are rejected. Root records are sorted by
`keyId`; policy records are sorted by `policyId`. Arrays containing revisions
are sorted and unique. Digests are SHA-256 over the exact canonical file bytes.

## `roots.v1`

The root object has exactly `schemaVersion`, `generation`, `keyCount`, and
`keys` fields. `schemaVersion` is integer `1`; `generation` is an unsigned
local counter; `keyCount` must equal the array length.
There are at most 32 records. A record has exactly `keyId`, `algorithm`,
`publicKey`, `signerIdentity`, and `state`, with optional
`enrollmentReference` metadata. The only algorithm is `Ed25519`. The public
key is 32 bytes encoded as 64 lowercase hexadecimal characters. `keyId` is
the first 16 bytes of SHA-256(public-key), encoded as 32 lowercase hex
characters. `state` is `active` or `revoked`. Signer identities are exact and
unique. The optional reference is an audit label, not proof of enrollment.

The schema has no `verified` flag, external identity assertion, or implicit
key authority. A key installed by an administrator is deliberately local
trust, not proof that a named CI system controls it.

## Snapshot handling

The provider records each file generation and content digest plus the
directory and file identities used to read them. Root and policy generations
are independent and need not be equal. Before a successful diagnostic result,
the provider reopens both stores from its held root descriptor and compares
the complete snapshot. Any replacement, mutation, parse failure or generation
change invalidates signer and policy authentication. These local generations
are not rollback-resistant against an attacker who can replace the stores.

Missing stores remain missing during inspection. No transaction, enrollment,
revocation, rotation, or recovery writes exist in this increment. Those
lifecycle interfaces are deferred to P013D-2B.

The partial P013D-2B-1 reader detects `transaction.v1` and the fixed stage names and fails closed. A matching `state.v1` binds both stores; a missing marker reports legacy unanchored history. See [transaction metadata](builder-trust-transactions.md).
