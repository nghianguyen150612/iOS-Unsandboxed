# P013 trust-anchor storage

The production reader looks only at `/var/lib/ios-unsandboxed/trusted-publishers/store.v1`. The containing directory must be owned by uid/gid 0 and mode 0700. The file must be a regular, single-link, non-symlink file owned by uid/gid 0, mode 0600, and at most 16 KiB. Schema versions other than 1, malformed metadata, duplicate IDs, and more than 64 keys deny trust.

The reader traverses from an open root descriptor using `openat` and `O_NOFOLLOW`, retains each directory descriptor, and checks the directory entries again after reading. On iOS it uses the fixed `/private/var` backing path for `/var`; other hosts use `/var`. File identity, ownership, mode, link count, size, and nanosecond timestamps are compared before and after reading. This is a snapshot, not a guarantee that the store cannot change after verification.

The canonical ASCII/LF format is:

```text
ios-unsandboxed-trust-store
schema_version=1
generation=1
key_count=1
key_0=<key-id>|ed25519|<64-lowercase-hex-public-key>|publisher|<publisher-id>|active
```

Records are ordered by contiguous index. Key ID is the first 16 bytes of SHA-256(public key), lowercase hex. `active` and `revoked` are explicit states. The only authority scope implemented is the exact publisher identity in the record. A publisher key cannot establish source/build origin or claim an artifact is non-protected.

This increment does not provide add/revoke/rotation commands or atomic writes. Do not create a production trust file by copying arbitrary key material. Installing an anchor must be an administrator-reviewed trust-policy change. Rotation requires provisioning a separately reviewed key and explicit revocation of the old key; there is no automatic rollover. `generation` provides a version field, not rollback protection: a monotonic external state provider is unavailable, so privileged filesystem rollback is undetectable.
