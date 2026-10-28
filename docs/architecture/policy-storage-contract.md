# Policy storage contract v1

The separate file `/var/lib/ios-unsandboxed/execution-policy` lives in a root:wheel `0700` project directory and must be a single-link root:wheel regular file with exact mode `0600`. Its maximum size is 17,000 bytes. It is not part of the immutable P007 eight-file install manifest. Missing means zero scopes. Unsafe, corrupt, unsupported, or unreadable never means an empty usable policy.

Canonical ASCII records, with LF including the final LF, are ordered exactly:

```text
ios-unsandboxed-execution-policy
schema_version=1
mode=preview-only
scope_count=0
```

For each of up to eight sorted scopes, append `scope_N=HEX|DEVICE|INODE` and LF. N starts at zero; HEX is lowercase hexadecimal encoding of every path byte, DEVICE and INODE are canonical unsigned decimal filesystem identifiers, with nonzero inode. Paths use the restricted canonical ASCII namespace described in [root execution policy](root-execution-policy.md). Duplicates, overlap, reordered records, leading zeros, unsupported schemas, unknown fields, NULs, extra records, truncated records, malformed hex, and every mode other than `preview-only` are rejected. There is no persisted enabled bit, code, token, or secret.

The loader uses the already-validated project directory descriptor and `openat` with no-follow and nonblocking flags. It checks directory and file ownership, mode, type, link count, bounded size, complete read, descriptor identity and timestamps, and final pathname identity. It distinguishes missing, valid, corrupt, unsafe, unsupported and I/O error. Root ownership is an access-control condition, not proof of package or Amethyst provenance.

Under the shared P007 lock, a mutation revalidates installation and policy, rechecks all scopes, writes a unique same-directory `.policy-tmp-*` file with `0600` and expected owner, synchronizes it, rechecks the prior file, renames, synchronizes the directory where supported, and reopens and verifies the result. Before rename an interruption leaves the old record intact; after rename the complete new record is visible. Directory fsync can be unsupported on some filesystems. Unknown temporary files are preserved for manual review. Schema-v1 install manifest semantics remain unchanged.
