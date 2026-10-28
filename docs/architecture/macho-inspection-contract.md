# Read-only Mach-O inspection contract

`iu_ame_macho_inspect_v1` reads regular files without mapping them and caps input at 64 MiB. P009's path API opens with no-follow semantics after resolving each absolute path component without symlinks. P010 adds `iu_ame_macho_inspect_fd_v1`, which borrows the caller's already-open descriptor, leaves it open and does not change its offset. Both entry points reuse the same parser and take before/after file identity snapshots. Unsupported, unsafe, unreadable, oversized, and changed files fail without accepting partial data. P010 uses the descriptor entry point and the P009 SHA-256 reader on the same opened object.

The v1 parser currently handles little-endian 64-bit ARM64 thin Mach-O files. It validates the header, `ncmds`, `sizeofcmds`, each load-command size and range, and exactly bounded `LC_CODE_SIGNATURE` offsets. It classifies:

* A structurally bounded CodeDirectory.
* A structurally bounded ad-hoc CodeDirectory (`CS_ADHOC`).
* Malformed/unusable signature structures and invalid SuperBlob indexes.
* Present but empty or out-of-bounds signature data.
* No `LC_CODE_SIGNATURE` command.
* Unsupported architecture/file formats.
* Truncated/corrupt Mach-O headers or load commands.

CodeDirectory inspection checks the fixed header, identifier bounds, hash-slot arithmetic, and hash storage bounds. It does not validate CMS, code-page digests, entitlements, kernel acceptance, or launch behavior. “Parseable” is a structural parser result, not a trusted signature or execution verdict. The parser does not rewrite files, generate signatures, insert load commands, or call `F_ADDSIGS`.

Fixtures cover ARM64 parseable and ad-hoc CodeDirectories, malformed SuperBlob/CodeDirectory data, empty signature data, absent signature commands, non-ARM64 input, invalid load-command size, oversized offsets, duplicate signature commands, and truncated files. Host parser tests are not iOS or Amethyst runtime tests. Structural parseability is not cryptographic validity or execution authorization.
