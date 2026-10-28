# Read-only Mach-O inspection contract

`iu_ame_macho_inspect_v1` reads regular files without mapping them and caps input at 64 MiB. It opens with no-follow semantics after resolving each absolute path component without symlinks, takes before/after file identity snapshots, and never changes the binary. Device, inode, owner, mode, link count, size, and parser state are returned for evidence. Unsupported, unsafe, unreadable, oversized, and changed files fail without accepting partial data.

The v1 parser currently handles little-endian 64-bit ARM64 thin Mach-O files. It validates the header, `ncmds`, `sizeofcmds`, each load-command size and range, and exactly bounded `LC_CODE_SIGNATURE` offsets. It classifies:

* A structurally bounded CodeDirectory.
* A structurally bounded ad-hoc CodeDirectory (`CS_ADHOC`).
* Malformed/unusable signature structures and invalid SuperBlob indexes.
* Present but empty or out-of-bounds signature data.
* No `LC_CODE_SIGNATURE` command.
* Unsupported architecture/file formats.
* Truncated/corrupt Mach-O headers or load commands.

CodeDirectory inspection checks the fixed header, identifier bounds, hash-slot arithmetic, and hash storage bounds. It does not validate CMS, code-page digests, entitlements, kernel acceptance, or launch behavior. “Parseable” is a structural parser result, not a trusted signature or execution verdict. The parser does not rewrite files, generate signatures, insert load commands, or call `F_ADDSIGS`.

Fixtures cover ARM64 parseable and ad-hoc CodeDirectories, malformed SuperBlob/CodeDirectory data, empty signature data, absent signature commands, non-ARM64 input, invalid load-command size, oversized offsets, and truncated files. Host parser tests are not iOS or Amethyst runtime tests.
