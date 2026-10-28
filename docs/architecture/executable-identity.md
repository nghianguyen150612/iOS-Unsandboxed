# Executable identity and revalidation

P010 records what the invoking user inspected. It does not grant permission to execute the file or promise that a later pathname lookup will select that file.

## Descriptor-backed snapshot

`iu_execution_plan_create_v1` rejects empty and overlong paths, `..` components, duplicate/trailing separators, symlinked parent or final components, non-regular files, hard links, and files above P009's 64 MiB inspection bound. Relative `.` components such as `./tool` are normalized into the canonical absolute path. It opens parent directories component by component with `openat` and no-follow behavior, checks the final name with `fstatat(..., AT_SYMLINK_NOFOLLOW)`, then opens the target read-only. The opened descriptor is the common object used by P009's descriptor-based Mach-O parser and SHA-256 reader. Those interfaces borrow the descriptor and leave its offset and ownership with the caller.

The planner compares descriptor metadata before and after parsing and hashing, compares the held descriptor with the still-named directory entry, then resolves the canonical path again from `/` and confirms it still reaches the same descriptor identity. Reopening the full path also detects parent-directory replacement during inspection. A complete snapshot includes canonical path, regular-file type, UID/GID, permission bits, link count, device, inode, size, modification and change timestamps when provided by the host, full 32-byte SHA-256, Mach-O architecture and file type, and signature/parser state. Reads are bounded and partial reads fail.

SHA-256 is a content fingerprint in the record. It does not prove authorship, signature correctness, trust-cache membership, kernel acceptance, or launchability. The planner does not create temporary copies or write to the executable.

## Revalidation and the remaining race

`iu_execution_plan_revalidate_v1` checks the saved ABI and enum values, opens the saved canonical path again with the same path checks, and compares identity metadata and the complete digest. It detects a replaced inode, device, size, content, mode, owner, group, link count, timestamps, parser result, and path no longer naming the same safe file.

This is a second read-only observation. Another process can replace or modify the path after revalidation and before a future `execve` or `posix_spawn`. Holding a descriptor during inspection does not bind a later path-based launch to that vnode. Any future operation needs a reviewed same-object launch boundary that receives or independently opens the requested image and verifies identity immediately before launch. A saved path or hash alone is never sufficient.

## Host coverage and limitations

`make planner-test` uses isolated temporary fixtures and no root or device. It covers symlinks, hard links, directory targets, invalid paths and ABI records, metadata and content changes, replacement inodes, complete-read digest output, synthetic ARM64 and malformed Mach-O data, and unchanged operational authorization. Tests demonstrate finite fixture behavior; they are not an exhaustive proof of parser safety or a race-free launch primitive.
