# Persistent service state (P005)

Canonical device path: `/var/lib/ios-unsandboxed/install-state`.

P005 introduced a **read-only loader**. P007 adds a narrowly scoped state writer used only by the project rootful installer during an authorized, journaled transaction. There is still no public IPC state mutation operation. Missing state does not prevent diagnostics and never implies that an installation or execution activation is present.

## Schema version 1

The entire file is UTF-8-compatible ASCII with LF line endings and exactly these four lines, including the final LF:

```text
ios-unsandboxed-state
schema_version=1
service_installation=installed
execution_activation=disabled
```

There are no optional keys, comments, secrets, directories, executable paths, Amethyst kernel structures, or user-supplied enable flags. Version 1 accepts only the exact `disabled` activation value. An `enabled` value, unknown key, missing line, extra byte, malformed integer, or truncated write is corrupt and fails closed. A version other than 1 is reported as unsupported and is not migrated automatically.

The `service_installation=installed` line is a root-owned installation marker. It does not prove that launchd loaded the job or that the daemon is running. Amethyst compatibility is re-probed; device acceptance is external evidence and is never loaded from this file. Neither marker is execution authorization.

[`packaging/rootful/install-state.example`](../../packaging/rootful/install-state.example) is a package template. P007 writes the canonical state only after all project files and the ownership manifest have been staged and verified. The writer emits the same four lines shown above, uses a unique same-directory temporary file, restrictive mode, file sync, atomic rename, and parent-directory sync where supported. It preserves the prior record in the verified backup generation and uses the P005 reader to verify the result. It never writes an enabled activation value.

## Ownership and read rules

Production expects the project data directory to be a real `root:wheel` directory (UID/GID 0) with mode `0700`, and the state file to be a regular `root:wheel` file with mode `0600`. The loader opens the project directory with `O_NOFOLLOW`, opens `install-state` relative to that directory with `openat`, `O_NOFOLLOW`, and `O_NONBLOCK`, and checks type, UID, GID, mode, link count, bounded size, and stable descriptor metadata. It rejects multiple links; a descriptor opened just before atomic replacement may report zero links and still represents the complete old snapshot. `O_NONBLOCK` prevents a raced FIFO from hanging status. Symlinks at the project-directory or state-file component, directories, FIFOs, unexpected owner/mode, and I/O failures cannot produce a valid state. The OS may resolve the fixed system `/var` alias while opening parent components; verify on the device that this alias and target are system-owned and not user-writable. The actual `wheel` GID and filesystem behavior still require physical verification.

The loader returns one of these states:

| Value | State | Interpretation |
|---:|---|---|
| 0 | Directory missing | State unavailable; not installed is not inferred. |
| 1 | File missing | No installation record; activation remains disabled. |
| 2 | Valid | Schema 1 is supported; service marker is installed; activation is disabled. |
| 3 | Unsafe | Ownership, type, link, or permission validation failed. |
| 4 | Unsupported schema | No migration or activation inference is attempted. |
| 5 | Corrupt | Contents are malformed, truncated, or contain any non-disabled activation value. |
| 6 | I/O error | State could not be safely read. |

The state result always initializes execution activation to disabled. Unsupported, unsafe, missing, and corrupt files cannot set it. P007's installer writer emits only the literal `disabled`, and direct file manipulation cannot enable execution.

## Installer-only atomic mutation contract (P007)

P007's state mutation is authorized only by the project installer or explicit recovery command. It is not exposed through `ENABLE`, `DISABLE`, `SET_POLICY`, or another public management IPC operation. The manager:

1. Open and validate the real root-owned `0700` data directory by descriptor.
2. Create a unique temporary file in that directory using exclusive creation, no-follow flags, mode `0600`, and the expected owner/group.
3. Write a complete supported schema, set final owner/mode, and `fsync` the file.
4. Atomically `renameat` the temporary file over `install-state`, then `fsync` the directory.
5. Remove only its own temporary files on handled errors. Never unlink the old state before replacement.

Readers open a descriptor and see either the old or new complete file across atomic replacement. P005 fixture tests simulate interruption before rename and concurrent atomic replacement; these tests do not imply that a production writer exists. An orphan temporary file is ignored and is never treated as canonical state.

The daemon continues to use a read-only status loader and has no writer API. `iu enable` and `iu disable` continue to return `NOT_IMPLEMENTED` without changing the state file. An installed service marker remains an installation fact, not execution authorization.
