# Builder trust and installer lifecycle

All package, publisher-trust and builder-trust persistence uses the persistent
P007 `.ios-unsandboxed-installer.lock` fcntl write lock under the verified var/lib
directory. The lock is acquired nonblocking and held until return or process
exit. A crash releases it without deleting/recreating a lock inode.

`check_no_transaction` now also validates settled builder state.
Package install, upgrade, rollback, uninstall, recovery, policy mutation and
service mutation refuse pending or unsafe builder state. Publisher changes and
publisher recovery also refuse it. Builder changes and builder recovery refuse
package journals or unresolved publisher evidence. Builder recovery handles its
own pending state while retaining the same external conflict guards.

The builder guard calls the in-process canonical validator: it does more than
look for a journal name. It rejects orphan stages, unsafe entries, incomplete
pairs and mismatched/missing markers, including corrupt settled-looking files.
Read-only status/list/inspect/recovery inspection remain available without
writing; unsafe state is diagnosed and returned as a failure.

Installation never creates a builder directory, enrolls keys or invents a
policy. Package manifests/backups/staging contain only package-owned payloads
and disabled install state; builder roots, policies, marker and transaction
history are excluded. Upgrade and rollback retain exact builder bytes and do
not change generations. A committed signer/policy revocation is therefore not
reversed by package rollback or package recovery. Uninstall reports and preserves
builder history. When administrator metadata remains, empty installer bookkeeping
directories are retained so read-only history inspection still works.

Reinstallation into a retained data directory without an install manifest
continues to follow P007's existing refusal-to-adopt rule; this increment does
not bypass it or automatically delete retained trust to permit reinstall.
Builder mutation/recovery still requires a verified installation. Offline
inspection is available after uninstall. No incidental cleanup deletes trust,
no schema v2 migration occurs, and no operation authorizes execution.
