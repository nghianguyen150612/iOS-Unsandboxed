# P008 service lifecycle validation

**Implementation status:** offline source and host-fixture work only. **Device validation: NOT RUN.** No physical iPad evidence is claimed.

| Gate | Result | Evidence boundary |
| --- | --- | --- |
| P007 main baseline and ancestry | PASS | Baseline commit `159a6c76c4675ec62854c4283356584e3ac3450a`; P007 is ancestor. |
| Device identifier agreement | PASS (source) | Installer, preflight, and qualification harness use `iPad4,4`; this does not identify an attached device. |
| Host service lifecycle mock | PASS | `tests/service/service-lifecycle-test.py` passed with non-root fixture UID 1000 and explicit mock; no real host launchctl. |
| Ordinary install/upgrade remains passive | PASS | Host manager fixture checked active plist absence and no launchctl mock call after install; upgrade remains passive and is blocked while active. |
| P007 installer transaction fixtures | PASS | `tests/packaging/installer-integration.py` passed with simulated fixture ownership. |
| Native, plist, and device-harness host fixtures | PASS | `make native-test`, `make packaging-test`, and `make device-harness-test` passed. |
| Apple ARM64/iOS 12.0 helper build | NOT RUN locally | This workspace is Linux and has no Xcode iPhoneOS SDK; the macOS CI result is still required. |
| Package integrity/reproducibility | NOT RUN locally | Requires actual Apple ARM64 artifacts and macOS packaging tools; the macOS CI result is still required. |
| iOS 12.5.7 launchctl command acceptance | NOT RUN | Physical-device gate. |
| Active plist, RunAtLoad and daemon startup | NOT RUN | Physical-device gate. |
| Root:wheel, Procursus, socket/log and signing behavior | NOT RUN | Physical-device gate. |
| SSH continuity, stop/removal/rollback and Amethyst interoperability | NOT RUN | Physical-device gate. |

The remaining device checklist also includes passive-to-active plist behavior, `RunAtLoad`, `/bin/launchctl` command acceptance, actual ARM64 executable startup, Darwin `getpeereid`, `/var/run` and log behavior, Procursus paths and `root:wheel` ownership, daemon stop/restart/removal, rollback and reboot, SSH continuity, and Amethyst coexistence. Each stays **NOT RUN** until recorded from the reference iPad.

The host mock cannot establish device startup eligibility, code signing or AMFI trust, Darwin `getpeereid`, Amethyst interoperability, or transparent unsigned Mach-O execution. The latter is outside P008 scope.
