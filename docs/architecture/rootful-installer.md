# Rootful installer manager (P007)

P007 adds a project-owned package and management entrypoint for the v0.1.0 rootful layout. It installs the CLI, daemon, `iu` symlink, manager helper, path contract, passive plist template, and disabled schema-v1 state. It does not activate execution, register a LaunchDaemon, invoke `launchctl`, prepare a user binary, or change Amethyst state.

## Package and manager

Build the distributable on macOS after the Apple ARM64 artifacts are available:

```sh
make package-rootful
```

The build requires the Xcode iPhoneOS SDK, `file`, `otool`, `codesign`, and the Rust `aarch64-apple-ios` target. It fails when those tools or the actual iOS artifacts are missing. It never substitutes a Linux or macOS executable. The output is a deterministic `.tar.gz` and a matching expanded package directory under `dist/`; see [package format](package-format.md).

The package manager accepts the expanded package directory containing `package-manifest`, `SHA256SUMS`, and `payload/`. The archive is not extracted by the privileged manager. Inspect and extract the distribution on a trusted host before transferring the expanded directory to the device.

```sh
manager.sh help
manager.sh version
manager.sh plan --package /path/to/ios-unsandboxed-0.1.0-rootful-arm64
manager.sh install --package /path/to/ios-unsandboxed-0.1.0-rootful-arm64
manager.sh install --package /path/to/ios-unsandboxed-0.1.0-rootful-arm64 --apply
manager.sh status
manager.sh upgrade --package /path/to/new-rootful-package --apply
manager.sh rollback --apply
manager.sh uninstall
manager.sh uninstall --apply
manager.sh recover --apply
```

`install`, `upgrade`, `rollback`, `uninstall`, and `recover` are read-only unless `--apply` is present. Install and upgrade require `--package DIR`. The `plan` command validates the package and current manifest, then reports whether it would install or upgrade. `status` verifies the manager manifest and disabled state; it does not infer that a daemon process or launchd job is running from files on disk.

Production mutation requires effective UID 0, an identifiable `iPad4,4` (A1489), iOS 12.5.7, the expected rootful Procursus paths, `root:wheel` ownership, and safe non-group/world-writable parent directories. A package's payload paths, file types, modes, SHA-256 values, and Mach-O ARM64/iOS 12.0 headers are checked before staging. There is no force option. If the device cannot be identified or a destination is occupied by a foreign file, mutation fails.

### Host fixture mode

Host tests use an explicit existing filesystem root. The root must be absolute, privately writable by the calling user, not a symlink, and not `/`. The fixture must provide the system parent directories; the manager creates only project-owned directories under `var/lib` after validation.

```sh
IU_FIXTURE=$(mktemp -d)
chmod 0700 "$IU_FIXTURE"
mkdir -p "$IU_FIXTURE/usr/local/bin" "$IU_FIXTURE/var/lib" "$IU_FIXTURE/var/log"
chmod 0755 "$IU_FIXTURE/usr" "$IU_FIXTURE/usr/local" "$IU_FIXTURE/usr/local/bin"
chmod 0755 "$IU_FIXTURE/var" "$IU_FIXTURE/var/lib" "$IU_FIXTURE/var/log"
manager.sh plan --package ./package --test-root "$IU_FIXTURE"
manager.sh install --package ./package --test-root "$IU_FIXTURE" --apply
manager.sh status --test-root "$IU_FIXTURE"
```

Fixture ownership is simulated with the host process UID/GID. Fixture success is not device installation evidence. The fixture mode never invokes `launchctl` and does not redirect production paths through environment variables.

## Owned layout

The manager owns these installed files only:

| Destination | Type and mode |
| --- | --- |
| `/usr/local/bin/ios-unsandboxed` | Regular executable, `0755` |
| `/usr/local/bin/iu` | Symlink to the CLI |
| `/usr/local/bin/ios-unsandboxedd` | Regular executable, `0755` |
| `/var/lib/ios-unsandboxed/manager.sh` | Manager entrypoint, `0700` |
| `/var/lib/ios-unsandboxed/installer-helper` | C17 filesystem helper, `0700` |
| `/var/lib/ios-unsandboxed/paths.env` | Path contract, `0600` |
| `/var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive` | Passive plist copy, `0600` |
| `/var/lib/ios-unsandboxed/install-state` | Exact schema-v1 disabled record, `0600` |

The separate `install-manifest` records schema, project version, package generation, backup generation, signing status, and each file's fixed path, type, mode, owner, group, and SHA-256. Its parser accepts only the known project paths and bounded schema v1. It does not source or evaluate fields. The `backups/` and `staging/` directories are private mode `0700` subdirectories. `/var/lib/.ios-unsandboxed-installer.lock` is a persistent root-owned advisory-lock file so a process crash releases the lock without leaving a stale lock directory.

P007 does not create native hooks, a runtime socket, or log files. The plist stays under the private project data directory; its canonical active destination remains `/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist` for a later lifecycle component. The plist has `RunAtLoad=true`, so P007 never copies it to that active destination or starts it.

## Signing and evidence

Package metadata records one of `unsigned`, `adhoc_signed`, `signed_unverified`, `signature_verification_passed`, or `unknown`, plus the result of local signature verification. The builder does not run `codesign`, `ldid`, or a jailbreak bypass to change signing state. An unsigned or ad-hoc package is not evidence of iOS startup or AMFI/Amethyst acceptance. SHA-256 records detect payload mismatch against the manifest; P007 has no package-signing key and therefore does not claim package provenance authentication.

All physical-device installer, filesystem, ownership, trust, SSH recovery, launchd, upgrade, rollback, reboot, and Amethyst gates remain **NOT RUN** until evidence is collected on the reference iPad. Host fixtures and Apple cross-compilation do not change those results.
