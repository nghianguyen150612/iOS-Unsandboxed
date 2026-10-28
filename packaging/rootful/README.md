# Rootful package assets

This directory holds the canonical rootful path contract, disabled schema-v1 state example, passive LaunchDaemon template, and the `manager.sh` management entrypoint. The paired `installer-helper` is built from `native/src/iu_installer.c` and is included in the distribution package.

## Build

On macOS with Xcode command line tools, the iPhoneOS SDK, Rust's `aarch64-apple-ios` target, `file`, `otool`, and `codesign`:

```sh
make package-rootful
```

The result is `dist/ios-unsandboxed-0.1.0-rootful-arm64.tar.gz` and its expanded package directory. The builder fails if any iOS artifact is absent or has the wrong architecture, iOS platform, or deployment target. It records SHA-256 and signing metadata without signing or running the binaries. Linux host programs are never packaged as iOS payloads.

## Manager interface

The package's `payload/share/manager.sh` locates the paired helper and supports:

```text
manager.sh help
manager.sh version
manager.sh plan --package DIR
manager.sh status
manager.sh install --package DIR [--apply]
manager.sh upgrade --package DIR [--apply]
manager.sh rollback [--apply]
manager.sh uninstall [--apply]
manager.sh recover [--apply]
```

Commands are read-only unless `--apply` is supplied. The manager accepts a package directory, not a tar archive. The helper validates SHA-256 records, the strict package/ownership schemas, fixed destinations, ownership and modes, and ARM64 iOS Mach-O headers. It uses no post-install scripts or hooks.

Host fixtures select `--test-root ABSOLUTE_PRIVATE_DIRECTORY`; this explicitly redirects only the fixed path table into a private fixture and never invokes launchd. Fixture results are host evidence only. Production writes require root on the reference `iPad4,1`, iOS 12.5.7, with safe rootful `root:wheel` layout checks.

The passive plist remains packaged at `/var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive`. Do not copy it to `/Library/LaunchDaemons` during a normal P007 install: `RunAtLoad=true` could start the job after registration. P007 does not register or start the service.

See [the package format](../../docs/architecture/package-format.md), [manager contract](../../docs/architecture/rootful-installer.md), and [transaction behavior](../../docs/architecture/install-transactions.md).
