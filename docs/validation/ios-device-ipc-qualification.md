# iOS device IPC qualification (P006)

This qualification separates evidence from the reference rootful iPad mini 2 Wi-Fi A1489 (expected product identifier `iPad4,4`, Apple A7 ARM64, iOS 12.5.7) from source review, host fixtures, and Apple ARM64 cross-compilation. Expected values in this document are not observations. Each real-device result must include the observed device, OS/build, command, exit status, sanitized output, timestamp, evidence source, and limitations.

The P006 harness defaults to read-only inventory. It does not install or alter files, run production `--serve`, change SSH, execute Amethyst operations, modify sandbox labels or kernel memory, or activate execution. Its optional IPC mode requires an explicit option and explicit binary paths, creates one mode-0700 temporary directory under `/tmp`, uses only `--test-socket`, and removes only that directory and its contents. Keep a second unrelated SSH session open during the optional runtime check and verify it after daemon shutdown.

For command details and host fixture scope, see [`tests/device/README.md`](../../tests/device/README.md).

Do not infer device behavior from Amethyst source, Linux `SO_PEERCRED` fixtures, or an Apple cross-build. Do not confuse a displayed/ad-hoc signature, cryptographic signature validity, Amethyst trust, sandbox state, and successful program startup. If startup is rejected or the process is killed, record the exact command, exit/signal, output, binary hash, architecture, and signing facts. Do not attribute a kill to AMFI without evidence. Do not sign or add a trust entry as part of this qualification.

## 1. Build and stage diagnostic binaries

On a supported macOS/Xcode host, run `make build-ios`. The CLI output is `target/aarch64-apple-ios/release/ios-unsandboxed`; the daemon output is `build/ios/ios-unsandboxedd`. CI inspects the Mach-O headers, deployment/load commands, dynamic dependencies, hashes, and signing metadata. Review that output separately from device startup evidence.

Transfer the two outputs over the existing SSH route to a unique temporary directory, for example `/tmp/ios-unsandboxed-p006-run`. Do not put them in `/usr/local/bin`, `/usr/local/lib`, `/var/lib`, `/Library/LaunchDaemons`, or another production location. Verify both file hashes after transfer when a SHA-256 tool is present. Do not run or source any Amethyst package script.

## 2. Read-only inventory

From an existing SSH session, run:

```sh
sh tests/device/ios-runtime-qualification.sh
```

The script records the device clock, kernel name/release/build/architecture, effective UID/GID, root UID, wheel GID, available hardware and OS identifiers, and whether selected environment variables are set. It omits environment values and does not read password, SSH-key, token, or general process-list data. It reports missing utilities, inspects the expected rootful paths and Amethyst candidates with type/owner/group/mode/size/link metadata, and hashes regular Amethyst candidate files when `shasum`, `sha256sum`, or `openssl` is available.

When present, `file` classifies candidate binaries; `otool` reports Mach-O headers, dependencies, and load commands; and `codesign` displays signature metadata and local validation output. Tool output is evidence about the file only. A signature display or local validation does not prove device trust or startup. Package inspection queries only the audited source package identifier `com.staturnz.tnsv2-updater` and ownership of the two component paths; a matching package name/version is not a binary hash comparison.

The script reports `REFERENCE_DEVICE_AND_OS_MATCH` only from observed identifiers. `iPad4,4`, `arm64`, and `12.5.7` are the expected profile; record `kern.osversion` as a separate build fact. Missing commands or identifiers are explicitly unavailable, never filled from the expected values.

`--root DIR` is reserved for host fixture testing. It reports `HOST FIXTURE ONLY`, redirects path inspection below that directory, and cannot be combined with runtime testing. Fixture output is not device evidence.

## 3. Explicit temporary IPC runtime test

Only use binaries you explicitly staged at temporary paths. From each existing SSH identity that is available and permitted, run the harness in that identity's session, first as the ordinary user and separately as root only if root SSH/sudo access already exists:

```sh
sh tests/device/ios-runtime-qualification.sh \
  --runtime-test \
  --cli /tmp/ios-unsandboxed-p006-run/ios-unsandboxed \
  --daemon /tmp/ios-unsandboxed-p006-run/ios-unsandboxedd
```

The script runs only `--version`, `--probe`, the test daemon at its private socket, `--test-socket … check`, `--test-socket … status`, and SIGTERM. It records each command, exit status/output, binary SHA-256, available Mach-O/signature facts, socket metadata, and peer UID/GID. The `check` operation covers PING, unchanged GET_STATUS, GET_PREFLIGHT, and GET_LIFECYCLE_STATUS. On iOS the credentials reported by this endpoint are the daemon's `getpeereid(2)` result. The harness compares them with `id -u`/`id -g` for the current session.

A blocked preflight exit can still be a normal program start if its diagnostic banner is present. Missing components, `UNVERIFIED` Amethyst provenance, or unsupported host-specific conditions remain their reported preflight state and do not turn activation on. If `--version` or the preflight banner is absent, preserve the exact exit/signal and output; do not classify its cause automatically. The harness never runs a management request, supplies a state path, or touches `/var/run/ios-unsandboxedd.sock`.

After SIGTERM, record that the daemon exited cleanly and removed the socket, and confirm the private directory was removed. The script cannot prove SSH continuity. Keep the independent session open, issue a harmless command through it, and verify a new SSH command/login after shutdown. If either fails, stop and use the existing independent SSH recovery route; do not replace or reconfigure SSH.

Repeat the private-socket test for every already available SSH identity. A successful root request does not prove non-root peer credentials, and a successful non-root test does not grant access to the production socket.

## 4. Production rootful layout and socket

The harness inventories these established rootful paths without creating or repairing any of them:

```text
/usr/local/bin/ios-unsandboxed
/usr/local/bin/ios-unsandboxedd
/usr/local/bin/iu
/var/lib/ios-unsandboxed/
/var/lib/ios-unsandboxed/install-state
/var/lib/ios-unsandboxed/manager.sh
/usr/local/lib/ios-unsandboxed/
/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist
/var/run/ios-unsandboxedd.sock
/var/log/ios-unsandboxed/
```

It also reports numeric root/wheel assumptions when `id` can resolve them. The P005 state reader expects the data directory as UID/GID 0 mode `0700` and the state file as UID/GID 0 mode `0600`; do not create or fix those paths during qualification.

The intended production socket remains owner-only mode `0600`. This supports an already root-capable SSH session and intentionally denies ordinary non-root pathname access. Do not loosen it. Inspect an existing production socket and `/var/run` ownership/mode read-only; do not remove an ambiguous socket. P006's initial runtime matrix does not start `--serve` or create the production socket.

## 5. Amethyst source and installed provenance

The audited upstream source revision is `61ce86d7d3f00e5395f4d42bebda0e5dce04946a`. Its `basebins/launchd_hook/Makefile` builds `launchd_hook.dylib`; `basebins/base_hook/Makefile` builds `base_hook.dylib`. Both target iOS 12+, include arm64 (and arm64e), build dynamic libraries, strip symbols, and invoke `ldid -S`. `basebins/Makefile` stages the candidates at `amethyst/launchd_hook.dylib` and `usr/lib/base_hook.dylib`. The source package control file identifies package `com.staturnz.tnsv2-updater`, version `1.1`, architecture `iphoneos-arm`.

These source/build facts explain the candidate paths and a possible installed package record. They do not establish that either file on a device was built from this revision. The installed files' SHA-256 values, Mach-O slices/load commands, code-signing metadata, package record, and live injection status must be observed independently. A package version or `.version` marker is not proof of either component's source SHA. If installed-build identity or live-hook state cannot be proved, report Amethyst compatibility as `UNVERIFIED`.

Source references: [launchd_hook build](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/launchd_hook/Makefile), [base_hook build](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/base_hook/Makefile), [component staging and package metadata](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/Makefile).

## 6. Preflight and LaunchDaemon interpretation

The existing preflight distinguishes known unsupported platform/device, OS version mismatch, missing/unusable required component, and `UNVERIFIED`. Source review confirms the detector does not establish installed build provenance or live hook injection and therefore does not promote observations to `SUPPORTED_AND_VERIFIED`. Host tests can validate these decision rules only; the device's `--probe` and GET_PREFLIGHT outputs remain device evidence.

The passive P005 plist specifies `/usr/local/bin/ios-unsandboxedd --serve`, `root:wheel`, `RunAtLoad=true`, `KeepAlive=false`, and log paths under `/var/log/ios-unsandboxed`. Host plist parsing checks syntax/fields only. On the device, inventory the installed plist, referenced executable, directories, and logs; use `plutil -lint` or a specific read-only `launchctl list com.ios-unsandboxed.daemon` query only when available. Do not load, bootstrap, kickstart, or activate the job. Device acceptance of the plist and startup/shutdown remain NOT RUN until launchd itself is observed without loading the project job.

## 7. Evidence and result recording

Record device gates in [P006_DEVICE_RESULTS.md](P006_DEVICE_RESULTS.md). Use only `PASS`, `FAIL`, `BLOCKED`, or `NOT RUN`. A command that could not run is `NOT RUN` or `BLOCKED`, not `PASS`; record an exit status only when the command ran. Keep separate sections for host tests, iOS cross-compilation, and physical-device runtime results. Never replace a device gate with a Linux fixture or cross-build.

The initial P006 run has no reference iPad session available. All physical-device gates therefore remain `NOT RUN`, with the missing device session recorded as the blocker. Do not claim full device qualification until actual records are reviewed and the per-gate evidence fields are complete.
