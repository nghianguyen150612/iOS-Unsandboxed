# Device qualification tools

`ios-runtime-qualification.sh` is a POSIX `sh` inventory for the supported rootful iPad profile. It runs read-only by default and reports missing utilities instead of assuming Procursus includes them. It records selected machine, OS, kernel, effective identity, environment-presence, filesystem, Amethyst component, package, plist, and launchd facts. It omits environment values and unrelated package/process data.

Run the inventory on the device with:

```sh
sh tests/device/ios-runtime-qualification.sh
```

`--root DIR` redirects filesystem probes below an isolated fixture root. It is for the host fixture test only; it does not query host package/launchd state and does not provide device evidence.

The opt-in runtime mode requires both explicit staged binary paths:

```sh
sh tests/device/ios-runtime-qualification.sh \
  --runtime-test \
  --cli /tmp/ios-unsandboxed-p006-run/ios-unsandboxed \
  --daemon /tmp/ios-unsandboxed-p006-run/ios-unsandboxedd
```

It uses a new `/tmp/ios-unsandboxed-p006.*` directory, a private `--test-socket`, read-only status requests, and SIGTERM. It never starts production `--serve`, writes install-state, changes socket permissions, or calls management operations. It removes only its own test directory; an unexpected leftover prevents directory removal and is reported. SSH continuity and root/non-root coverage must be verified manually from existing sessions.

`inspect-ios-build.sh IOS_CLI IOS_DAEMON` runs on the macOS CI runner after `make build-ios`. It records hashes, Mach-O architecture/type, iOS 12 deployment commands, dynamic dependencies, and code-signing display/validation. It does not sign or deploy. Host signature validity, an ad-hoc signature, Amethyst trust, sandbox state, and successful device startup remain distinct.

`host-fixture-test.py` checks shell syntax and read-only path reporting against a temporary fixture tree. It does not emulate Darwin sockets or device behavior and ordinary CI does not require an iPad.
