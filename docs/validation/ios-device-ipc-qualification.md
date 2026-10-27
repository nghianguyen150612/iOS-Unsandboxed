# iOS device IPC qualification (P005)

This procedure is for a manually supervised, read-only qualification on the reference rootful iPad mini 2 Wi-Fi A1489 (Apple A7 ARM64, iOS 12.5.7). It does not load a LaunchDaemon, install a manager, alter Amethyst, replace SSH/shell, sign a binary, or activate execution. Keep a second unrelated SSH session open throughout the socket tests.

Do not infer device results from Amethyst source, Linux host tests, or an Apple cross-build. If the candidate Mach-O does not execute because it is unsigned or otherwise rejected, record the exact error and stop. Do not invent or use an unapproved signing/trust-cache process.

## 1. Record the device and installed environment

Build the Rust CLI and C17 daemon for Apple ARM64 on a supported macOS/Xcode host with `make build-ios`. Transfer the outputs to a temporary location over the existing SSH route; do not install them into the canonical project paths for this qualification. Record hashes at both ends if the available tools permit.

From the device, record the unmodified probe output and basic process identity:

```sh
uname -a
id
sysctl -n hw.machine
sysctl -n kern.osversion
/tmp/ios-unsandboxedd --version
/tmp/ios-unsandboxedd --probe
file /tmp/ios-unsandboxed /tmp/ios-unsandboxedd
ls -l /usr/lib/dyld /var /var/run /var/lib /usr/local/bin /usr/local/lib
ls -ld /var/jb /etc/apt /var/lib/dpkg/status
dpkg -l | grep -i -E 'amethyst|procursus'
```

If `file`, `sysctl`, or a listed path is unavailable, record that exact limitation. Record the actual iOS product version and build from `--probe`; expected values in the project brief are not device evidence. Inspect, without changing, the candidate Amethyst paths `/amethyst/launchd_hook.dylib` and `/usr/lib/base_hook.dylib`. Capture owner, group, mode, type, size, and hashes. Separately record the installed package name/version/revision from the on-device package database when available. Do not infer the installed revision from a source checkout or filenames. Check Procursus/rootful indicators and the actual `/var/run` owner/mode. The P005 state loader expects the project directory to be UID/GID 0 mode `0700` and state file UID/GID 0 mode `0600`; do not create or repair these paths for this test.

Record the installed SSH server package/version and active daemon process from the package database and process list when available. Record the effective UID/GID used by each existing SSH client identity. Do not restart, replace, or reconfigure SSH.

If the binary cannot start and reports a loader/signing error, record the exact error and stop the device execution tests. A nonzero `--probe` exit with diagnostic output such as `UNVERIFIED`, missing components, or unsupported platform is a safe preflight result; record it and continue only with the read-only IPC checks. Do not add a signature or trust entry without an explicitly approved conventional process.

## 2. Test a private, isolated socket as the ordinary SSH user

Use an existing non-root SSH identity; do not change sshd settings or create an account. In one session:

```sh
test_dir="$(mktemp -d /tmp/iu-p005-user.XXXXXX)"
chmod 700 "$test_dir"
/tmp/ios-unsandboxedd --test-socket "$test_dir/daemon.sock" \
  >"$test_dir/stdout.log" 2>"$test_dir/stderr.log" &
daemon_pid=$!
sleep 1
ls -l "$test_dir/daemon.sock"
```

From the same UID in that session or a second one, run:

```sh
/tmp/ios-unsandboxed --test-socket "$test_dir/daemon.sock" check
/tmp/ios-unsandboxed --test-socket "$test_dir/daemon.sock" status
```

`check` sends PING, the unchanged P004 GET_STATUS, GET_PREFLIGHT, and the P005 lifecycle request. Record the returned peer UID/GID. They must match the actual invoking effective credentials reported by `id`; on iOS this is native `getpeereid` evidence. Record the socket owner/group/mode. Expected socket mode is `0600`. A missing Amethyst component or state directory is diagnostic output and must not prevent this read-only server from starting or turn activation on.

Stop with SIGTERM and verify cleanup:

```sh
kill -TERM "$daemon_pid"
wait "$daemon_pid"
test ! -e "$test_dir/daemon.sock"
cat "$test_dir/stderr.log"
rm "$test_dir/stdout.log" "$test_dir/stderr.log"
rmdir "$test_dir"
```

Record the daemon exit code and whether only its own socket was removed. Repeat this private-socket test as root only if root SSH/sudo access already exists and is permitted. The returned peer UID/GID must then match root's effective credentials. Do not enable root SSH access to perform the test.

## 3. Check production pathname authorization without launchd

This step is a manual foreground run of the existing read-only `--serve` mode. It does not install or load the plist. First verify that no daemon already owns `/var/run/ios-unsandboxedd.sock`, that `/var/run` is a root-owned directory without group/world write access, and that the path is not occupied by an unrelated object. If anything is active, ambiguous, or not project-owned, stop and record the result; never unlink it by hand.

In a dedicated root SSH session, run the staged daemon in the foreground:

```sh
sudo /tmp/ios-unsandboxedd --serve
```

From an existing root-capable SSH session, query and record the peer and state diagnostics:

```sh
sudo /tmp/ios-unsandboxed status
ls -l /var/run/ios-unsandboxedd.sock /var/run/ios-unsandboxedd.sock.lock
stat -f 'uid=%u gid=%g mode=%Lp' /var/run/ios-unsandboxedd.sock
```

The socket should be root-owned and mode `0600`; activation must report disabled and the state/Amethyst status must remain separate. From a separate existing non-root SSH identity, run `/tmp/ios-unsandboxed status`. A connection failure is expected from the production socket's `0600` mode; it must report activation `UNKNOWN`, not infer it from a local state file. Record both the denial and the SSH identity. This verifies the intended root-only production access model. It does not test non-root peer credentials through that root-only socket; step 2 tests native peer credentials through a private socket run as that non-root identity.

Stop the foreground daemon with SIGTERM, verify it exits cleanly and removes only the socket inode it created, and confirm the lock file is retained. Do not remove the lock file or alter `/var/run` permissions during qualification. Keep the separate SSH sessions open and verify that a new unrelated SSH login/command still works. If it does not, stop testing and use the existing independent SSH recovery route; do not replace or reconfigure SSH.

## 4. Device-only lifecycle gates

The P005 plist is not installed or activated. Do not load it during the initial IPC qualification. Launchd acceptance, service startup/shutdown under launchd, reboot recovery, and jailbreak-environment restart require a separately scheduled device window and explicit later deployment authorization. During that later gate, verify launchd logs, no restart loop, `RunAtLoad`, normal SIGTERM cleanup, and SSH preservation. Do not treat host `plistlib` parsing as launchd evidence.

## 5. Evidence ledger

At P005 implementation time, no physical reference iPad session is available in this workspace. No device commands or output have been collected. Every physical gate therefore remains **NOT RUN**:

| Gate | Result |
|---|---|
| A1489 / Apple A7 / iOS product version and build observed | NOT RUN |
| ARM64 iOS CLI and daemon execute on device | NOT RUN |
| Available dynamic linker and Mach-O startup prerequisites | NOT RUN |
| Installed Amethyst provenance and component availability | NOT RUN |
| Procursus/rootful filesystem and project-directory ownership | NOT RUN |
| Native Darwin `getpeereid` peer UID/GID | NOT RUN |
| Root and non-root SSH IPC behavior | NOT RUN |
| `/var/run` socket creation, mode, owner, and stale-path behavior | NOT RUN |
| SIGTERM cleanup and daemon restart on device | NOT RUN |
| Unrelated SSH sessions remain functional | NOT RUN |
| launchd accepts/starts/stops the plist on iOS 12.5.7 | NOT RUN |
| Device reboot and jailbreak-environment restart recovery | NOT RUN |

Host Linux `SO_PEERCRED`, temporary state fixtures, and macOS iOS cross-compilation must be recorded in separate columns from these device gates. Device acceptance remains `NOT TESTED` until actual device records are reviewed and attached.
