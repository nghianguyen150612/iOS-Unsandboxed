# IPC socket lifecycle

`ios-unsandboxedd --serve` explicitly starts the foreground production server at `/var/run/ios-unsandboxedd.sock`; it does not daemonize, install a LaunchDaemon, or start at boot. The caller must run it with effective UID 0. A later packaging/lifecycle task owns service management.

For development, `ios-unsandboxedd --test-socket <path>` explicitly selects test mode. It requires a socket path in an existing directory owned by the invoking UID and rejects the production socket pathname. It does not enable privileged operations. Host tests use private temporary directories and do not need root.

The daemon refuses an existing symlink or non-socket. For an existing socket, it checks owner and attempts a connection. An active listener is preserved and causes failure; a clearly stale socket in the validated parent may be removed before bind. Production also holds a lock file during the full server lifetime. Cleanup is limited to a pathname that still identifies the socket inode the process bound.

There is an unavoidable pathname race between a final `lstat` and `unlink` on portable POSIX APIs. Production reduces exposure by requiring a root-owned directory with no group/world write access and holding the instance lock. Test paths are intended to be inside a private directory owned by the test process. The daemon never recursively changes parent ownership or modes and never follows a final-component symlink.

The listener polls at short intervals so termination is responsive. It has backlog four, one active client, a 512-byte payload bound, and two-second frame transfer deadlines. Malformed or abandoned clients are closed; later clients continue to be served. If the runtime directory is absent or fails validation, startup fails without creating a path elsewhere.

On iOS, `/var/run` layout, Darwin peer credentials, socket permissions, root/non-root SSH behavior, and Apple A7 client/server behavior remain physical-device gates. The macOS cross-build only verifies compilation against the iOS SDK.
