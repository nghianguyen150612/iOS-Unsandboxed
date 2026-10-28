# P008 — Controlled LaunchDaemon Lifecycle & Recovery

## Outcome scope

P008 extends the P007 installer helper with service plan/status/register/start/stop/unregister/recover operations for only `com.ios-unsandboxed.daemon`. It does not implement or activate transparent Mach-O execution.

## Baseline

- Verified `origin/main`: `159a6c76c4675ec62854c4283356584e3ac3450a`.
- P007 transaction implementation `2af2c6f3e8796c7ecfc7c35b7446a8a330376d5c` and correction `e42e564959433f219e6bbea5468e6a9cfb34ca88` are in main ancestry.
- Reference A1489 identifier is `iPad4,4`; installer, preflight and device harness agree.
- Branch: `feat/p008-launchd-lifecycle`.

## Safety invariants

- P005 state schema v1 remains unchanged and execution activation remains disabled.
- No automatic service action occurs during install or upgrade.
- Service mutation requires `--apply --confirm`; register additionally requires `--acknowledge-run-at-load`.
- Production mutation is root-only and limited to iPad4,4 / iOS 12.5.7 plus P007 path, ownership, manifest, and integrity checks.
- Launchctl operations use fixed arguments through the adapter. Host fixture calls require an explicit mock path under `--test-root`.
- Foreign plist files and ambiguous launchd states are preserved; no unrelated job or SSH operation is targeted.
- P008 does not implement any P009 work.

## Device evidence boundary

No physical-device result may be inferred from source, host fixtures, or Apple cross-compilation. iOS 12.5.7 launchctl acceptance, `RunAtLoad`, startup/signing, Darwin peer credentials, root:wheel and Procursus behavior, SSH continuity, removal, reboot and Amethyst interoperability remain **NOT RUN** until observed on hardware.
