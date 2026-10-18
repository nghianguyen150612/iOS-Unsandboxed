# Native execution layer boundary

This directory is reserved for native execution-engine code. P001 contains no native engine, Apple API calls, Amethyst adapter, launch hook, or signing/trust integration.

Future native code must remain separate from the Rust CLI and generic C17 daemon. Keep any Apple-specific API use behind platform guards and a project-owned interface. Place Amethyst-specific code behind a backend adapter so it can be reviewed and validated against the exact upstream source revision and ABI in use. Do not make generic engine code depend directly on Amethyst internals.

P001 intentionally does not define a speculative C ABI here. The interface should be established alongside validated IPC and backend requirements in later work.
