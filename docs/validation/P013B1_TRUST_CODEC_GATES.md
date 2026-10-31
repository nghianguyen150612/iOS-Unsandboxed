# P013B-1 trust codec gates

The in-memory C17 ABI v1 uses a 264-byte record and 16,920-byte fixed store. The codec validates schema, canonical ASCII, limits, key IDs, publisher scope, state, generation, and strictly ascending IDs. The key ID uses the existing adapter SHA-256 implementation. Encoding produces exactly the Rust v1 text format and never writes files. The codec checks the 32-byte key representation and derived ID; curve-point acceptance remains the Ed25519 verifier's responsibility, matching the Rust store parser.

`make trust-format-test` runs C API checks, deterministic valid and malformed fixtures through C and Rust, byte-for-byte round trips in both directions, and AddressSanitizer/UndefinedBehaviorSanitizer when available. These checks do not establish memory safety or device runtime behavior. Apple ARM64 compilation is checked by the existing iOS package CI. Trust lifecycle mutations and recovery are outside this increment.

On the Linux development host, `cargo fmt --check`, strict Clippy, all 23 Rust tests, `make trust-format-test` (including ASan/UBSan), and `make test` passed. Apple cross-compilation requires the macOS CI result for this commit; physical-device validation remains NOT RUN.
