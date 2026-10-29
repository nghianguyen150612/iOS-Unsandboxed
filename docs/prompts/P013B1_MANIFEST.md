# P013B-1 manifest

Adds a bounded in-memory C17 trust-store codec, shares the existing SHA-256 implementation, enforces ascending key IDs in C and Rust, and exercises cross-language canonical fixtures. No persistent trust-store mutation or execution authorization is implemented. See `docs/validation/P013B1_TRUST_CODEC_GATES.md` for the ABI and test contract.
