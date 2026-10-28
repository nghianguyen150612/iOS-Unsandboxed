# P013 canonical cryptographic contract

Manifest v1 is ASCII, LF terminated, contains no CR/NUL, is at most 8192 bytes, and has exactly these unique fields in this order:

```text
schema_version=1
artifact_sha256=<64 lowercase hex>
artifact_size=<canonical unsigned decimal>
architecture=<canonical unsigned decimal>
filetype=<canonical unsigned decimal>
artifact_id=<identifier>
repository=<identifier>
revision=<identifier>
workflow=<identifier>
builder=<identifier>
publisher=<identifier>
algorithm=ed25519
key_id=<identifier>
origin=<unknown|protected|unprotected>
signature=<128 lowercase hex>
```

Identifiers use ASCII letters, digits, `.`, `_`, `-`, `/`, `:`, `+`, and `@`, up to 192 bytes. Decimal values have no leading zero except `0`. No JSON normalization is involved.

The Ed25519 message is the exact byte string `ios-unsandboxed-provenance-v1` followed by NUL, then the original manifest bytes from the first byte through the newline after `origin`. The `signature` line is excluded. No alternate algorithm or fallback is accepted. Signature length is exactly 64 bytes; public keys are exactly 32 bytes. Key ID is SHA-256(public key)[0..16], lowercase hex. The artifact digest, size, architecture and filetype must all equal the P010 inspected identity.

Canonical syntax validity, signature validity, trust-anchor state, publisher identity, build-origin authentication, protected-origin classification, and policy acceptance are separate outcomes. P013 currently cannot verify build-origin evidence or authoritative protected classification, so those outcomes remain unverified/unknown and policy remains rejected.
