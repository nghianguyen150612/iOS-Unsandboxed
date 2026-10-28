# Artifact provenance contract (P012)

ABI v1 is defined by `iu_artifact_provenance.h`. The result is fixed-width, sized and pointer-free. The verifier consumes an already inspected P010 identity and at most 2048 bytes of evidence; it performs no file execution, shell interpretation, network access, or writes. It reports absent, local declaration, malformed, identity mismatch, untrusted, verified, known protected, and unverified separately. `identity_match`, document integrity, publisher authentication and protected classification are separate facts. None is launch authorization.

The v1 byte format is ASCII, LF terminated, with exactly these ordered, unique fields:

```
schema_version=1
artifact_sha256=<64 lowercase hex digits>
artifact_size=<canonical unsigned decimal>
architecture=<P010 architecture number>
filetype=<Mach-O filetype number>
source=<local|manifest>
publisher=<token>
build=<token>
manifest=<token>
anchor=<token>
origin=<unknown|protected|unprotected>
algorithm=none
proof=<token>
```

Tokens contain only ASCII letters, digits, `.`, `_`, or `-`, and are 1–95 bytes. A `-` can represent an unspecified label. Canonical decimals have no leading zero except `0`. Truncated, oversized, duplicated, reordered, non-ASCII, unknown schema and unsupported algorithm inputs are rejected. `none` supplies no signature; neither the identity strings, `proof`, nor the claimed origin are trusted. A local declaration remains `LOCAL_DECLARATION_ONLY`. An identity mismatch is reported before trust; matching the exact digest, size, architecture, and file type is necessary but never sufficient for authentication. The production implementation contains no trusted verifier, public keys, or configurable test backend, so a matching manifest with `algorithm=none` is `PROVENANCE_UNVERIFIED`.

The verifier accepts evidence bytes rather than opening an arbitrary path. The caller is responsible for safely collecting and supplying a current bounded document; its source and custody are not established by this API. The launch revalidator requires the caller to supply the current bytes again and compares them against the snapshot; it cannot detect an evidence file change that the caller conceals by resupplying old bytes. A future trusted collector must bind a safely opened evidence object and its trust policy to the launch boundary. `iu plan` currently supplies no evidence and reports it absent; it does not claim to discover manifests.
