# P013 implementation manifest

Branch: `feat/p013-authenticated-provenance` (based on open P012 branch `feat/p012-artifact-provenance-launch-binding`).

P013 adds an offline Rust Ed25519 signed-manifest verifier and a strict read-only publisher trust-store parser. P013C binds that publisher result to P012/P010's opened artifact descriptor. P013D adds separate bounded DSSE/in-toto/SLSA build-attestation verification through an independent versioned builder provider; P013D-2A adds read-only canonical builder roots and exact policies, without promoting publisher trust into builder trust. Diagnostics include `iu provenance attestation verify ATTESTATION ARTIFACT` and `iu provenance builder-trust status|list|inspect`.

Publisher identity and key trust are separate from artifact identity, builder identity/trust, source identity, reproducibility, protected origin, policy, runtime capability, and operational authorization. Production has no independently authenticated builder enrollment chain and remains `BUILD_ORIGIN_UNVERIFIED`, even if a local key and policy match. Trust mutation and lifecycle, authoritative protected-artifact classification, and rollback-resistant generations remain open. No execution behavior, trust-cache manipulation, kernel changes, Amethyst private XPC, or launch authorization is implemented.
