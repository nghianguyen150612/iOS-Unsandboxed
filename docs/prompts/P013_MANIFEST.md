# P013 implementation manifest

Branch: `feat/p013-authenticated-provenance` (based on open P012 branch `feat/p012-artifact-provenance-launch-binding`).

P013 adds an offline Rust Ed25519 signed-manifest verifier and a strict read-only publisher trust-store parser. P013C binds that publisher result to P012/P010's opened artifact descriptor. P013D-1 adds separate bounded DSSE/in-toto/SLSA build-attestation verification through an independent versioned builder provider; it never promotes publisher trust into builder trust. The attestation CLI is `iu provenance attestation verify ATTESTATION ARTIFACT`.

Publisher identity and key trust are separate from artifact identity, builder identity/trust, source identity, reproducibility, protected origin, policy, runtime capability, and operational authorization. Production has no independent builder root in P013D-1 and remains `BUILD_ORIGIN_UNVERIFIED`. Trust mutation, authoritative protected-artifact classification, rollback-resistant generations, and full filesystem transaction testing remain open. No execution behavior, trust-cache manipulation, kernel changes, Amethyst private XPC, or launch authorization is implemented.
