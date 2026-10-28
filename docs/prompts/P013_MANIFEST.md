# P013 implementation manifest

Branch: `feat/p013-authenticated-provenance` (based on open P012 branch `feat/p012-artifact-provenance-launch-binding`).

P013 adds an offline Rust Ed25519 signed-manifest verifier and a strict read-only trust-store parser. It keeps P012 ABI v1 unchanged. `iu provenance verify MANIFEST ARTIFACT` inspects local files and reports signature, anchor, publisher, claimed build identity, build-origin evidence, protected-origin policy, P011 scope, P009 backend, and execution authorization separately.

Trust mutation, P012 production provider integration, independent build-origin attestations, authoritative protected-artifact classification, rollback-resistant generations, and full filesystem transaction testing remain open. No execution behavior, trust-cache manipulation, kernel changes, Amethyst private XPC, or launch authorization is implemented.
