# Build-origin evidence boundary

P013 manifests carry an artifact identity plus claimed build artifact ID, source repository, source revision, workflow, builder, and publisher. These fields are included in the Ed25519 signed bytes. The signature establishes that a trusted publisher made those claims; it does not independently establish that the binary was built from that source or workflow.

This repository has no independently verifiable CI attestation provider, transparency log integration, reproducible-build verifier, or trusted builder identity registry. Consequently every report says `ORIGIN_UNVERIFIED`, even if the signature and publisher identity are valid. The pinned Amethyst source revision is not evidence of the installed Amethyst binary's build.

An eventual provider must validate an attestation from a configured issuer, bind its subject digest to the inspected artifact, bind workflow and source identities to issuer policy, and validate freshness/revocation. Until that exists, origin claims cannot satisfy protected-origin policy.
