# P013D-1 implementation manifest

P013D-1 implements a bounded offline verifier for a DSSE envelope carrying an in-toto Statement v1 with a SLSA Provenance v1.0 predicate. It uses exact DSSE PAE bytes and RustCrypto Ed25519, rejects duplicate JSON fields and unsupported profiles, binds one matching SHA-256 subject to the already-opened P013C descriptor snapshot, extracts builder/source/build-type claims, and returns typed independent trust outcomes.

The versioned builder provider is separate from P013 publisher trust. Host tests inject deterministic synthetic builder roots; production has no builder roots and rejects unknown signers/builders without enrollment. `iu provenance attestation verify ATTESTATION ARTIFACT` is a read-only local diagnostic and does not require the daemon.

No SLSA level, GitHub Actions authenticity, reproducible-build result, or protected-origin result is claimed. Protected origin stays `UNKNOWN`, Amethyst runtime stays `UNVERIFIED`, launch boundary stays `NOT IMPLEMENTED`, execution activation stays disabled, and operational authorization stays false. No launching, activation, trust-cache or AMFI changes, code-signature bypass, private Amethyst operation, or device validation is included. P013D-2 and P014 remain out of scope.
