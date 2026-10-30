# P013D-2A builder policy schema

The optional combined `state.v1` marker binds this policy store to the root store; a conflicting marker fails closed. Root and policy changes are one logical configuration. `transaction.v1` records expected old/new generations and digests for both stores, including the unchanged store when an operation changes only one. The read-only classifier rejects unsettled pairs and retains the actual observed generations in status output. See [transaction metadata](builder-trust-transactions.md).

`policies.v1` is a separate canonical JSON document. Its root has exactly
`schemaVersion`, `generation`, and `policies`. `schemaVersion` is integer `1`,
and there may be at most 64 policy records. Root and policy generations are
independent local counters.

Each policy has exactly these fields:

```json
{
  "allowedGitRevisions": ["0123456789abcdef0123456789abcdef01234567"],
  "builderId": "https://ci.example.invalid/builders/release-v1",
  "buildType": "https://ci.example.invalid/buildtypes/ios-release-v1",
  "externalParameters": {"repository":"https://example.invalid/acme/app","revision":"0123456789abcdef0123456789abcdef01234567"},
  "policyId": "<64 lowercase hex characters>",
  "signerIdentity": "local-ci-key-enrollment-17",
  "sourceUri": "git+https://example.invalid/acme/app",
  "state": "active",
  "version": 1
}
```

`policyId` is the lowercase hexadecimal SHA-256 digest of the compact,
sorted-key JSON encoding of the policy fields other than `policyId`. It
includes `version`, `state`, and the complete external-parameter object.
Policies are sorted by `policyId`. There may be only one policy for an exact
signer identity and builder ID pair.

The signer identity must match the identity attached to an active key in
`roots.v1`. Builder ID and source URI are exact strings; wildcard and prefix
matches are unsupported. The build type must match exactly. The attested
`externalParameters` object must be structurally equal to the entire approved
object, so missing and extra parameters both reject. JSON object key order does
not affect structural comparison. The expected source URI must match the
resolved dependency URI, and its Git revision must exactly match one allowed
full 40- or 64-character lowercase hexadecimal object ID. Revision prefixes
are rejected.

`active` policies can authorize only their explicit tuple. `revoked` policies
are retained for inspection and never authorize. No policy authorizes future
revisions by repository wildcard, and no local policy by itself proves the
real-world identity of a CI system. The P013D-2B enrollment workflow must
establish that trust anchor independently before production can report a
verified build origin.
