# P013D-2A implementation manifest

P013D-2A implements the versioned read-only `roots.v1` and `policies.v1`
builder trust schemas, bounded canonical duplicate-rejecting JSON parsing,
descriptor-relative no-follow reads, strict ownership/mode/link checks,
separate Ed25519 signer and exact builder policy matching, snapshot digest and
generation reporting, and CLI status/list/inspect diagnostics. The concrete
`LocalBuilderVerificationProviderV1` uses only this separate builder store;
publisher trust is never reused.

Production has no embedded or automatically provisioned builder keys. Root
ownership and a matching local policy establish only local administrative
trust. Independent trust establishment remains `UNVERIFIED`, so production
build origin remains `BUILD_ORIGIN_UNVERIFIED`. Local generations are not
rollback-resistant. Enrollment, revocation management, key rotation,
transaction journals and crash recovery remain P013D-2B work.

The provider continues to verify DSSE with the existing RustCrypto
implementation and binds the subject digest to the P013C opened descriptor.
It does not accept caller-supplied trust booleans. It issues no authorization
token and makes no network calls. Protected origin remains `UNKNOWN`, runtime
remains `UNVERIFIED`, launch boundary remains `NOT IMPLEMENTED`, execution
activation is disabled, operational authorization remains false, and device
validation is `NOT RUN`.
