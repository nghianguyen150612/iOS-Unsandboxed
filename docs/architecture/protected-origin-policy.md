# Protected-origin decision

P013 never infers safety from absence in a small Apple executable hash list. Its protected-origin field is `UNKNOWN` because no authoritative protected-artifact classification provider is available. A manifest's `origin=unprotected` value is a signed claim only. A publisher key is scoped to authenticate its publisher identity and is not authorized to assert source origin or override Apple-protected classification.

The current policy rejects unknown origin, unknown or revoked keys, unsupported algorithms, publisher/key scope mismatch, invalid signatures, malformed documents, and artifact identity mismatch. Even a valid signature for a matching artifact remains ineligible because build origin and protected-origin status are unverified. Copied system binaries cannot become eligible by receiving a new manifest. No policy result creates operational authorization.
