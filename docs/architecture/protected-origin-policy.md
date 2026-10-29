# Protected-origin decision

P013 never infers safety from absence in a small Apple executable hash list. Its protected-origin field is `UNKNOWN` because no authoritative protected-artifact classification provider is available. A manifest's `origin=unprotected` value is a signed claim only. A publisher key is scoped to authenticate its publisher identity and is not authorized to assert source origin or override Apple-protected classification.

The P013C integrated provider rejects unknown or revoked keys, unsupported algorithms, publisher/key scope mismatch, invalid signatures, malformed documents, stale trust state, and artifact identity mismatch. It checks any known protected-path result before returning its diagnostic snapshot. A synthetic copied-protected-artifact fixture remains blocked even with a valid publisher signature. The signed `origin=unprotected` field does not change the provider's `ORIGIN_UNVERIFIED` build-origin and `UNKNOWN` protected-origin values. No policy result creates operational authorization.

P013C does not provide an authoritative catalog or independent provenance source. A complete protected-artifact classification and external build/source evidence remain outstanding. Runtime behavior remains unverified, launch remains blocked, and authorization remains false.
