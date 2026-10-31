//! Canonical, bounded read-only builder transaction metadata.

pub(crate) const MAX_JOURNAL_BYTES: usize = 1024;
pub(crate) const MAX_MARKER_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pair {
    pub generation: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marker {
    pub roots: Pair,
    pub policies: Pair,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Journal {
    pub operation: String,
    pub old_roots: Option<Pair>,
    pub new_roots: Pair,
    pub old_policies: Option<Pair>,
    pub new_policies: Pair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransactionState {
    NoTransaction,
    PreparedOldPair,
    FirstStoreReplaced,
    SecondStoreReplaced,
    BothStoresReplaced,
    CommittedPairMarkerPending,
    CompleteCommit,
    RecoveryRequired,
    ConflictingState,
    CorruptTransaction,
    UnsafeTransactionArtifact,
    UnknownState,
}

impl TransactionState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NoTransaction => "NO_TRANSACTION",
            Self::PreparedOldPair => "PREPARED_OLD_PAIR",
            Self::FirstStoreReplaced => "FIRST_STORE_REPLACED",
            Self::SecondStoreReplaced => "SECOND_STORE_REPLACED",
            Self::BothStoresReplaced => "BOTH_STORES_REPLACED",
            Self::CommittedPairMarkerPending => "COMMITTED_PAIR_MARKER_PENDING",
            Self::CompleteCommit => "COMPLETE_COMMIT",
            Self::RecoveryRequired => "RECOVERY_REQUIRED",
            Self::ConflictingState => "CONFLICTING_STATE",
            Self::CorruptTransaction => "CORRUPT_TRANSACTION",
            Self::UnsafeTransactionArtifact => "UNSAFE_TRANSACTION_ARTIFACT",
            Self::UnknownState => "UNKNOWN_STATE",
        }
    }

    pub(crate) fn provider_label(self) -> &'static str {
        match self {
            Self::NoTransaction => "BUILDER_TRUST_SETTLED",
            Self::PreparedOldPair
            | Self::FirstStoreReplaced
            | Self::SecondStoreReplaced
            | Self::BothStoresReplaced
            | Self::CommittedPairMarkerPending
            | Self::CompleteCommit => "BUILDER_TRANSACTION_PENDING",
            Self::RecoveryRequired => "BUILDER_TRANSACTION_RECOVERY_REQUIRED",
            Self::ConflictingState => "BUILDER_TRUST_PAIR_INCONSISTENT",
            Self::CorruptTransaction => "BUILDER_TRANSACTION_CORRUPT",
            Self::UnsafeTransactionArtifact => "BUILDER_TRANSACTION_UNSAFE",
            Self::UnknownState => "BUILDER_TRUST_SNAPSHOT_STALE",
        }
    }

    pub(crate) fn recovery_label(self) -> &'static str {
        match self {
            Self::NoTransaction => "NO",
            Self::UnknownState => "UNKNOWN",
            _ => "YES",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkerStatus {
    Matching,
    LegacyUnanchored,
    MatchingOldPair,
    MatchingNewPair,
    MissingPending,
    OldPairPending,
    Inconsistent,
    Unsafe,
    Unavailable,
    Unknown,
}

impl MarkerStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Matching => "MATCHING",
            Self::LegacyUnanchored => "LEGACY_UNANCHORED",
            Self::MatchingOldPair => "MATCHING_OLD_PAIR",
            Self::MatchingNewPair => "MATCHING_NEW_PAIR",
            Self::MissingPending => "BUILDER_GENERATION_MARKER_UNAVAILABLE",
            Self::OldPairPending => "OLD_PAIR_MARKER_PENDING",
            Self::Inconsistent => "BUILDER_GENERATION_MARKER_INCONSISTENT",
            Self::Unsafe => "UNSAFE",
            Self::Unavailable => "BUILDER_GENERATION_MARKER_UNAVAILABLE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observation<T> {
    Absent,
    Valid(T),
    Invalid,
    Unsafe,
    Unavailable,
}

/// Classifies the observed pair and transaction artifacts. Every conclusion
/// comes from parsed store generations and raw content digests. The journal's
/// phase field is deliberately absent from this interface.
pub(crate) fn classify(
    journal: Observation<Journal>,
    roots: Observation<Pair>,
    policies: Observation<Pair>,
    root_stage: Observation<Pair>,
    policy_stage: Observation<Pair>,
    marker: Observation<Marker>,
) -> TransactionState {
    use Observation::{Absent, Invalid, Unsafe, Valid};
    use TransactionState as State;

    if matches!(&journal, Unsafe)
        || matches!(&root_stage, Unsafe)
        || matches!(&policy_stage, Unsafe)
    {
        return State::UnsafeTransactionArtifact;
    }
    if matches!(&journal, Observation::Unavailable)
        || matches!(&root_stage, Observation::Unavailable)
        || matches!(&policy_stage, Observation::Unavailable)
    {
        return State::UnknownState;
    }
    if matches!(&journal, Invalid) {
        return State::CorruptTransaction;
    }
    if matches!(&root_stage, Invalid) || matches!(&policy_stage, Invalid) {
        return State::ConflictingState;
    }

    let transaction = match journal {
        Absent if matches!(&root_stage, Absent) && matches!(&policy_stage, Absent) => {
            return State::NoTransaction;
        }
        Absent => return State::RecoveryRequired,
        Valid(transaction) => transaction,
        Invalid | Unsafe | Observation::Unavailable => unreachable!(),
    };

    if matches!(&roots, Unsafe) || matches!(&policies, Unsafe) || matches!(&marker, Unsafe) {
        return State::UnsafeTransactionArtifact;
    }
    if matches!(&roots, Observation::Unavailable)
        || matches!(&policies, Observation::Unavailable)
        || matches!(&marker, Observation::Unavailable)
    {
        return State::UnknownState;
    }
    if matches!(&roots, Invalid) || matches!(&policies, Invalid) || matches!(&marker, Invalid) {
        return State::ConflictingState;
    }

    let roots_old = matches_pair(&roots, transaction.old_roots.as_ref());
    let policies_old = matches_pair(&policies, transaction.old_policies.as_ref());
    let roots_new = matches_pair(&roots, Some(&transaction.new_roots));
    let policies_new = matches_pair(&policies, Some(&transaction.new_policies));
    if !(roots_old || roots_new) || !(policies_old || policies_new) {
        return State::ConflictingState;
    }

    let roots_changed = transaction.old_roots.as_ref() != Some(&transaction.new_roots);
    let policies_changed = transaction.old_policies.as_ref() != Some(&transaction.new_policies);
    let root_stage_new = matches!(&root_stage, Valid(pair) if pair == &transaction.new_roots);
    let policy_stage_new =
        matches!(&policy_stage, Valid(pair) if pair == &transaction.new_policies);
    let root_stage_absent = matches!(&root_stage, Absent);
    let policy_stage_absent = matches!(&policy_stage, Absent);

    let marker_old = match (
        transaction.old_roots.as_ref(),
        transaction.old_policies.as_ref(),
        &marker,
    ) {
        (Some(old_roots), Some(old_policies), Valid(marker)) => {
            marker.roots == *old_roots && marker.policies == *old_policies
        }
        (_, _, Absent) => true,
        _ => false,
    };
    let marker_new = matches!(
        &marker,
        Valid(value)
            if value.roots == transaction.new_roots
                && value.policies == transaction.new_policies
    );

    if roots_old && policies_old {
        if !marker_old {
            return State::ConflictingState;
        }
        let stages_complete = (!roots_changed || root_stage_new)
            && (!policies_changed || policy_stage_new)
            && (roots_changed || root_stage_absent)
            && (policies_changed || policy_stage_absent);
        if stages_complete {
            return State::PreparedOldPair;
        }
        let stages_missing_only = (!roots_changed || root_stage_new || root_stage_absent)
            && (!policies_changed || policy_stage_new || policy_stage_absent)
            && (roots_changed || root_stage_absent)
            && (policies_changed || policy_stage_absent);
        return if stages_missing_only {
            State::RecoveryRequired
        } else {
            State::ConflictingState
        };
    }

    if roots_new && policies_old && roots_changed && policies_changed {
        return if root_stage_absent && policy_stage_new && marker_old {
            State::FirstStoreReplaced
        } else {
            State::ConflictingState
        };
    }
    if roots_old && policies_new && roots_changed && policies_changed {
        return if root_stage_new && policy_stage_absent && marker_old {
            State::SecondStoreReplaced
        } else {
            State::ConflictingState
        };
    }

    if roots_new && policies_new {
        if (roots_changed && !root_stage_absent)
            || (policies_changed && !policy_stage_absent)
            || (!roots_changed && !root_stage_absent)
            || (!policies_changed && !policy_stage_absent)
        {
            return State::ConflictingState;
        }
        if marker_new {
            State::CompleteCommit
        } else if matches!(&marker, Absent) {
            State::CommittedPairMarkerPending
        } else if marker_old {
            State::BothStoresReplaced
        } else {
            State::ConflictingState
        }
    } else {
        State::ConflictingState
    }
}

fn matches_pair(observation: &Observation<Pair>, expected: Option<&Pair>) -> bool {
    match (observation, expected) {
        (Observation::Absent, None) => true,
        (Observation::Valid(actual), Some(expected)) => actual == expected,
        _ => false,
    }
}

fn lines(bytes: &[u8], maximum: usize) -> Result<Vec<&str>, &'static str> {
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.last() != Some(&b'\n')
        || bytes
            .iter()
            .any(|b| *b != b'\n' && !(0x20..=0x7e).contains(b))
    {
        return Err("invalid ASCII/LF metadata");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid ASCII")?;
    Ok(text[..text.len() - 1].split('\n').collect())
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str, &'static str> {
    line.strip_prefix(name)
        .filter(|v| !v.is_empty())
        .ok_or("invalid field order or value")
}

fn number(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical generation");
    }
    value.parse().map_err(|_| "generation overflow")
}

fn digest(value: &str) -> Result<String, &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid SHA-256");
    }
    Ok(value.to_owned())
}

fn pair(generation: &str, hash: &str) -> Result<Pair, &'static str> {
    Ok(Pair {
        generation: number(generation)?,
        digest: digest(hash)?,
    })
}

fn old_pair(generation: &str, hash: &str) -> Result<Option<Pair>, &'static str> {
    if generation == "none" && hash == "none" {
        Ok(None)
    } else if generation == "none" || hash == "none" {
        Err("inconsistent absent store")
    } else {
        Ok(Some(pair(generation, hash)?))
    }
}

fn changed(old: &Option<Pair>, new: &Pair) -> Result<bool, &'static str> {
    match old {
        None if new.generation == 1 => Ok(true),
        None => Err("invalid initial generation"),
        Some(old) if old == new => Ok(false),
        Some(old)
            if old.generation.checked_add(1) == Some(new.generation)
                && old.digest != new.digest =>
        {
            Ok(true)
        }
        Some(_) => Err("invalid generation transition"),
    }
}

pub(crate) fn parse_journal(bytes: &[u8]) -> Result<Journal, &'static str> {
    let l = lines(bytes, MAX_JOURNAL_BYTES)?;
    if l.len() != 14 || l[0] != "ios-unsandboxed-builder-transaction" || l[1] != "schema_version=1"
    {
        return Err("unsupported journal schema");
    }
    let operation = field(l[2], "operation=")?;
    let old_roots = old_pair(
        field(l[3], "old_root_generation=")?,
        field(l[5], "old_root_sha256=")?,
    )?;
    let new_roots = pair(
        field(l[4], "new_root_generation=")?,
        field(l[6], "new_root_sha256=")?,
    )?;
    let old_policies = old_pair(
        field(l[7], "old_policy_generation=")?,
        field(l[9], "old_policy_sha256=")?,
    )?;
    let new_policies = pair(
        field(l[8], "new_policy_generation=")?,
        field(l[10], "new_policy_sha256=")?,
    )?;
    if l[11] != "stage_roots=roots.stage.v1"
        || l[12] != "stage_policies=policies.stage.v1"
        || l[13] != "phase=prepared"
    {
        return Err("unsupported stage or phase");
    }
    let roots_changed = changed(&old_roots, &new_roots)?;
    let policies_changed = changed(&old_policies, &new_policies)?;
    if !matches!(
        (operation, roots_changed, policies_changed),
        ("roots", true, false) | ("policies", false, true) | ("combined", true, true)
    ) {
        return Err("operation does not match changes");
    }
    Ok(Journal {
        operation: operation.to_owned(),
        old_roots,
        new_roots,
        old_policies,
        new_policies,
    })
}

pub(crate) fn parse_marker(bytes: &[u8]) -> Result<Marker, &'static str> {
    let l = lines(bytes, MAX_MARKER_BYTES)?;
    if l.len() != 6 || l[0] != "ios-unsandboxed-builder-state" || l[1] != "schema_version=1" {
        return Err("unsupported marker schema");
    }
    Ok(Marker {
        roots: pair(
            field(l[2], "root_generation=")?,
            field(l[3], "root_sha256=")?,
        )?,
        policies: pair(
            field(l[4], "policy_generation=")?,
            field(l[5], "policy_sha256=")?,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(generation: u64, digest: char) -> Pair {
        Pair {
            generation,
            digest: digest.to_string().repeat(64),
        }
    }

    fn combined_update() -> (Journal, Pair, Pair, Pair, Pair) {
        let old_roots = pair(4, '1');
        let new_roots = pair(5, 'a');
        let old_policies = pair(7, '2');
        let new_policies = pair(8, 'b');
        (
            Journal {
                operation: "combined".into(),
                old_roots: Some(old_roots.clone()),
                new_roots: new_roots.clone(),
                old_policies: Some(old_policies.clone()),
                new_policies: new_policies.clone(),
            },
            old_roots,
            new_roots,
            old_policies,
            new_policies,
        )
    }

    fn marker(roots: Pair, policies: Pair) -> Observation<Marker> {
        Observation::Valid(Marker { roots, policies })
    }

    #[test]
    fn canonical_metadata_rejects_duplicates_and_overflow() {
        assert!(parse_journal(include_bytes!(
            "../../tests/builder-trust/valid-transaction.v1"
        ))
        .is_ok());
        let hash = "a".repeat(64);
        let marker = format!("ios-unsandboxed-builder-state\nschema_version=1\nroot_generation=1\nroot_sha256={hash}\npolicy_generation=2\npolicy_sha256={hash}\n");
        assert!(parse_marker(marker.as_bytes()).is_ok());
        assert!(parse_marker(
            marker
                .replace("root_generation=1", "root_generation=01")
                .as_bytes()
        )
        .is_err());
        assert!(parse_marker(
            marker
                .replace("policy_generation=2", "root_generation=2")
                .as_bytes()
        )
        .is_err());
        let journal = format!("ios-unsandboxed-builder-transaction\nschema_version=1\noperation=combined\nold_root_generation=none\nnew_root_generation=1\nold_root_sha256=none\nnew_root_sha256={hash}\nold_policy_generation=none\nnew_policy_generation=1\nold_policy_sha256=none\nnew_policy_sha256={hash}\nstage_roots=roots.stage.v1\nstage_policies=policies.stage.v1\nphase=prepared\n");
        assert!(parse_journal(journal.as_bytes()).is_ok());
        assert!(parse_journal(journal.replace("roots.stage.v1", "../roots").as_bytes()).is_err());
        assert!(parse_journal(
            journal
                .replace(
                    "new_root_generation=1",
                    "new_root_generation=18446744073709551616"
                )
                .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn rust_parser_matches_the_shared_c17_adversarial_corpus() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/builder-trust/transaction-vectors.json"
        ))
        .unwrap();
        assert_eq!(corpus["schemaVersion"], 1);
        for case in corpus["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let base_name = case["base"].as_str().unwrap();
            let mut document = corpus["bases"][base_name].as_str().unwrap().to_owned();
            for mutation in case["mutations"].as_array().unwrap() {
                let from = mutation[0].as_str().unwrap();
                let to = mutation[1].as_str().unwrap();
                assert_eq!(document.matches(from).count(), 1, "{name}");
                document = document.replacen(from, to, 1);
            }
            let parsed = parse_journal(document.as_bytes());
            assert_eq!(parsed.is_ok(), case["valid"].as_bool().unwrap(), "{name}");
        }
        let oversized = vec![b' '; MAX_JOURNAL_BYTES + 1];
        assert!(parse_journal(&oversized).is_err());
    }

    #[test]
    fn classifier_covers_all_recoverable_pair_observations_fail_closed() {
        use Observation::{Absent, Invalid, Unsafe, Valid};
        use TransactionState as State;

        assert_eq!(
            classify(Absent, Absent, Absent, Absent, Absent, Absent),
            State::NoTransaction
        );
        assert_eq!(
            classify(Absent, Absent, Absent, Valid(pair(1, 'a')), Absent, Absent),
            State::RecoveryRequired
        );
        assert_eq!(
            classify(Invalid, Absent, Absent, Absent, Absent, Absent),
            State::CorruptTransaction
        );
        assert_eq!(
            classify(Unsafe, Absent, Absent, Absent, Absent, Absent),
            State::UnsafeTransactionArtifact
        );
        assert_eq!(
            classify(
                Observation::Unavailable,
                Absent,
                Absent,
                Absent,
                Absent,
                Absent
            ),
            State::UnknownState
        );

        let (journal, old_roots, new_roots, old_policies, new_policies) = combined_update();
        let journal_obs = || Valid(journal.clone());
        let old_marker = || marker(old_roots.clone(), old_policies.clone());
        assert_eq!(
            classify(
                journal_obs(),
                Valid(old_roots.clone()),
                Valid(old_policies.clone()),
                Valid(new_roots.clone()),
                Valid(new_policies.clone()),
                old_marker(),
            ),
            State::PreparedOldPair
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(new_roots.clone()),
                Valid(old_policies.clone()),
                Absent,
                Valid(new_policies.clone()),
                old_marker(),
            ),
            State::FirstStoreReplaced
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(old_roots.clone()),
                Valid(new_policies.clone()),
                Valid(new_roots.clone()),
                Absent,
                old_marker(),
            ),
            State::SecondStoreReplaced
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(old_roots.clone()),
                Valid(old_policies.clone()),
                Absent,
                Valid(new_policies.clone()),
                old_marker(),
            ),
            State::RecoveryRequired
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(new_roots.clone()),
                Valid(new_policies.clone()),
                Absent,
                Absent,
                old_marker(),
            ),
            State::BothStoresReplaced
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(new_roots.clone()),
                Valid(new_policies.clone()),
                Absent,
                Absent,
                Absent,
            ),
            State::CommittedPairMarkerPending
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(new_roots.clone()),
                Valid(new_policies.clone()),
                Absent,
                Absent,
                marker(new_roots.clone(), new_policies.clone()),
            ),
            State::CompleteCommit
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(pair(5, 'c')),
                Valid(new_policies),
                Absent,
                Absent,
                old_marker(),
            ),
            State::ConflictingState
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(old_roots),
                Valid(old_policies),
                Invalid,
                Absent,
                Absent,
            ),
            State::ConflictingState
        );
        assert_eq!(
            classify(
                journal_obs(),
                Valid(pair(4, '1')),
                Valid(pair(7, '2')),
                Valid(pair(5, 'a')),
                Valid(pair(8, 'b')),
                marker(pair(9, '9'), pair(7, '2')),
            ),
            State::ConflictingState
        );
    }
}
