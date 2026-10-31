//! Read-only local builder signer roots and exact build policies.
//!
//! This store is deliberately separate from publisher trust. Root ownership
//! establishes local installation, not the external identity of a CI system;
//! consequently this provider never establishes independent enrollment trust.

use crate::build_attestation::{
    BuilderAuthorityV1, BuilderPolicyV1, BuilderVerificationProviderV1, SignatureAlgorithmV1,
    SignerV1, PROVIDER_VERSION_V1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub const ROOT_STORE_SCHEMA_V1: u32 = 1;
pub const POLICY_STORE_SCHEMA_V1: u32 = 1;
pub const MAX_STORE_BYTES: usize = 64 * 1024;
pub const MAX_SIGNING_KEYS: usize = 32;
pub const MAX_POLICIES: usize = 64;
pub(crate) const MAX_IDENTITY_BYTES: usize = 256;
pub(crate) const MAX_URI_BYTES: usize = 2048;
const ROOT_FILE: &str = "roots.v1";
const POLICY_FILE: &str = "policies.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreErrorKind {
    Missing,
    Unavailable,
    Unsafe,
    Malformed,
    Unsupported,
    Stale,
    Pending,
    TransactionCorrupt,
    MarkerInconsistent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub kind: StoreErrorKind,
    pub message: String,
}

impl StoreError {
    fn new(kind: StoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileIdentity {
    fn from_meta(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            nlink: meta.nlink(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileSnapshot {
    identity: FileIdentity,
    digest: [u8; 32],
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderTrustSnapshotV1 {
    pub root_generation: u64,
    pub root_digest: [u8; 32],
    pub policy_generation: u64,
    pub policy_digest: [u8; 32],
    directory_chain: Vec<FileIdentity>,
    root_file: FileIdentity,
    policy_file: FileIdentity,
    marker: Option<FileSnapshot>,
}

impl BuilderTrustSnapshotV1 {
    pub fn render(&self) -> String {
        format!(
            "root_generation={} root_sha256={} policy_generation={} policy_sha256={}",
            self.root_generation,
            hex(&self.root_digest),
            self.policy_generation,
            hex(&self.policy_digest)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecordV1 {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: [u8; 32],
    pub signer_identity: String,
    pub state: String,
    pub enrollment_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyRecordV1 {
    pub policy_id: String,
    pub version: u32,
    pub state: String,
    pub signer_identity: String,
    pub builder_id: String,
    pub build_type: String,
    pub external_parameters: Value,
    pub source_uri: String,
    pub allowed_git_revisions: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RootStoreV1 {
    pub generation: u64,
    pub keys: BTreeMap<String, RootRecordV1>,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyStoreV1 {
    pub generation: u64,
    pub policies: BTreeMap<String, PolicyRecordV1>,
}

#[derive(Debug, Clone)]
struct LoadedStore<T> {
    parsed: Option<T>,
    snapshot: Option<FileSnapshot>,
    error: Option<StoreError>,
}

#[derive(Debug, Clone)]
struct LocalTrustState {
    roots: LoadedStore<RootStoreV1>,
    policies: LoadedStore<PolicyStoreV1>,
    directory_chain: Option<Vec<FileIdentity>>,
    marker: Option<FileSnapshot>,
    marker_status: crate::builder_transaction::MarkerStatus,
    transaction_status: crate::builder_transaction::TransactionState,
    root_diagnostic: Option<String>,
    policy_diagnostic: Option<String>,
}

#[derive(Debug)]
struct TrustLocation {
    root: File,
    components: Vec<std::ffi::CString>,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MutationFingerprintV1 {
    pub(crate) directory_chain: Option<Vec<FileIdentity>>,
    pub(crate) roots: Option<FileSnapshot>,
    pub(crate) policies: Option<FileSnapshot>,
    pub(crate) marker: Option<FileSnapshot>,
    pub(crate) transaction_status: crate::builder_transaction::TransactionState,
    pub(crate) marker_status: crate::builder_transaction::MarkerStatus,
    pub(crate) root_error: Option<StoreErrorKind>,
    pub(crate) policy_error: Option<StoreErrorKind>,
}

#[derive(Debug, Clone)]
pub(crate) struct BuilderMutationBaseV1 {
    pub roots: Option<RootStoreV1>,
    pub policies: Option<PolicyStoreV1>,
    pub root_generation: Option<u64>,
    pub root_digest: Option<[u8; 32]>,
    pub policy_generation: Option<u64>,
    pub policy_digest: Option<[u8; 32]>,
    pub(crate) fingerprint: MutationFingerprintV1,
}

impl BuilderMutationBaseV1 {
    #[allow(dead_code)] // Used by the privileged static library, not the read-only CLI.
    pub(crate) fn from_admin_bytes(
        roots: Option<&[u8]>,
        policies: Option<&[u8]>,
    ) -> Result<Self, StoreError> {
        let root_store = roots
            .map(parse_root_store)
            .transpose()?
            .map(|(store, _)| store);
        let policy_store = policies
            .map(parse_policy_store)
            .transpose()?
            .map(|(store, _)| store);
        Ok(Self {
            root_generation: root_store.as_ref().map(|s| s.generation),
            policy_generation: policy_store.as_ref().map(|s| s.generation),
            root_digest: roots.map(|b| Sha256::digest(b).into()),
            policy_digest: policies.map(|b| Sha256::digest(b).into()),
            roots: root_store,
            policies: policy_store,
            fingerprint: MutationFingerprintV1 {
                directory_chain: None,
                roots: None,
                policies: None,
                marker: None,
                transaction_status: crate::builder_transaction::TransactionState::NoTransaction,
                marker_status: crate::builder_transaction::MarkerStatus::Matching,
                root_error: None,
                policy_error: None,
            },
        })
    }
}

impl TrustLocation {
    fn load(&self) -> LocalTrustState {
        let Ok(root) = self.root.try_clone() else {
            return unavailable_state(StoreError::new(
                StoreErrorKind::Unavailable,
                "cannot duplicate trust root descriptor",
            ));
        };
        let components = self
            .components
            .iter()
            .map(|part| part.as_c_str())
            .collect::<Vec<_>>();
        load_state_from_root(root, &components, self.uid, self.gid)
    }
}

impl LocalTrustState {
    fn snapshot(&self) -> Option<BuilderTrustSnapshotV1> {
        if self.marker_status != crate::builder_transaction::MarkerStatus::Matching {
            return None;
        }
        let roots = self.roots.parsed.as_ref()?;
        let policies = self.policies.parsed.as_ref()?;
        let root = self.roots.snapshot.as_ref()?;
        let policy = self.policies.snapshot.as_ref()?;
        Some(BuilderTrustSnapshotV1 {
            root_generation: roots.generation,
            root_digest: root.digest,
            policy_generation: policies.generation,
            policy_digest: policy.digest,
            directory_chain: self.directory_chain.clone()?,
            root_file: root.identity.clone(),
            policy_file: policy.identity.clone(),
            marker: self.marker.clone(),
        })
    }
}

/// Concrete production provider. `production()` only reads the fixed system
/// location. Test roots are reachable only through `#[cfg(test)]` helpers.
#[derive(Debug)]
pub struct LocalBuilderVerificationProviderV1 {
    state: LocalTrustState,
    location: Option<TrustLocation>,
}

impl LocalBuilderVerificationProviderV1 {
    pub fn production() -> Self {
        let root = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open("/")
        {
            Ok(root) => root,
            Err(error) => {
                return Self {
                    state: unavailable_state(StoreError::new(
                        StoreErrorKind::Unavailable,
                        error.to_string(),
                    )),
                    location: None,
                }
            }
        };
        #[cfg(target_os = "ios")]
        let parts = ["private", "var", "lib", "ios-unsandboxed", "builder-trust"];
        #[cfg(not(target_os = "ios"))]
        let parts = ["var", "lib", "ios-unsandboxed", "builder-trust"];
        let components = parts
            .iter()
            .map(|part| std::ffi::CString::new(*part).expect("fixed path"))
            .collect::<Vec<_>>();
        let location = TrustLocation {
            root,
            components,
            uid: 0,
            gid: 0,
        };
        let state = location.load();
        Self {
            state,
            location: Some(location),
        }
    }

    pub fn snapshot(&self) -> Option<BuilderTrustSnapshotV1> {
        self.state.snapshot()
    }

    pub fn revalidate(&self) -> Result<(), StoreError> {
        let expected = self.snapshot().ok_or_else(|| {
            StoreError::new(
                StoreErrorKind::Unavailable,
                "both valid stores are required",
            )
        })?;
        let current = self
            .location
            .as_ref()
            .ok_or_else(|| {
                StoreError::new(
                    StoreErrorKind::Unavailable,
                    "trust root descriptor unavailable",
                )
            })?
            .load();
        let actual = current.snapshot().ok_or_else(|| {
            StoreError::new(StoreErrorKind::Stale, "trust snapshot became unavailable")
        })?;
        if expected != actual {
            return Err(StoreError::new(
                StoreErrorKind::Stale,
                "trust snapshot changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn mutation_base(&self) -> Result<BuilderMutationBaseV1, StoreError> {
        use crate::builder_transaction::{MarkerStatus, TransactionState};
        if self.state.transaction_status != TransactionState::NoTransaction {
            return Err(StoreError::new(
                StoreErrorKind::Pending,
                format!(
                    "builder transaction state is {}",
                    self.state.transaction_status.label()
                ),
            ));
        }
        let roots = optional_valid_store(&self.state.roots)?;
        let policies = optional_valid_store(&self.state.policies)?;
        let trust_directory_missing = self.state.directory_chain.is_none()
            && self
                .state
                .roots
                .error
                .as_ref()
                .is_some_and(|e| e.kind == StoreErrorKind::Missing)
            && self
                .state
                .policies
                .error
                .as_ref()
                .is_some_and(|e| e.kind == StoreErrorKind::Missing);
        if !matches!(
            self.state.marker_status,
            MarkerStatus::Matching | MarkerStatus::LegacyUnanchored
        ) && !trust_directory_missing
        {
            return Err(StoreError::new(
                if self.state.marker_status == MarkerStatus::Inconsistent {
                    StoreErrorKind::MarkerInconsistent
                } else {
                    StoreErrorKind::Unsafe
                },
                format!(
                    "builder generation marker state is {}",
                    self.state.marker_status.label()
                ),
            ));
        }
        let root_snapshot = self.state.roots.snapshot.as_ref();
        let policy_snapshot = self.state.policies.snapshot.as_ref();
        if roots.is_some() != root_snapshot.is_some()
            || policies.is_some() != policy_snapshot.is_some()
        {
            return Err(StoreError::new(
                StoreErrorKind::Malformed,
                "builder store parser and snapshot disagree",
            ));
        }
        Ok(BuilderMutationBaseV1 {
            roots,
            policies,
            root_generation: root_snapshot.map(|snapshot| snapshot.generation),
            root_digest: root_snapshot.map(|snapshot| snapshot.digest),
            policy_generation: policy_snapshot.map(|snapshot| snapshot.generation),
            policy_digest: policy_snapshot.map(|snapshot| snapshot.digest),
            fingerprint: mutation_fingerprint(&self.state),
        })
    }

    pub(crate) fn revalidate_mutation_base(
        &self,
        expected: &BuilderMutationBaseV1,
    ) -> Result<(), StoreError> {
        let location = self.location.as_ref().ok_or_else(|| {
            StoreError::new(
                StoreErrorKind::Unavailable,
                "trust root descriptor unavailable",
            )
        })?;
        let current = location.load();
        if current.transaction_status != crate::builder_transaction::TransactionState::NoTransaction
            || mutation_fingerprint(&current) != expected.fingerprint
        {
            return Err(StoreError::new(
                StoreErrorKind::Stale,
                "builder trust configuration changed during mutation planning",
            ));
        }
        Ok(())
    }

    pub fn status_report(&self) -> String {
        let root = self
            .state
            .root_diagnostic
            .clone()
            .unwrap_or_else(|| root_store_diagnostic(&self.state.roots));
        let policy = self
            .state
            .policy_diagnostic
            .clone()
            .unwrap_or_else(|| policy_store_diagnostic(&self.state.policies));
        let configured = self.snapshot().is_some();
        format!(
            "Builder trust provider: {}\nRoot store: {}\nPolicy store: {}\nTransaction state: {}\nBuilder trust state: {}\nCombined marker: {}\nRecovery required: {}\nIndependent trust establishment: UNVERIFIED\nRollback protection: UNVERIFIED\nBuild-origin verification: BUILD_ORIGIN_UNVERIFIED\n",
            if configured { "CONFIGURED_READ_ONLY" } else { "UNCONFIGURED_OR_UNAVAILABLE" },
            root, policy, self.state.transaction_status.label(),
            self.state.transaction_status.provider_label(), self.state.marker_status.label(),
            self.state.transaction_status.recovery_label()
        )
    }

    pub fn list_report(&self) -> String {
        let mut output = self.status_report();
        let Some(roots) = self.state.roots.parsed.as_ref() else {
            output.push_str("Signer roots: unavailable\n");
            return output;
        };
        output.push_str(&format!(
            "Signer roots (generation {}):\n",
            roots.generation
        ));
        for record in roots.keys.values() {
            let policies = self
                .state
                .policies
                .parsed
                .as_ref()
                .map(|store| {
                    store
                        .policies
                        .values()
                        .filter(|policy| policy.signer_identity == record.signer_identity)
                        .map(|policy| format!("{}:{}", policy.policy_id, policy.state))
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            output.push_str(&format!(
                "  key_id={} identity={} state={} algorithm={} policies={}\n",
                record.key_id,
                escape(&record.signer_identity),
                record.state,
                record.algorithm,
                if policies.is_empty() {
                    "NONE"
                } else {
                    &policies
                }
            ));
        }
        output
    }

    pub fn inspect_report(&self, signer_id: &str) -> String {
        let Some(roots) = self.state.roots.parsed.as_ref() else {
            return format!(
                "Signer {}: unavailable\n{}",
                escape(signer_id),
                self.status_report()
            );
        };
        let Some(record) = roots.keys.get(signer_id) else {
            return format!(
                "Signer key ID: {}\nStatus: UNKNOWN_SIGNER\n{}",
                escape(signer_id),
                self.status_report()
            );
        };
        let mut output = format!(
            "Signer key ID: {}\nSigner identity: {}\nAlgorithm: {}\nState: {}\nEnrollment reference: {}\n",
            record.key_id, escape(&record.signer_identity), record.algorithm, record.state,
            record.enrollment_reference.as_deref().map(escape).unwrap_or_else(|| "NONE".into())
        );
        match self.state.policies.parsed.as_ref() {
            Some(store) => {
                output.push_str(&format!("Policy generation: {}\n", store.generation));
                for policy in store
                    .policies
                    .values()
                    .filter(|policy| policy.signer_identity == record.signer_identity)
                {
                    let parameter_digest = serde_json::to_vec(&policy.external_parameters)
                        .map(|bytes| hex(&Sha256::digest(bytes)))
                        .unwrap_or_else(|_| "UNAVAILABLE".to_owned());
                    output.push_str(&format!(
                        "Policy: {} state={} builder={} build_type={} source={} external_parameters_sha256={} allowed_revisions={}\n",
                        policy.policy_id, policy.state, escape(&policy.builder_id),
                        escape(&policy.build_type), escape(&policy.source_uri),
                        parameter_digest,
                        policy.allowed_git_revisions.len()
                    ));
                }
            }
            None => output.push_str("Builder policies: UNAVAILABLE\n"),
        }
        output.push_str(&self.status_report());
        output
    }

    #[cfg(test)]
    pub(crate) fn from_test_root(
        root: File,
        components: &[&std::ffi::CStr],
        uid: u32,
        gid: u32,
    ) -> Self {
        let location = TrustLocation {
            root,
            components: components
                .iter()
                .map(|value| std::ffi::CString::new(value.to_bytes()).expect("validated C string"))
                .collect(),
            uid,
            gid,
        };
        let state = location.load();
        Self {
            state,
            location: Some(location),
        }
    }
}

impl BuilderVerificationProviderV1 for LocalBuilderVerificationProviderV1 {
    fn version(&self) -> u32 {
        PROVIDER_VERSION_V1
    }

    fn diagnostic_error(&self) -> Option<crate::build_attestation::AttestationError> {
        use crate::build_attestation::AttestationError as Error;
        use crate::builder_transaction::TransactionState as State;
        match self.state.marker_status {
            crate::builder_transaction::MarkerStatus::Inconsistent => {
                return Some(Error::BuilderMarkerInconsistent)
            }
            crate::builder_transaction::MarkerStatus::Unavailable
            | crate::builder_transaction::MarkerStatus::LegacyUnanchored => {
                return Some(Error::BuilderGenerationMarkerUnavailable)
            }
            crate::builder_transaction::MarkerStatus::Unsafe => {
                return Some(Error::BuilderGenerationMarkerUnavailable)
            }
            _ => {}
        }
        match self.state.transaction_status {
            State::NoTransaction => None,
            State::PreparedOldPair
            | State::FirstStoreReplaced
            | State::SecondStoreReplaced
            | State::BothStoresReplaced
            | State::CommittedPairMarkerPending
            | State::CompleteCommit => Some(Error::BuilderTransactionPending),
            State::RecoveryRequired => Some(Error::BuilderTransactionRecoveryRequired),
            State::ConflictingState => Some(Error::BuilderTrustPairInconsistent),
            State::CorruptTransaction => Some(Error::BuilderTransactionCorrupt),
            State::UnsafeTransactionArtifact => Some(Error::BuilderTransactionUnsafe),
            State::UnknownState => Some(Error::BuilderTrustSnapshotStale),
        }
    }

    fn signer(&self, key_id: &str) -> Option<SignerV1> {
        if self.diagnostic_error().is_some() {
            return None;
        }
        let record = self.state.roots.parsed.as_ref()?.keys.get(key_id)?;
        if record.state != "active" {
            return None;
        }
        Some(SignerV1 {
            identity: Some(record.signer_identity.clone()),
            algorithm: SignatureAlgorithmV1::Ed25519,
            public_key: record.public_key,
        })
    }

    fn signer_revoked(&self, key_id: &str) -> bool {
        self.state
            .roots
            .parsed
            .as_ref()
            .and_then(|roots| roots.keys.get(key_id))
            .is_some_and(|record| record.state == "revoked")
    }

    fn builder_authority(
        &self,
        signer_identity: &str,
        builder_identity: &str,
    ) -> BuilderAuthorityV1 {
        if self.diagnostic_error().is_some() {
            return BuilderAuthorityV1::Untrusted;
        }
        let Some(roots) = self.state.roots.parsed.as_ref() else {
            return BuilderAuthorityV1::Unknown;
        };
        if !roots
            .keys
            .values()
            .any(|key| key.state == "active" && key.signer_identity == signer_identity)
        {
            return BuilderAuthorityV1::Unknown;
        }
        let Some(policies) = self.state.policies.parsed.as_ref() else {
            return BuilderAuthorityV1::Untrusted;
        };
        let candidates = policies
            .policies
            .values()
            .filter(|policy| policy.signer_identity == signer_identity)
            .collect::<Vec<_>>();
        let Some(policy) = candidates
            .iter()
            .find(|policy| policy.builder_id == builder_identity)
        else {
            return if candidates.is_empty() {
                BuilderAuthorityV1::Untrusted
            } else {
                BuilderAuthorityV1::IdentityMismatch
            };
        };
        if policy.state != "active" {
            return BuilderAuthorityV1::Untrusted;
        }
        BuilderAuthorityV1::Trusted(BuilderPolicyV1 {
            builder_identity: policy.builder_id.clone(),
            build_type: policy.build_type.clone(),
            external_parameters: policy.external_parameters.clone(),
            source_uri: policy.source_uri.clone(),
            trusted_revisions: policy.allowed_git_revisions.clone(),
        })
    }

    fn policy_identity(&self, signer_identity: &str, builder_identity: &str) -> Option<String> {
        if self.diagnostic_error().is_some() {
            return None;
        }
        self.state
            .policies
            .parsed
            .as_ref()?
            .policies
            .values()
            .find(|policy| {
                policy.signer_identity == signer_identity
                    && policy.builder_id == builder_identity
                    && policy.state == "active"
            })
            .map(|policy| policy.policy_id.clone())
    }

    fn trust_snapshot(&self) -> Option<BuilderTrustSnapshotV1> {
        self.snapshot()
    }

    fn revalidate_trust_snapshot(&self) -> bool {
        self.revalidate().is_ok()
    }

    // Root-owned files and policy matching are local trust only. D2B must add
    // reviewed enrollment authentication before this can ever return true.
    fn independent_trust_established(&self) -> bool {
        false
    }
}

fn store_status<T>(store: &LoadedStore<T>) -> String {
    if store.parsed.is_some() {
        "VALID".to_owned()
    } else if let Some(error) = &store.error {
        format!("{:?}: {}", error.kind, escape(&error.message))
    } else {
        "UNAVAILABLE".to_owned()
    }
}

fn optional_valid_store<T: Clone>(store: &LoadedStore<T>) -> Result<Option<T>, StoreError> {
    if let Some(parsed) = &store.parsed {
        return Ok(Some(parsed.clone()));
    }
    match &store.error {
        Some(error) if error.kind == StoreErrorKind::Missing => Ok(None),
        Some(error) => Err(error.clone()),
        None => Err(StoreError::new(
            StoreErrorKind::Unavailable,
            "builder store has no parsed value or typed error",
        )),
    }
}

fn mutation_fingerprint(state: &LocalTrustState) -> MutationFingerprintV1 {
    MutationFingerprintV1 {
        directory_chain: state.directory_chain.clone(),
        roots: state.roots.snapshot.clone(),
        policies: state.policies.snapshot.clone(),
        marker: state.marker.clone(),
        transaction_status: state.transaction_status,
        marker_status: state.marker_status,
        root_error: state.roots.error.as_ref().map(|error| error.kind.clone()),
        policy_error: state
            .policies
            .error
            .as_ref()
            .map(|error| error.kind.clone()),
    }
}

fn root_store_diagnostic(store: &LoadedStore<RootStoreV1>) -> String {
    match (&store.parsed, &store.snapshot) {
        (Some(value), Some(snapshot)) => format!(
            "VALID generation={} keys={} sha256={}",
            value.generation,
            value.keys.len(),
            hex(&snapshot.digest)
        ),
        _ => store_status(store),
    }
}

fn policy_store_diagnostic(store: &LoadedStore<PolicyStoreV1>) -> String {
    match (&store.parsed, &store.snapshot) {
        (Some(value), Some(snapshot)) => format!(
            "VALID generation={} policies={} sha256={}",
            value.generation,
            value.policies.len(),
            hex(&snapshot.digest)
        ),
        _ => store_status(store),
    }
}

fn include_store_diagnostics(
    mut state: LocalTrustState,
    roots: &LoadedStore<RootStoreV1>,
    policies: &LoadedStore<PolicyStoreV1>,
) -> LocalTrustState {
    state.root_diagnostic = Some(root_store_diagnostic(roots));
    state.policy_diagnostic = Some(policy_store_diagnostic(policies));
    state
}

fn unavailable_state(error: StoreError) -> LocalTrustState {
    use crate::builder_transaction::TransactionState as State;
    let transaction_status = match error.kind {
        StoreErrorKind::Missing => State::NoTransaction,
        StoreErrorKind::Pending => State::RecoveryRequired,
        StoreErrorKind::TransactionCorrupt => State::CorruptTransaction,
        StoreErrorKind::Unsafe => State::UnknownState,
        _ => State::UnknownState,
    };
    let marker_status = if error.kind == StoreErrorKind::MarkerInconsistent {
        crate::builder_transaction::MarkerStatus::Inconsistent
    } else if error.kind == StoreErrorKind::Unsafe {
        crate::builder_transaction::MarkerStatus::Unsafe
    } else {
        crate::builder_transaction::MarkerStatus::Unavailable
    };
    LocalTrustState {
        roots: LoadedStore {
            parsed: None,
            snapshot: None,
            error: Some(error.clone()),
        },
        policies: LoadedStore {
            parsed: None,
            snapshot: None,
            error: Some(error),
        },
        directory_chain: None,
        marker: None,
        marker_status,
        transaction_status,
        root_diagnostic: None,
        policy_diagnostic: None,
    }
}

fn load_state_from_root(
    root: File,
    components: &[&std::ffi::CStr],
    uid: u32,
    gid: u32,
) -> LocalTrustState {
    let root_for_revalidation = match root.try_clone() {
        Ok(root) => root,
        Err(error) => {
            return unavailable_state(StoreError::new(
                StoreErrorKind::Unavailable,
                error.to_string(),
            ))
        }
    };
    let (directory, chain) = match open_trust_directory(root, components, uid, gid) {
        Ok(value) => value,
        Err(error) => return unavailable_state(error),
    };
    let entries = match check_directory_entries(&directory) {
        Ok(entries) => entries,
        Err(error) => return unavailable_state(error),
    };
    let root_store = read_store::<RootStoreV1>(&directory, ROOT_FILE, uid, gid, parse_root_store);
    let policy_store =
        read_store::<PolicyStoreV1>(&directory, POLICY_FILE, uid, gid, parse_policy_store);
    let marker_store = if entries.contains("state.v1") {
        Some(read_store(&directory, "state.v1", uid, gid, |bytes| {
            let marker = crate::builder_transaction::parse_marker(bytes)
                .map_err(|e| StoreError::new(StoreErrorKind::MarkerInconsistent, e))?;
            Ok((marker, 0))
        }))
    } else {
        None
    };
    let root_diagnostic = root_store_diagnostic(&root_store);
    let policy_diagnostic = policy_store_diagnostic(&policy_store);

    let has_transaction_artifacts = entries.contains("transaction.v1")
        || entries.contains("roots.stage.v1")
        || entries.contains("policies.stage.v1")
        || entries.contains("state.stage.v1");
    if has_transaction_artifacts {
        use crate::builder_transaction::{classify, Observation, TransactionState};
        let journal_store = entries.contains("transaction.v1").then(|| {
            read_store(&directory, "transaction.v1", uid, gid, |bytes| {
                crate::builder_transaction::parse_journal(bytes)
                    .map(|journal| (journal, 0))
                    .map_err(|error| StoreError::new(StoreErrorKind::TransactionCorrupt, error))
            })
        });
        let root_stage = entries.contains("roots.stage.v1").then(|| {
            read_store::<RootStoreV1>(&directory, "roots.stage.v1", uid, gid, parse_root_store)
        });
        let policy_stage = entries.contains("policies.stage.v1").then(|| {
            read_store::<PolicyStoreV1>(
                &directory,
                "policies.stage.v1",
                uid,
                gid,
                parse_policy_store,
            )
        });
        let mut state = classify(
            journal_store
                .as_ref()
                .map(observation_journal)
                .unwrap_or(Observation::Absent),
            observation_pair(&root_store),
            observation_pair(&policy_store),
            root_stage
                .as_ref()
                .map(observation_stage_pair)
                .unwrap_or(Observation::Absent),
            policy_stage
                .as_ref()
                .map(observation_stage_pair)
                .unwrap_or(Observation::Absent),
            marker_store
                .as_ref()
                .map(observation_marker)
                .unwrap_or(Observation::Absent),
        );
        if entries.contains("state.stage.v1") {
            let staged = read_store(&directory, "state.stage.v1", uid, gid, |bytes| {
                crate::builder_transaction::parse_marker(bytes)
                    .map(|m| (m, 0))
                    .map_err(|e| StoreError::new(StoreErrorKind::MarkerInconsistent, e))
            });
            let valid = staged
                .parsed
                .as_ref()
                .zip(journal_store.as_ref().and_then(|j| j.parsed.as_ref()))
                .is_some_and(|(m, j)| m.roots == j.new_roots && m.policies == j.new_policies);
            if !valid
                || !matches!(
                    state,
                    TransactionState::BothStoresReplaced
                        | TransactionState::CommittedPairMarkerPending
                        | TransactionState::CompleteCommit
                )
            {
                state = if staged
                    .error
                    .as_ref()
                    .is_some_and(|e| e.kind == StoreErrorKind::Unsafe)
                {
                    TransactionState::UnsafeTransactionArtifact
                } else {
                    TransactionState::ConflictingState
                };
            }
        }
        if !revalidate_directory_chain(&root_for_revalidation, components, &chain) {
            return include_store_diagnostics(
                transaction_unavailable_state(
                    TransactionState::UnknownState,
                    crate::builder_transaction::MarkerStatus::Unknown,
                    StoreErrorKind::Stale,
                    "builder trust directory changed during transaction inspection",
                ),
                &root_store,
                &policy_store,
            );
        }
        let marker_status = transaction_marker_status(marker_store.as_ref(), state);
        return include_store_diagnostics(
            transaction_unavailable_state(
                state,
                marker_status,
                match state {
                    TransactionState::CorruptTransaction => StoreErrorKind::TransactionCorrupt,
                    TransactionState::UnsafeTransactionArtifact => StoreErrorKind::Unsafe,
                    TransactionState::UnknownState => StoreErrorKind::Unavailable,
                    _ => StoreErrorKind::Pending,
                },
                state.label(),
            ),
            &root_store,
            &policy_store,
        );
    }

    let marker = match marker_store {
        Some(loaded) => {
            let Some(value) = loaded.parsed.as_ref() else {
                return include_store_diagnostics(
                    unavailable_state(loaded.error.unwrap_or_else(|| {
                        StoreError::new(StoreErrorKind::MarkerInconsistent, "marker unavailable")
                    })),
                    &root_store,
                    &policy_store,
                );
            };
            let valid = root_store
                .snapshot
                .as_ref()
                .zip(policy_store.snapshot.as_ref())
                .is_some_and(|(roots, policies)| {
                    value.roots.generation == roots.generation
                        && value.roots.digest == hex(&roots.digest)
                        && value.policies.generation == policies.generation
                        && value.policies.digest == hex(&policies.digest)
                });
            if !valid {
                return include_store_diagnostics(
                    unavailable_state(StoreError::new(
                        StoreErrorKind::MarkerInconsistent,
                        "marker does not match root/policy pair",
                    )),
                    &root_store,
                    &policy_store,
                );
            }
            loaded.snapshot
        }
        None => None,
    };
    let final_chain_ok = revalidate_directory_chain(&root_for_revalidation, components, &chain);
    let directory_chain = if final_chain_ok { Some(chain) } else { None };
    let mut state = LocalTrustState {
        roots: root_store,
        policies: policy_store,
        directory_chain,
        marker_status: if marker.is_some() {
            crate::builder_transaction::MarkerStatus::Matching
        } else {
            crate::builder_transaction::MarkerStatus::LegacyUnanchored
        },
        marker,
        transaction_status: crate::builder_transaction::TransactionState::NoTransaction,
        root_diagnostic: None,
        policy_diagnostic: None,
    };
    if state.directory_chain.is_none() {
        let stale = StoreError::new(StoreErrorKind::Stale, "trust directory changed during read");
        state.root_diagnostic = Some(root_diagnostic);
        state.policy_diagnostic = Some(policy_diagnostic);
        state.roots = LoadedStore {
            parsed: None,
            snapshot: None,
            error: Some(stale.clone()),
        };
        state.policies = LoadedStore {
            parsed: None,
            snapshot: None,
            error: Some(stale),
        };
    }
    state
}

fn observation_pair<T>(
    loaded: &LoadedStore<T>,
) -> crate::builder_transaction::Observation<crate::builder_transaction::Pair> {
    use crate::builder_transaction::{Observation, Pair};
    if let (Some(_), Some(snapshot)) = (&loaded.parsed, &loaded.snapshot) {
        return Observation::Valid(Pair {
            generation: snapshot.generation,
            digest: hex(&snapshot.digest),
        });
    }
    match loaded.error.as_ref().map(|error| &error.kind) {
        Some(StoreErrorKind::Missing) => Observation::Absent,
        Some(StoreErrorKind::Unsafe) => Observation::Unsafe,
        Some(StoreErrorKind::Unavailable | StoreErrorKind::Stale) | None => {
            Observation::Unavailable
        }
        Some(_) => Observation::Invalid,
    }
}

fn observation_stage_pair<T>(
    loaded: &LoadedStore<T>,
) -> crate::builder_transaction::Observation<crate::builder_transaction::Pair> {
    use crate::builder_transaction::Observation;
    if let (Some(_), Some(snapshot)) = (&loaded.parsed, &loaded.snapshot) {
        return Observation::Valid(crate::builder_transaction::Pair {
            generation: snapshot.generation,
            digest: hex(&snapshot.digest),
        });
    }
    match loaded.error.as_ref().map(|error| &error.kind) {
        Some(StoreErrorKind::Unsafe) => Observation::Unsafe,
        Some(StoreErrorKind::Unavailable | StoreErrorKind::Stale | StoreErrorKind::Missing)
        | None => Observation::Unavailable,
        Some(_) => Observation::Invalid,
    }
}

fn observation_journal(
    loaded: &LoadedStore<crate::builder_transaction::Journal>,
) -> crate::builder_transaction::Observation<crate::builder_transaction::Journal> {
    use crate::builder_transaction::Observation;
    if let Some(journal) = &loaded.parsed {
        return Observation::Valid(journal.clone());
    }
    match loaded.error.as_ref().map(|error| &error.kind) {
        Some(StoreErrorKind::Unsafe) => Observation::Unsafe,
        Some(StoreErrorKind::Unavailable | StoreErrorKind::Stale) | None => {
            Observation::Unavailable
        }
        Some(StoreErrorKind::Missing) => Observation::Unavailable,
        Some(_) => Observation::Invalid,
    }
}

fn observation_marker(
    loaded: &LoadedStore<crate::builder_transaction::Marker>,
) -> crate::builder_transaction::Observation<crate::builder_transaction::Marker> {
    use crate::builder_transaction::Observation;
    if let Some(marker) = &loaded.parsed {
        return Observation::Valid(marker.clone());
    }
    match loaded.error.as_ref().map(|error| &error.kind) {
        Some(StoreErrorKind::Missing) => Observation::Unavailable,
        Some(StoreErrorKind::Unsafe) => Observation::Unsafe,
        Some(StoreErrorKind::Unavailable | StoreErrorKind::Stale) | None => {
            Observation::Unavailable
        }
        Some(_) => Observation::Invalid,
    }
}

fn marker_diagnostic_status(
    loaded: &LoadedStore<crate::builder_transaction::Marker>,
) -> crate::builder_transaction::MarkerStatus {
    use crate::builder_transaction::MarkerStatus as Marker;
    match (
        &loaded.parsed,
        loaded.error.as_ref().map(|error| &error.kind),
    ) {
        (Some(_), _) => Marker::Unknown,
        (_, Some(StoreErrorKind::Unsafe)) => Marker::Unsafe,
        (_, Some(StoreErrorKind::Unavailable | StoreErrorKind::Stale)) => Marker::Unavailable,
        (_, Some(_)) => Marker::Inconsistent,
        _ => Marker::Unknown,
    }
}

fn transaction_marker_status(
    loaded: Option<&LoadedStore<crate::builder_transaction::Marker>>,
    state: crate::builder_transaction::TransactionState,
) -> crate::builder_transaction::MarkerStatus {
    use crate::builder_transaction::MarkerStatus as Marker;
    use crate::builder_transaction::TransactionState as State;
    match state {
        State::CompleteCommit => Marker::MatchingNewPair,
        State::BothStoresReplaced => Marker::OldPairPending,
        State::CommittedPairMarkerPending => Marker::MissingPending,
        State::PreparedOldPair | State::FirstStoreReplaced | State::SecondStoreReplaced => {
            if loaded.is_some_and(|store| store.parsed.is_some()) {
                Marker::MatchingOldPair
            } else {
                Marker::LegacyUnanchored
            }
        }
        _ => loaded.map_or(Marker::LegacyUnanchored, marker_diagnostic_status),
    }
}

fn transaction_unavailable_state(
    transaction_status: crate::builder_transaction::TransactionState,
    marker_status: crate::builder_transaction::MarkerStatus,
    kind: StoreErrorKind,
    message: impl Into<String>,
) -> LocalTrustState {
    let mut state = unavailable_state(StoreError::new(kind, message));
    state.transaction_status = transaction_status;
    state.marker_status = marker_status;
    state
}

fn open_trust_directory(
    root: File,
    components: &[&std::ffi::CStr],
    uid: u32,
    gid: u32,
) -> Result<(File, Vec<FileIdentity>), StoreError> {
    let mut current = root;
    let mut identities = Vec::with_capacity(components.len());
    for (index, component) in components.iter().enumerate() {
        let parent = current
            .metadata()
            .map_err(|e| StoreError::new(StoreErrorKind::Unsafe, e.to_string()))?;
        if !parent.is_dir()
            || parent.uid() != uid
            || parent.gid() != gid
            || parent.mode() & 0o022 != 0
        {
            return Err(StoreError::new(
                StoreErrorKind::Unsafe,
                "unsafe builder trust parent directory",
            ));
        }
        let child = open_child(&current, component, true)
            .map_err(|error| classify_open_error(error, "builder trust directory"))?;
        let meta = child
            .metadata()
            .map_err(|e| StoreError::new(StoreErrorKind::Unsafe, e.to_string()))?;
        if !meta.is_dir()
            || meta.uid() != uid
            || meta.gid() != gid
            || meta.mode() & 0o022 != 0
            || (index + 1 == components.len() && meta.mode() & 0o7777 != 0o700)
        {
            return Err(StoreError::new(
                StoreErrorKind::Unsafe,
                "unsafe builder trust directory metadata",
            ));
        }
        identities.push(FileIdentity::from_meta(&meta));
        current = child;
    }
    Ok((current, identities))
}

fn classify_open_error(error: String, subject: &str) -> StoreError {
    let missing = error.contains("No such file or directory");
    StoreError::new(
        if missing {
            StoreErrorKind::Missing
        } else {
            StoreErrorKind::Unsafe
        },
        format!("{subject}: {error}"),
    )
}

fn open_child(parent: &File, name: &std::ffi::CStr, directory: bool) -> Result<File, String> {
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn check_directory_entries(directory: &File) -> Result<BTreeSet<String>, StoreError> {
    let dot = std::ffi::CString::new(".").expect("dot");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(StoreError::new(
            StoreErrorKind::Unsafe,
            "cannot scan builder trust directory",
        ));
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        return Err(StoreError::new(
            StoreErrorKind::Unsafe,
            "cannot scan builder trust directory",
        ));
    }
    let mut unexpected = false;
    let mut entries = BTreeSet::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"."
            && name != b".."
            && name != ROOT_FILE.as_bytes()
            && name != POLICY_FILE.as_bytes()
            && name != b"state.v1"
            && name != b"transaction.v1"
            && name != b"roots.stage.v1"
            && name != b"policies.stage.v1"
            && name != b"state.stage.v1"
        {
            unexpected = true;
            break;
        }
        if name != b"." && name != b".." {
            entries.insert(String::from_utf8_lossy(name).into_owned());
        }
    }
    unsafe { libc::closedir(stream) };
    if unexpected {
        Err(StoreError::new(
            StoreErrorKind::Unsafe,
            "unexpected entry in builder trust directory",
        ))
    } else {
        Ok(entries)
    }
}

type StoreParser<T> = fn(&[u8]) -> Result<(T, u64), StoreError>;

fn read_store<T>(
    directory: &File,
    filename: &str,
    uid: u32,
    gid: u32,
    parser: StoreParser<T>,
) -> LoadedStore<T> {
    read_store_with_hook(directory, filename, uid, gid, parser, || {})
}

fn read_store_with_hook<T, F: FnOnce()>(
    directory: &File,
    filename: &str,
    uid: u32,
    gid: u32,
    parser: StoreParser<T>,
    after_read: F,
) -> LoadedStore<T> {
    let maximum = match filename {
        "transaction.v1" => crate::builder_transaction::MAX_JOURNAL_BYTES,
        "state.v1" | "state.stage.v1" => crate::builder_transaction::MAX_MARKER_BYTES,
        _ => MAX_STORE_BYTES,
    };
    let name = std::ffi::CString::new(filename).expect("fixed filename");
    let mut file = match open_child(directory, &name, false) {
        Ok(file) => file,
        Err(error) => {
            return LoadedStore {
                parsed: None,
                snapshot: None,
                error: Some(classify_open_error(error, filename)),
            }
        }
    };
    let before = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => return load_failure(StoreErrorKind::Unsafe, error.to_string()),
    };
    if !before.is_file()
        || before.uid() != uid
        || before.gid() != gid
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.size() > maximum as u64
    {
        return load_failure(
            StoreErrorKind::Unsafe,
            format!("unsafe {filename} metadata or size"),
        );
    }
    let mut bytes = Vec::new();
    if let Err(error) = (&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
    {
        return load_failure(StoreErrorKind::Unavailable, error.to_string());
    }
    after_read();
    let after = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => return load_failure(StoreErrorKind::Stale, error.to_string()),
    };
    let current = match open_child(directory, &name, false)
        .and_then(|entry| entry.metadata().map_err(|e| e.to_string()))
    {
        Ok(meta) => meta,
        Err(error) => {
            return LoadedStore {
                parsed: None,
                snapshot: None,
                error: Some(StoreError::new(StoreErrorKind::Stale, error)),
            }
        }
    };
    let before_id = FileIdentity::from_meta(&before);
    if bytes.len() > maximum {
        return load_failure(
            StoreErrorKind::Unsafe,
            format!("{filename} exceeds size limit"),
        );
    }
    if before_id != FileIdentity::from_meta(&after)
        || before_id != FileIdentity::from_meta(&current)
        || bytes.len() as u64 != before.size()
    {
        return load_failure(
            StoreErrorKind::Stale,
            format!("{filename} changed during read"),
        );
    }
    let (parsed, generation) = match parser(&bytes) {
        Ok(value) => value,
        Err(error) => {
            return LoadedStore {
                parsed: None,
                snapshot: None,
                error: Some(error),
            }
        }
    };
    let snapshot = FileSnapshot {
        identity: before_id,
        digest: Sha256::digest(&bytes).into(),
        generation,
    };
    LoadedStore {
        parsed: Some(parsed),
        snapshot: Some(snapshot),
        error: None,
    }
}

fn load_failure<T>(kind: StoreErrorKind, message: impl Into<String>) -> LoadedStore<T> {
    LoadedStore {
        parsed: None,
        snapshot: None,
        error: Some(StoreError::new(kind, message)),
    }
}

fn revalidate_directory_chain(
    root: &File,
    components: &[&std::ffi::CStr],
    expected: &[FileIdentity],
) -> bool {
    if components.len() != expected.len() {
        return false;
    }
    let mut current = match root.try_clone() {
        Ok(file) => file,
        Err(_) => return false,
    };
    for (index, component) in components.iter().enumerate() {
        let Ok(child) = open_child(&current, component, true) else {
            return false;
        };
        let Ok(meta) = child.metadata() else {
            return false;
        };
        if FileIdentity::from_meta(&meta) != expected[index] {
            return false;
        }
        current = child;
    }
    true
}

pub(crate) fn parse_root_store(bytes: &[u8]) -> Result<(RootStoreV1, u64), StoreError> {
    let value = parse_canonical(bytes)?;
    let object = strict_object(
        &value,
        &["schemaVersion", "generation", "keyCount", "keys"],
        &[],
    )?;
    ensure_version(object, "schemaVersion", ROOT_STORE_SCHEMA_V1.into())?;
    let generation = number(object, "generation")?;
    let records = array(object, "keys", MAX_SIGNING_KEYS)?;
    if number(object, "keyCount")? != records.len() as u64 {
        return Err(malformed("keyCount does not match keys length"));
    }
    let mut keys = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut previous: Option<String> = None;
    for item in records {
        let item = item
            .as_object()
            .ok_or_else(|| malformed("key record must be an object"))?;
        exact_fields(
            item,
            &["algorithm", "keyId", "publicKey", "signerIdentity", "state"],
            &["enrollmentReference"],
        )?;
        let algorithm = string(item, "algorithm", 32)?;
        if algorithm != "Ed25519" {
            return Err(StoreError::new(
                StoreErrorKind::Unsupported,
                "unsupported builder signer algorithm",
            ));
        }
        let key_id = string(item, "keyId", 32)?;
        if !lower_hex(&key_id, 32) {
            return Err(malformed(
                "keyId must be 32 lowercase hexadecimal characters",
            ));
        }
        let key_text = string(item, "publicKey", 64)?;
        if !lower_hex(&key_text, 64) {
            return Err(malformed("publicKey must be lowercase hexadecimal"));
        }
        let public_key =
            decode_hex::<32>(&key_text).ok_or_else(|| malformed("invalid Ed25519 public key"))?;
        validate_ed25519_key(&public_key)?;
        if derive_key_id(&public_key) != key_id {
            return Err(malformed("keyId does not match publicKey"));
        }
        if previous.as_ref().is_some_and(|prev| prev >= &key_id) {
            return Err(malformed(
                "key records must be sorted by keyId without duplicates",
            ));
        }
        previous = Some(key_id.clone());
        let signer_identity =
            checked_identity(string(item, "signerIdentity", MAX_IDENTITY_BYTES)?)?;
        if !identities.insert(signer_identity.clone()) {
            return Err(malformed("signer identities must be unique"));
        }
        let state = string(item, "state", 16)?;
        if state != "active" && state != "revoked" {
            return Err(malformed("key state must be active or revoked"));
        }
        let enrollment_reference = item
            .get("enrollmentReference")
            .map(|value| {
                value
                    .as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 512 && !has_control(s))
                    .map(str::to_owned)
                    .ok_or_else(|| malformed("invalid enrollmentReference"))
            })
            .transpose()?;
        keys.insert(
            key_id.clone(),
            RootRecordV1 {
                key_id,
                algorithm,
                public_key,
                signer_identity,
                state,
                enrollment_reference,
            },
        );
    }
    Ok((RootStoreV1 { generation, keys }, generation))
}

pub(crate) fn parse_policy_store(bytes: &[u8]) -> Result<(PolicyStoreV1, u64), StoreError> {
    let value = parse_canonical(bytes)?;
    let object = strict_object(&value, &["schemaVersion", "generation", "policies"], &[])?;
    ensure_version(object, "schemaVersion", POLICY_STORE_SCHEMA_V1.into())?;
    let generation = number(object, "generation")?;
    let records = array(object, "policies", MAX_POLICIES)?;
    let mut policies = BTreeMap::new();
    let mut pairs = BTreeSet::new();
    let mut previous: Option<String> = None;
    for item in records {
        let item = item
            .as_object()
            .ok_or_else(|| malformed("policy record must be an object"))?;
        exact_fields(
            item,
            &[
                "allowedGitRevisions",
                "builderId",
                "buildType",
                "externalParameters",
                "policyId",
                "signerIdentity",
                "sourceUri",
                "state",
                "version",
            ],
            &[],
        )?;
        let policy_id = string(item, "policyId", 64)?;
        if !lower_hex(&policy_id, 64) {
            return Err(malformed(
                "policyId must be 64 lowercase hexadecimal characters",
            ));
        }
        if previous.as_ref().is_some_and(|prev| prev >= &policy_id) {
            return Err(malformed(
                "policies must be sorted by policyId without duplicates",
            ));
        }
        previous = Some(policy_id.clone());
        let version = u32::try_from(number(item, "version")?)
            .map_err(|_| malformed("invalid policy version"))?;
        if version != 1 {
            return Err(StoreError::new(
                StoreErrorKind::Unsupported,
                "unsupported builder policy version",
            ));
        }
        let state = string(item, "state", 16)?;
        if state != "active" && state != "revoked" {
            return Err(malformed("policy state must be active or revoked"));
        }
        let signer_identity =
            checked_identity(string(item, "signerIdentity", MAX_IDENTITY_BYTES)?)?;
        let builder_id = checked_identity(string(item, "builderId", MAX_IDENTITY_BYTES)?)?;
        if builder_id.contains('*') {
            return Err(malformed("wildcard builder IDs are unsupported"));
        }
        let build_type = checked_uri(string(item, "buildType", MAX_URI_BYTES)?)?;
        let source_uri = checked_uri(string(item, "sourceUri", MAX_URI_BYTES)?)?;
        if source_uri.contains('*') {
            return Err(malformed("wildcard source URIs are unsupported"));
        }
        let external_parameters = item
            .get("externalParameters")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| malformed("externalParameters must be an object"))?;
        let revisions = array(item, "allowedGitRevisions", 64)?;
        if revisions.is_empty() {
            return Err(malformed("at least one exact Git revision is required"));
        }
        let mut allowed_git_revisions = BTreeSet::new();
        let mut last_revision: Option<String> = None;
        for revision in revisions {
            let revision = revision
                .as_str()
                .ok_or_else(|| malformed("revision must be a string"))?
                .to_owned();
            if !valid_revision(&revision)
                || last_revision.as_ref().is_some_and(|prev| prev >= &revision)
            {
                return Err(malformed(
                    "revisions must be unique, sorted, full lowercase Git object IDs",
                ));
            }
            last_revision = Some(revision.clone());
            allowed_git_revisions.insert(revision);
        }
        if !pairs.insert((signer_identity.clone(), builder_id.clone())) {
            return Err(malformed("duplicate signer/builder policies"));
        }
        let record = PolicyRecordV1 {
            policy_id: policy_id.clone(),
            version,
            state,
            signer_identity,
            builder_id,
            build_type,
            external_parameters,
            source_uri,
            allowed_git_revisions,
        };
        if derive_policy_id(&record)? != policy_id {
            return Err(malformed(
                "policyId does not match canonical policy contents",
            ));
        }
        policies.insert(policy_id, record);
    }
    Ok((
        PolicyStoreV1 {
            generation,
            policies,
        },
        generation,
    ))
}

pub(crate) fn parse_canonical(bytes: &[u8]) -> Result<Value, StoreError> {
    if bytes.len() > MAX_STORE_BYTES {
        return Err(StoreError::new(
            StoreErrorKind::Unsafe,
            "store exceeds 64 KiB",
        ));
    }
    let value = crate::build_attestation::parse_bounded_json(bytes, 4096)
        .map_err(|e| malformed(format!("invalid or duplicate JSON field: {e}")))?;
    if serde_json::to_vec(&value).map_err(|e| malformed(e.to_string()))? != bytes {
        return Err(malformed(
            "store JSON is not canonical compact sorted-key encoding",
        ));
    }
    Ok(value)
}

pub(crate) fn derive_policy_id(policy: &PolicyRecordV1) -> Result<String, StoreError> {
    let mut value = Map::new();
    value.insert(
        "allowedGitRevisions".into(),
        Value::Array(
            policy
                .allowed_git_revisions
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    value.insert("builderId".into(), Value::String(policy.builder_id.clone()));
    value.insert("buildType".into(), Value::String(policy.build_type.clone()));
    value.insert(
        "externalParameters".into(),
        policy.external_parameters.clone(),
    );
    value.insert(
        "signerIdentity".into(),
        Value::String(policy.signer_identity.clone()),
    );
    value.insert("sourceUri".into(), Value::String(policy.source_uri.clone()));
    value.insert("state".into(), Value::String(policy.state.clone()));
    value.insert("version".into(), Value::Number(policy.version.into()));
    let bytes = serde_json::to_vec(&Value::Object(value)).map_err(|e| malformed(e.to_string()))?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn strict_object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, StoreError> {
    let object = value
        .as_object()
        .ok_or_else(|| malformed("store root must be an object"))?;
    exact_fields(object, required, optional)?;
    Ok(object)
}

fn exact_fields(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), StoreError> {
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(malformed("missing or unknown schema field"));
    }
    Ok(())
}

fn ensure_version(
    object: &Map<String, Value>,
    field: &str,
    expected: u64,
) -> Result<(), StoreError> {
    if number(object, field)? != expected {
        return Err(StoreError::new(
            StoreErrorKind::Unsupported,
            format!("unsupported {field}"),
        ));
    }
    Ok(())
}

fn number(object: &Map<String, Value>, field: &str) -> Result<u64, StoreError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(format!("{field} must be an unsigned integer")))
}
fn array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a [Value], StoreError> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(format!("{field} must be an array")))?;
    if values.len() > maximum {
        return Err(StoreError::new(
            StoreErrorKind::Unsafe,
            format!("{field} exceeds count limit"),
        ));
    }
    Ok(values)
}
fn string(object: &Map<String, Value>, field: &str, maximum: usize) -> Result<String, StoreError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum && !has_control(value))
        .map(str::to_owned)
        .ok_or_else(|| malformed(format!("invalid {field}")))
}
pub(crate) fn checked_identity(value: String) -> Result<String, StoreError> {
    if value.len() > MAX_IDENTITY_BYTES
        || value.trim() != value
        || has_control(&value)
        || value.contains('*')
    {
        Err(malformed("invalid exact identity"))
    } else {
        Ok(value)
    }
}
pub(crate) fn checked_uri(value: String) -> Result<String, StoreError> {
    if value.len() > MAX_URI_BYTES
        || !(value.starts_with("https://") || value.starts_with("git+https://"))
        || value.contains('*')
    {
        Err(malformed("URI must be an exact HTTPS or git+HTTPS URI"))
    } else {
        Ok(value)
    }
}
fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}
pub(crate) fn valid_revision(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && lower_hex(value, value.len())
}
pub(crate) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !lower_hex(value, N * 2) {
        return None;
    }
    let mut out = [0; N];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Some(out)
}
pub(crate) fn validate_ed25519_key(key: &[u8; 32]) -> Result<(), StoreError> {
    // Compressed Edwards Y must be the canonical representative below 2^255-19.
    // dalek accepts some noncanonical encodings for verification compatibility;
    // enrollment and canonical stores deliberately use the stricter profile.
    let mut y = *key;
    y[31] &= 0x7f;
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    if y.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less {
        return Err(malformed("publicKey has noncanonical Edwards Y"));
    }
    let point = ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| malformed("publicKey is not a valid Ed25519 point"))?;
    if point.is_weak() {
        return Err(malformed("weak small-order Ed25519 public key"));
    }
    Ok(())
}

pub(crate) fn derive_key_id(key: &[u8; 32]) -> String {
    hex(&Sha256::digest(key)[..16])
}
fn malformed(message: impl Into<String>) -> StoreError {
    StoreError::new(StoreErrorKind::Malformed, message)
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn escape(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_control() {
                format!("\\u{{{:04x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempTree(std::path::PathBuf);

    impl TempTree {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "iu-builder-trust-{label}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn trust_dir(&self) -> std::path::PathBuf {
            let path = self.0.join("builder-trust");
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        fn provider(&self) -> LocalBuilderVerificationProviderV1 {
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&self.0)
                .unwrap();
            let name = std::ffi::CString::new("builder-trust").unwrap();
            LocalBuilderVerificationProviderV1::from_test_root(
                root,
                &[name.as_c_str()],
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
            )
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_store(path: &std::path::Path, name: &str, bytes: &[u8]) {
        std::fs::write(path.join(name), bytes).unwrap();
        std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
        if [ROOT_FILE, POLICY_FILE].contains(&name)
            && !path.join("transaction.v1").exists()
            && !path.join("roots.stage.v1").exists()
            && !path.join("policies.stage.v1").exists()
        {
            if let (Ok(r), Ok(p)) = (
                std::fs::read(path.join(ROOT_FILE)),
                std::fs::read(path.join(POLICY_FILE)),
            ) {
                if let (Ok((_, rg)), Ok((_, pg))) = (parse_root_store(&r), parse_policy_store(&p)) {
                    let marker = crate::builder_mutation::marker_bytes(
                        rg,
                        &hex(&Sha256::digest(r)),
                        pg,
                        &hex(&Sha256::digest(p)),
                    );
                    std::fs::write(path.join("state.v1"), marker).unwrap();
                    std::fs::set_permissions(
                        path.join("state.v1"),
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
            }
        }
    }

    fn root_json(key: &[u8; 32], identity: &str, state: &str) -> Vec<u8> {
        root_json_with_generation(key, identity, state, 3)
    }

    fn root_json_with_generation(
        key: &[u8; 32],
        identity: &str,
        state: &str,
        generation: u64,
    ) -> Vec<u8> {
        let record = serde_json::json!({"algorithm":"Ed25519","keyId":derive_key_id(key),"publicKey":hex(key),"signerIdentity":identity,"state":state});
        serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"generation":generation,"keyCount":1,"keys":[record]}),
        )
        .unwrap()
    }

    fn policy_json(key_id: &str, identity: &str) -> Vec<u8> {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let mut record = PolicyRecordV1 {
            policy_id: String::new(),
            version: 1,
            state: "active".into(),
            signer_identity: identity.into(),
            builder_id: "https://ci.example.invalid/builders/release-v1".into(),
            build_type: "https://ci.example.invalid/buildtypes/ios-v1".into(),
            external_parameters: serde_json::json!({"repository":"https://example.invalid/acme/app","revision":revision}),
            source_uri: "git+https://example.invalid/acme/app".into(),
            allowed_git_revisions: [revision.to_owned()].into_iter().collect(),
        };
        let _ = key_id;
        record.policy_id = derive_policy_id(&record).unwrap();
        let value = serde_json::json!({"schemaVersion":1,"generation":8,"policies":[{
            "allowedGitRevisions":[revision],"builderId":record.builder_id,"buildType":record.build_type,
            "externalParameters":record.external_parameters,"policyId":record.policy_id,
            "signerIdentity":record.signer_identity,"sourceUri":record.source_uri,"state":record.state,"version":1
        }]});
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn canonical_roots_and_policy_bind_exact_identity_and_revisions() {
        let key = SigningKey::from_bytes(&[0x31; 32])
            .verifying_key()
            .to_bytes();
        let roots = parse_root_store(&root_json(&key, "ci-prod", "active"))
            .unwrap()
            .0;
        assert_eq!(
            roots
                .keys
                .get(&derive_key_id(&key))
                .unwrap()
                .signer_identity,
            "ci-prod"
        );
        let policy = parse_policy_store(&policy_json(&derive_key_id(&key), "ci-prod"))
            .unwrap()
            .0;
        assert_eq!(policy.policies.len(), 1);
        assert_eq!(
            policy
                .policies
                .values()
                .next()
                .unwrap()
                .allowed_git_revisions
                .len(),
            1
        );
        let empty = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "generation": 0,
            "keyCount": 0,
            "keys": []
        }))
        .unwrap();
        assert!(parse_root_store(&empty).unwrap().0.keys.is_empty());
    }

    #[test]
    fn duplicate_fields_noncanonical_order_and_key_identity_mismatch_fail() {
        assert!(parse_root_store(
            br#"{"schemaVersion":1,"schemaVersion":1,"generation":0,"keyCount":0,"keys":[]}"#
        )
        .is_err());
        assert!(
            parse_root_store(br#"{ "generation":0,"keyCount":0,"keys":[],"schemaVersion":1}"#)
                .is_err()
        );
        let key = [1; 32];
        let wrong = serde_json::json!({"schemaVersion":1,"generation":0,"keyCount":1,"keys":[{"algorithm":"Ed25519","keyId":"00000000000000000000000000000000","publicKey":hex(&key),"signerIdentity":"ci","state":"active"}]});
        assert!(parse_root_store(&serde_json::to_vec(&wrong).unwrap()).is_err());
    }

    #[test]
    fn roots_reject_duplicate_identities_and_excess_key_count() {
        let first = SigningKey::from_bytes(&[0x11; 32])
            .verifying_key()
            .to_bytes();
        let second = SigningKey::from_bytes(&[0x12; 32])
            .verifying_key()
            .to_bytes();
        let mut records = vec![
            serde_json::json!({"algorithm":"Ed25519","keyId":derive_key_id(&first),"publicKey":hex(&first),"signerIdentity":"same-ci","state":"active"}),
            serde_json::json!({"algorithm":"Ed25519","keyId":derive_key_id(&second),"publicKey":hex(&second),"signerIdentity":"same-ci","state":"active"}),
        ];
        records.sort_by_key(|record| record["keyId"].as_str().unwrap().to_owned());
        let duplicate_identity = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"generation":1,"keyCount":records.len(),"keys":records}),
        )
        .unwrap();
        assert!(parse_root_store(&duplicate_identity).is_err());

        let mut too_many = Vec::new();
        for index in 0..=MAX_SIGNING_KEYS {
            let seed = [index as u8; 32];
            let key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            too_many.push(serde_json::json!({"algorithm":"Ed25519","keyId":derive_key_id(&key),"publicKey":hex(&key),"signerIdentity":format!("ci-{index}"),"state":"active"}));
        }
        too_many.sort_by_key(|record| record["keyId"].as_str().unwrap().to_owned());
        let too_many = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"generation":1,"keyCount":too_many.len(),"keys":too_many}),
        )
        .unwrap();
        assert!(parse_root_store(&too_many).is_err());
    }

    #[test]
    fn provider_rejects_revoked_signers_and_reports_unknown_without_publisher_fallback() {
        let signing = SigningKey::from_bytes(&[0x42; 32]);
        let identity = "independent-ci";
        let mut provider = LocalBuilderVerificationProviderV1 {
            state: unavailable_state(StoreError::new(StoreErrorKind::Missing, "fixture")),
            location: None,
        };
        let roots = parse_root_store(&root_json(
            &signing.verifying_key().to_bytes(),
            identity,
            "revoked",
        ))
        .unwrap()
        .0;
        provider.state.roots.parsed = Some(roots);
        assert!(provider
            .signer(&derive_key_id(&signing.verifying_key().to_bytes()))
            .is_none());
        assert!(provider.signer_revoked(&derive_key_id(&signing.verifying_key().to_bytes())));
        assert!(provider.signer("publisher-key-id").is_none());
        assert!(!provider.independent_trust_established());
    }

    #[test]
    fn local_provider_verifies_real_dsse_but_never_claims_independent_enrollment() {
        let tree = TempTree::new("ed25519");
        let directory = tree.trust_dir();
        let signing = SigningKey::from_bytes(&[0x63; 32]);
        let public = signing.verifying_key().to_bytes();
        let key_id = derive_key_id(&public);
        let identity = "independent-ci-release";
        write_store(
            &directory,
            ROOT_FILE,
            &root_json(&public, identity, "active"),
        );
        write_store(&directory, POLICY_FILE, &policy_json(&key_id, identity));
        let provider = tree.provider();
        let digest = hex(&Sha256::digest(b"opened descriptor artifact"));
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let statement = serde_json::json!({
            "_type":"https://in-toto.io/Statement/v1",
            "subject":[{"name":"artifact","digest":{"sha256":digest}}],
            "predicateType":"https://slsa.dev/provenance/v1",
            "predicate":{"buildDefinition":{
                "buildType":"https://ci.example.invalid/buildtypes/ios-v1",
                "externalParameters":{"repository":"https://example.invalid/acme/app","revision":revision},
                "resolvedDependencies":[{"uri":"git+https://example.invalid/acme/app","digest":{"gitCommit":revision}}]
            },"runDetails":{"builder":{"id":"https://ci.example.invalid/builders/release-v1"}}}
        });
        let payload = serde_json::to_vec(&statement).unwrap();
        let payload_type = crate::build_attestation::DSSE_PAYLOAD_TYPE.as_bytes();
        let mut pae = b"DSSEv1 ".to_vec();
        pae.extend_from_slice(payload_type.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(payload_type);
        pae.push(b' ');
        pae.extend_from_slice(payload.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(&payload);
        let envelope = serde_json::to_vec(&serde_json::json!({
            "payloadType":crate::build_attestation::DSSE_PAYLOAD_TYPE,
            "payload":base64::engine::general_purpose::STANDARD.encode(&payload),
            "signatures":[{"keyid":key_id,"sig":base64::engine::general_purpose::STANDARD.encode(signing.sign(&pae).to_bytes())}]
        })).unwrap();
        let artifact_digest: [u8; 32] = Sha256::digest(b"opened descriptor artifact").into();
        let result = crate::build_attestation::verify_bytes(&envelope, &artifact_digest, &provider);
        assert_eq!(
            result.signature,
            crate::build_attestation::SignatureStatus::Valid
        );
        assert_eq!(
            result.signer_identity,
            crate::build_attestation::SignerIdentityStatus::Verified
        );
        assert_eq!(
            result.builder_trust,
            crate::build_attestation::BuilderTrustStatus::Trusted
        );
        assert_eq!(
            result.build_parameters,
            crate::build_attestation::BuildParametersStatus::Accepted
        );
        assert_eq!(
            result.trust_snapshot_status,
            crate::build_attestation::TrustSnapshotStatus::Consistent
        );
        assert_eq!(
            result.signer_key_id.as_deref(),
            Some(derive_key_id(&public).as_str())
        );
        assert!(result.applicable_policy_identity.is_some());
        assert_eq!(
            result.independent_trust_establishment,
            crate::build_attestation::TrustEstablishmentStatus::Unverified
        );
        assert_eq!(
            result.build_origin,
            crate::build_attestation::BuildOriginStatus::Unverified
        );
        assert!(!provider.independent_trust_established());

        // The same key is unknown to builder trust unless it is present in
        // roots.v1; a matching publisher key ID is never an implicit fallback.
        let empty_tree = TempTree::new("publisher-is-not-builder");
        let empty_directory = empty_tree.trust_dir();
        write_store(
            &empty_directory,
            ROOT_FILE,
            &serde_json::to_vec(&serde_json::json!({
                "schemaVersion":1,"generation":1,"keyCount":0,"keys":[]
            }))
            .unwrap(),
        );
        write_store(
            &empty_directory,
            POLICY_FILE,
            &serde_json::to_vec(&serde_json::json!({
                "schemaVersion":1,"generation":1,"policies":[]
            }))
            .unwrap(),
        );
        let empty_provider = empty_tree.provider();
        let publisher_key_unknown_to_builder =
            crate::build_attestation::verify_bytes(&envelope, &artifact_digest, &empty_provider);
        assert_eq!(
            publisher_key_unknown_to_builder.signature,
            crate::build_attestation::SignatureStatus::UnknownSigner
        );
    }

    #[test]
    fn missing_policy_keeps_recognized_signer_untrusted_and_snapshot_mutations_go_stale() {
        let tree = TempTree::new("missing-policy");
        let directory = tree.trust_dir();
        let signing = SigningKey::from_bytes(&[0x64; 32]);
        let public = signing.verifying_key().to_bytes();
        write_store(
            &directory,
            ROOT_FILE,
            &root_json(&public, "signer-a", "active"),
        );
        let provider = tree.provider();
        assert!(provider.signer(&derive_key_id(&public)).is_none());
        assert!(matches!(
            provider.builder_authority("signer-a", "builder-a"),
            BuilderAuthorityV1::Untrusted
        ));
        assert!(provider.snapshot().is_none());
        write_store(
            &directory,
            POLICY_FILE,
            &serde_json::to_vec(
                &serde_json::json!({"schemaVersion":1,"generation":1,"policies":[]}),
            )
            .unwrap(),
        );
        let configured = tree.provider();
        assert!(configured.snapshot().is_some());
        assert!(configured.revalidate().is_ok());
        let original_root: Value =
            serde_json::from_slice(&std::fs::read(directory.join(ROOT_FILE)).unwrap()).unwrap();
        let mut next_root = original_root.clone();
        next_root["generation"] = serde_json::json!(4);
        write_store(
            &directory,
            ROOT_FILE,
            &serde_json::to_vec(&next_root).unwrap(),
        );
        assert_eq!(
            configured.revalidate().unwrap_err().kind,
            StoreErrorKind::Stale
        );
        write_store(
            &directory,
            ROOT_FILE,
            &serde_json::to_vec(&original_root).unwrap(),
        );
        let configured = tree.provider();
        let changed = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"generation":2,"policies":[]}),
        )
        .unwrap();
        write_store(&directory, POLICY_FILE, &changed);
        assert_eq!(
            configured.revalidate().unwrap_err().kind,
            StoreErrorKind::Stale
        );
    }

    #[test]
    fn secure_reader_rejects_symlinks_hardlinks_unsafe_modes_and_oversized_files() {
        let tree = TempTree::new("unsafe");
        let directory = tree.trust_dir();
        let signing = SigningKey::from_bytes(&[0x65; 32]);
        write_store(
            &directory,
            ROOT_FILE,
            &root_json(&signing.verifying_key().to_bytes(), "signer", "active"),
        );
        write_store(
            &directory,
            POLICY_FILE,
            &serde_json::to_vec(
                &serde_json::json!({"schemaVersion":1,"generation":1,"policies":[]}),
            )
            .unwrap(),
        );
        let valid = tree.provider();
        assert!(valid.snapshot().is_some());
        std::fs::remove_file(directory.join(ROOT_FILE)).unwrap();
        let outside = tree.0.join("outside");
        std::fs::write(
            &outside,
            root_json(&signing.verifying_key().to_bytes(), "signer", "active"),
        )
        .unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&outside, directory.join(ROOT_FILE)).unwrap();
        assert!(tree.provider().state.roots.parsed.is_none());
        std::fs::remove_file(directory.join(ROOT_FILE)).unwrap();
        std::fs::hard_link(&outside, directory.join(ROOT_FILE)).unwrap();
        assert!(tree.provider().state.roots.parsed.is_none());
        std::fs::remove_file(directory.join(ROOT_FILE)).unwrap();
        write_store(&directory, ROOT_FILE, &vec![b' '; MAX_STORE_BYTES + 1]);
        assert!(tree.provider().state.roots.parsed.is_none());
        write_store(
            &directory,
            ROOT_FILE,
            &root_json(&signing.verifying_key().to_bytes(), "signer", "active"),
        );
        std::fs::set_permissions(
            directory.join(ROOT_FILE),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(tree.provider().state.roots.parsed.is_none());
    }

    #[test]
    fn secure_reader_rejects_symlinked_trust_directory_and_unexpected_entries() {
        let tree = TempTree::new("symlink-dir");
        let real = tree.0.join("real-trust");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&tree.0)
            .unwrap();
        let name = std::ffi::CString::new("builder-trust").unwrap();
        std::os::unix::fs::symlink(&real, tree.0.join("builder-trust")).unwrap();
        let provider = LocalBuilderVerificationProviderV1::from_test_root(
            root.try_clone().unwrap(),
            &[name.as_c_str()],
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        );
        assert!(provider.snapshot().is_none());
        std::fs::remove_file(tree.0.join("builder-trust")).unwrap();
        std::fs::rename(&real, tree.0.join("builder-trust")).unwrap();
        std::fs::write(tree.0.join("builder-trust/unexpected.tmp"), b"x").unwrap();
        let provider = LocalBuilderVerificationProviderV1::from_test_root(
            root,
            &[name.as_c_str()],
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        );
        assert!(provider.snapshot().is_none());
    }

    #[test]
    fn unsafe_journal_links_and_modes_are_classified_and_never_trusted() {
        let tree = TempTree::new("unsafe-transaction-artifact");
        let directory = tree.trust_dir();
        let key = SigningKey::from_bytes(&[0x7a; 32])
            .verifying_key()
            .to_bytes();
        write_store(&directory, ROOT_FILE, &root_json(&key, "signer", "active"));
        write_store(
            &directory,
            POLICY_FILE,
            &serde_json::to_vec(
                &serde_json::json!({"schemaVersion":1,"generation":1,"policies":[]}),
            )
            .unwrap(),
        );
        let target = tree.0.join("journal-target");
        std::fs::write(
            &target,
            include_bytes!("../../tests/builder-trust/valid-transaction.v1"),
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::os::unix::fs::symlink(&target, directory.join("transaction.v1")).unwrap();
        let symlink = tree.provider();
        assert!(symlink
            .status_report()
            .contains("Transaction state: UNSAFE_TRANSACTION_ARTIFACT"));
        assert!(symlink.signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("transaction.v1")).unwrap();

        std::fs::hard_link(&target, directory.join("transaction.v1")).unwrap();
        let hard_link = tree.provider();
        assert!(hard_link
            .status_report()
            .contains("Transaction state: UNSAFE_TRANSACTION_ARTIFACT"));
        assert!(hard_link.signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("transaction.v1")).unwrap();

        write_store(
            &directory,
            "transaction.v1",
            include_bytes!("../../tests/builder-trust/valid-transaction.v1"),
        );
        std::fs::set_permissions(
            directory.join("transaction.v1"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let unsafe_mode = tree.provider();
        assert!(unsafe_mode
            .status_report()
            .contains("Transaction state: UNSAFE_TRANSACTION_ARTIFACT"));
        assert!(unsafe_mode.signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("transaction.v1")).unwrap();

        write_store(&directory, "transaction.v1", &vec![b'x'; 1025]);
        let oversized = tree.provider();
        assert!(oversized
            .status_report()
            .contains("Transaction state: UNSAFE_TRANSACTION_ARTIFACT"));
        assert!(oversized.signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("transaction.v1")).unwrap();

        write_store(&directory, "state.v1", &vec![b'x'; 513]);
        let oversized_marker = tree.provider();
        assert!(oversized_marker
            .status_report()
            .contains("Combined marker: UNSAFE"));
        assert!(oversized_marker.signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("state.v1")).unwrap();

        let roots = root_json(&key, "signer", "active");
        let policies = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"generation":1,"policies":[]}),
        )
        .unwrap();
        let marker = format!(
            "ios-unsandboxed-builder-state\nschema_version=1\nroot_generation=3\nroot_sha256={}\npolicy_generation=1\npolicy_sha256={}\n",
            hex(&Sha256::digest(&roots)),
            hex(&Sha256::digest(&policies)),
        );
        std::fs::write(&target, marker.as_bytes()).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, directory.join("state.v1")).unwrap();
        let marker_symlink = tree.provider();
        assert!(marker_symlink
            .status_report()
            .contains("Combined marker: UNSAFE"));
        assert!(marker_symlink.signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("state.v1")).unwrap();
        std::fs::hard_link(&target, directory.join("state.v1")).unwrap();
        let marker_hardlink = tree.provider();
        assert!(marker_hardlink
            .status_report()
            .contains("Combined marker: UNSAFE"));
        assert!(marker_hardlink.signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("state.v1")).unwrap();
        write_store(&directory, "state.v1", marker.as_bytes());
        std::fs::set_permissions(
            directory.join("state.v1"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let marker_mode = tree.provider();
        assert!(marker_mode
            .status_report()
            .contains("Combined marker: UNSAFE"));
        assert!(marker_mode.signer(&derive_key_id(&key)).is_none());
    }

    #[test]
    fn directory_replacement_invalidates_transaction_reader_identity() {
        let tree = TempTree::new("replace-transaction-directory");
        let trust = tree.trust_dir();
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&tree.0)
            .unwrap();
        let component = std::ffi::CString::new("builder-trust").unwrap();
        let (opened, chain) = open_trust_directory(
            root.try_clone().unwrap(),
            &[component.as_c_str()],
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        )
        .unwrap();
        assert!(opened.metadata().unwrap().is_dir());
        let moved = tree.0.join("builder-trust-old");
        std::fs::rename(&trust, &moved).unwrap();
        std::fs::create_dir(&trust).unwrap();
        std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!revalidate_directory_chain(
            &root,
            &[component.as_c_str()],
            &chain
        ));
    }

    #[test]
    fn replacement_during_a_store_read_is_detected() {
        let tree = TempTree::new("replace-during-read");
        let directory_path = tree.trust_dir();
        let signing = SigningKey::from_bytes(&[0x66; 32]);
        let contents = root_json(&signing.verifying_key().to_bytes(), "signer", "active");
        write_store(&directory_path, ROOT_FILE, &contents);
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory_path)
            .unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let result =
            read_store_with_hook(&directory, ROOT_FILE, uid, gid, parse_root_store, || {
                let replacement = directory_path.join("replacement");
                std::fs::write(&replacement, &contents).unwrap();
                std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                std::fs::rename(replacement, directory_path.join(ROOT_FILE)).unwrap();
            });
        assert_eq!(result.error.unwrap().kind, StoreErrorKind::Stale);
    }

    #[test]
    fn transaction_artifacts_and_marker_fail_closed_without_writes() {
        let tree = TempTree::new("transaction-marker");
        let directory = tree.trust_dir();
        let key = SigningKey::from_bytes(&[0x67; 32])
            .verifying_key()
            .to_bytes();
        let roots = root_json(&key, "builder-signer", "active");
        let policies = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"generation":1,"policies":[]}),
        )
        .unwrap();
        write_store(&directory, ROOT_FILE, &roots);
        write_store(&directory, POLICY_FILE, &policies);
        std::fs::remove_file(directory.join("state.v1")).unwrap();
        let legacy = tree.provider();
        assert!(legacy.snapshot().is_none());
        assert!(legacy.signer(&derive_key_id(&key)).is_none());
        assert!(legacy.status_report().contains("LEGACY_UNANCHORED"));
        let marker = format!("ios-unsandboxed-builder-state\nschema_version=1\nroot_generation=3\nroot_sha256={}\npolicy_generation=1\npolicy_sha256={}\n", hex(&Sha256::digest(&roots)), hex(&Sha256::digest(&policies)));
        write_store(&directory, "state.v1", marker.as_bytes());
        assert!(legacy.revalidate().is_err());
        let matching = tree.provider();
        assert!(matching.snapshot().is_some());
        assert!(matching
            .status_report()
            .contains("Combined marker: MATCHING"));
        write_store(
            &directory,
            "state.v1",
            marker
                .replace("root_generation=3", "root_generation=4")
                .as_bytes(),
        );
        let inconsistent = tree.provider();
        assert!(inconsistent.signer(&derive_key_id(&key)).is_none());
        assert!(inconsistent
            .status_report()
            .contains("BUILDER_GENERATION_MARKER_INCONSISTENT"));
        write_store(
            &directory,
            "state.v1",
            marker
                .replace("policy_generation=1", "policy_generation=2")
                .as_bytes(),
        );
        let stale_policy_generation = tree.provider();
        assert!(stale_policy_generation
            .signer(&derive_key_id(&key))
            .is_none());
        assert!(stale_policy_generation
            .status_report()
            .contains("BUILDER_GENERATION_MARKER_INCONSISTENT"));
        write_store(
            &directory,
            "state.v1",
            marker
                .replace(&hex(&Sha256::digest(&policies)), &"0".repeat(64))
                .as_bytes(),
        );
        let stale_policy_digest = tree.provider();
        assert!(stale_policy_digest.signer(&derive_key_id(&key)).is_none());
        assert!(stale_policy_digest
            .status_report()
            .contains("BUILDER_GENERATION_MARKER_INCONSISTENT"));
        write_store(&directory, "state.v1", marker.as_bytes());
        write_store(&directory, "roots.stage.v1", &roots);
        let pending = tree.provider();
        assert!(pending.signer(&derive_key_id(&key)).is_none());
        assert!(pending.status_report().contains("RECOVERY_REQUIRED"));
        assert_eq!(
            pending.diagnostic_error(),
            Some(crate::build_attestation::AttestationError::BuilderTransactionRecoveryRequired)
        );
        assert_eq!(
            std::fs::read(directory.join("roots.stage.v1")).unwrap(),
            roots
        );
        std::fs::remove_file(directory.join("roots.stage.v1")).unwrap();
        write_store(&directory, "transaction.v1", b"corrupt\n");
        let corrupt = tree.provider();
        assert!(corrupt.signer(&derive_key_id(&key)).is_none());
        assert!(corrupt
            .status_report()
            .contains("BUILDER_TRANSACTION_CORRUPT"));
        assert_eq!(
            corrupt.diagnostic_error(),
            Some(crate::build_attestation::AttestationError::BuilderTransactionCorrupt)
        );
        assert_eq!(
            std::fs::read(directory.join("transaction.v1")).unwrap(),
            b"corrupt\n"
        );
    }

    #[test]
    fn read_only_reader_classifies_enrollment_transition_from_store_contents() {
        let tree = TempTree::new("transaction-classifier");
        let directory = tree.trust_dir();
        let key = SigningKey::from_bytes(&[0x79; 32])
            .verifying_key()
            .to_bytes();
        let roots = root_json_with_generation(&key, "builder-signer", "active", 1);
        let policies = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":1,"generation":1,"policies":[]}),
        )
        .unwrap();
        let journal = format!(
            "ios-unsandboxed-builder-transaction\nschema_version=1\noperation=combined\nold_root_generation=none\nnew_root_generation=1\nold_root_sha256=none\nnew_root_sha256={}\nold_policy_generation=none\nnew_policy_generation=1\nold_policy_sha256=none\nnew_policy_sha256={}\nstage_roots=roots.stage.v1\nstage_policies=policies.stage.v1\nphase=prepared\n",
            hex(&Sha256::digest(&roots)),
            hex(&Sha256::digest(&policies)),
        );
        write_store(&directory, "roots.stage.v1", &roots);
        write_store(&directory, "policies.stage.v1", &policies);
        write_store(&directory, "transaction.v1", journal.as_bytes());

        let other_key = SigningKey::from_bytes(&[0x7b; 32])
            .verifying_key()
            .to_bytes();
        write_store(
            &directory,
            "roots.stage.v1",
            &root_json_with_generation(&other_key, "different-signer", "active", 1),
        );
        let modified_stage = tree.provider();
        assert!(modified_stage
            .status_report()
            .contains("Transaction state: CONFLICTING_STATE"));
        assert!(modified_stage.signer(&derive_key_id(&key)).is_none());
        write_store(&directory, "roots.stage.v1", &roots);

        let prepared = tree.provider();
        assert!(prepared
            .status_report()
            .contains("Transaction state: PREPARED_OLD_PAIR"));
        assert_eq!(
            prepared.diagnostic_error(),
            Some(crate::build_attestation::AttestationError::BuilderGenerationMarkerUnavailable)
        );
        assert!(prepared.signer(&derive_key_id(&key)).is_none());
        assert_eq!(
            std::fs::read(directory.join("transaction.v1")).unwrap(),
            journal.as_bytes()
        );

        std::fs::rename(directory.join("roots.stage.v1"), directory.join(ROOT_FILE)).unwrap();
        let first_replaced = tree.provider();
        assert!(first_replaced
            .status_report()
            .contains("Transaction state: FIRST_STORE_REPLACED"));
        assert!(first_replaced.signer(&derive_key_id(&key)).is_none());

        std::fs::rename(
            directory.join("policies.stage.v1"),
            directory.join(POLICY_FILE),
        )
        .unwrap();
        let marker_pending = tree.provider();
        assert!(marker_pending
            .status_report()
            .contains("Transaction state: COMMITTED_PAIR_MARKER_PENDING"));
        assert!(marker_pending
            .status_report()
            .contains("Root store: VALID generation=1"));
        assert!(marker_pending
            .status_report()
            .contains("Policy store: VALID generation=1"));
        assert!(marker_pending.signer(&derive_key_id(&key)).is_none());

        let marker = format!(
            "ios-unsandboxed-builder-state\nschema_version=1\nroot_generation=1\nroot_sha256={}\npolicy_generation=1\npolicy_sha256={}\n",
            hex(&Sha256::digest(&roots)),
            hex(&Sha256::digest(&policies)),
        );
        write_store(&directory, "state.stage.v1", marker.as_bytes());
        let staged_marker = tree.provider();
        assert!(staged_marker
            .status_report()
            .contains("COMMITTED_PAIR_MARKER_PENDING"));
        assert!(staged_marker.signer(&derive_key_id(&key)).is_none());
        write_store(&directory, "state.stage.v1", b"truncated");
        assert!(tree
            .provider()
            .status_report()
            .contains("CONFLICTING_STATE"));
        std::fs::remove_file(directory.join("state.stage.v1")).unwrap();
        std::os::unix::fs::symlink(directory.join("roots.v1"), directory.join("state.stage.v1"))
            .unwrap();
        assert!(tree
            .provider()
            .status_report()
            .contains("UNSAFE_TRANSACTION_ARTIFACT"));
        assert!(tree.provider().signer(&derive_key_id(&key)).is_none());
        std::fs::remove_file(directory.join("state.stage.v1")).unwrap();
        write_store(&directory, "state.v1", marker.as_bytes());
        let completed = tree.provider();
        assert!(completed
            .status_report()
            .contains("Transaction state: COMPLETE_COMMIT"));
        assert_eq!(
            completed.diagnostic_error(),
            Some(crate::build_attestation::AttestationError::BuilderTransactionPending)
        );
        assert!(completed.signer(&derive_key_id(&key)).is_none());
        assert_eq!(
            std::fs::read(directory.join("transaction.v1")).unwrap(),
            journal.as_bytes()
        );
    }

    #[test]
    fn policy_rejects_duplicate_policies_and_revision_prefixes() {
        let one = policy_json("ignored", "signer");
        let value: Value = serde_json::from_slice(&one).unwrap();
        let mut duplicate = value.clone();
        duplicate["policies"]
            .as_array_mut()
            .unwrap()
            .push(value["policies"][0].clone());
        assert!(parse_policy_store(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        let mut revision = value;
        revision["policies"][0]["allowedGitRevisions"] = serde_json::json!(["0123456789abcdef"]);
        assert!(parse_policy_store(&serde_json::to_vec(&revision).unwrap()).is_err());
    }

    #[test]
    fn diagnostic_reader_does_not_create_a_missing_root() {
        let root =
            std::env::temp_dir().join(format!("iu-builder-trust-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&root)
            .unwrap();
        let name = std::ffi::CString::new("absent").unwrap();
        let provider = LocalBuilderVerificationProviderV1::from_test_root(
            root_file,
            &[name.as_c_str()],
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        );
        assert!(provider.snapshot().is_none());
        assert!(!root.join("absent").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
