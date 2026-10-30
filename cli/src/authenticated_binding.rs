//! P013C's read-only, descriptor-bound publisher-authentication preview.
//!
//! The C result is only a P012 v1 snapshot projected through a versioned v2
//! pointer-free structure. Rust owns the artifact descriptor and performs the
//! actual Ed25519 check against the canonical P013 manifest and trust store.

use crate::build_attestation::{
    self, AttestationError, BuildOriginStatus, BuilderVerificationProviderV1,
    UnconfiguredBuilderProviderV1, VerificationResult,
};
use crate::provenance::{
    self, GenerationMarkerStatus, SignatureCheck, TrustLoadError, TrustSnapshot,
};
use sha2::{Digest, Sha256};
use std::ffi::{c_char, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const COMPOSITE_ABI_VERSION: u32 = 2;
const PATH_CAPACITY: usize = 1024;
const MAX_ARTIFACT_SIZE: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_SIZE: usize = 8192;
const MAX_ATTESTATION_SIZE: usize = 2 * 1024 * 1024;
const P012_SUMMARY_ABI_VERSION: u32 = 2;
const P012_SUMMARY_SIZE: u32 = 3376;
const PLAN_ABI_VERSION: u32 = 1;
const PLAN_SIZE: u32 = 1232;
const P012_BOUNDARY_NOT_IMPLEMENTED: u32 = 1;
const P012_REVALIDATION_SAME_OPEN_OBJECT: i32 = 1;
const P012_REVALIDATION_PATH_REPLACED: i32 = 2;
const P012_REVALIDATION_OBJECT_MODIFIED: i32 = 3;
const P012_REVALIDATION_IDENTITY_UNVERIFIED: i32 = 4;
const P012_REVALIDATION_STALE_EVIDENCE: i32 = 5;
const P012_REVALIDATION_STALE_POLICY: i32 = 6;
const ARCH_ARM64: u32 = 1;
const MACHO_EXECUTABLE: u32 = 2;
const MACHO_UNSUPPORTED_FORMAT: u32 = 6;
const MACHO_TRUNCATED_OR_CORRUPT: u32 = 7;
const MACHO_IO_ERROR: u32 = 8;
const P003_POLICY_DISABLED: u32 = 2;
const P003_DENY_PROTECTED_PATH: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct PlanV1 {
    abi_version: u32,
    struct_size: u32,
    error_code: u32,
    inspection_status: u32,
    file_type: u32,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    link_count: u32,
    identity_status: u32,
    macho_state: u32,
    architecture: u32,
    macho_filetype: u32,
    signature_preparation: u32,
    policy_outcome: u32,
    policy_reason: u32,
    adapter_compatibility: u32,
    required_capabilities: u32,
    missing_prerequisites: u32,
    preview_status: u32,
    blocking_reason: u32,
    device_runtime_verified: u32,
    operational_authorization: u32,
    device_number: u64,
    inode: u64,
    file_size: u64,
    modification_seconds: i64,
    modification_nanoseconds: u32,
    reserved0: u32,
    change_seconds: i64,
    change_nanoseconds: u32,
    reserved1: u32,
    sha256: [u8; 32],
    canonical_path_length: u32,
    canonical_path: [c_char; PATH_CAPACITY],
    reserved: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct P012SummaryV2 {
    abi_version: u32,
    struct_size: u32,
    scope_state: u32,
    store_state: u32,
    hypothetical_p003_outcome: u32,
    decision: u32,
    boundary_status: u32,
    operational_authorization: u32,
    scope_device: u64,
    scope_inode: u64,
    store_device: u64,
    store_inode: u64,
    store_sha256: [u8; 32],
    scope_path: [c_char; PATH_CAPACITY],
    requested_path: [c_char; PATH_CAPACITY],
    artifact: PlanV1,
}

const _: [(); PLAN_SIZE as usize] = [(); std::mem::size_of::<PlanV1>()];
const _: [(); P012_SUMMARY_SIZE as usize] = [(); std::mem::size_of::<P012SummaryV2>()];

extern "C" {
    fn iu_launch_binding_preview_fd_summary_v2(
        borrowed_fd: i32,
        requested_path: *const c_char,
        summary: *mut P012SummaryV2,
    ) -> i32;
    fn iu_launch_binding_revalidate_fd_summary_v2(
        borrowed_fd: i32,
        previous: *const P012SummaryV2,
    ) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactIdentityState {
    Unverified,
    Verified,
    Mismatch,
    Replaced,
    Mutated,
}

impl ArtifactIdentityState {
    fn label(self) -> &'static str {
        match self {
            Self::Unverified => "UNVERIFIED",
            Self::Verified => "VERIFIED",
            Self::Mismatch => "MISMATCH",
            Self::Replaced => "REPLACED",
            Self::Mutated => "MUTATED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoClassification {
    Unverified,
    Arm64,
    UnsupportedArchitecture,
    UnsupportedFileType,
    Malformed,
}

impl MachoClassification {
    fn label(self) -> &'static str {
        match self {
            Self::Unverified => "UNVERIFIED",
            Self::Arm64 => "ARM64",
            Self::UnsupportedArchitecture => "UNSUPPORTED_ARCHITECTURE",
            Self::UnsupportedFileType => "UNSUPPORTED_FILETYPE",
            Self::Malformed => "MALFORMED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestState {
    NotRead,
    Valid,
    Malformed,
    IdentityMismatch,
    Stale,
}

impl ManifestState {
    fn label(self) -> &'static str {
        match self {
            Self::NotRead => "NOT_VERIFIED",
            Self::Valid => "VALID",
            Self::Malformed => "MALFORMED",
            Self::IdentityMismatch => "IDENTITY_MISMATCH",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    NotVerified,
    Valid,
    Invalid,
}

impl SignatureState {
    fn label(self) -> &'static str {
        match self {
            Self::NotVerified => "NOT_VERIFIED",
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Unknown,
    Active,
    Revoked,
    Invalid,
}

impl KeyState {
    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Active => "ACTIVE",
            Self::Revoked => "REVOKED",
            Self::Invalid => "INVALID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherState {
    Unverified,
    Authenticated,
    Mismatch,
}

impl PublisherState {
    fn label(self) -> &'static str {
        match self {
            Self::Unverified => "UNVERIFIED",
            Self::Authenticated => "AUTHENTICATED",
            Self::Mismatch => "MISMATCH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSnapshotState {
    Unavailable,
    Consistent,
    Inconsistent,
    Pending,
    Stale,
}

impl TrustSnapshotState {
    fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "UNAVAILABLE",
            Self::Consistent => "CONSISTENT",
            Self::Inconsistent => "INCONSISTENT",
            Self::Pending => "PENDING",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationMarkerState {
    Unavailable,
    Consistent,
    Missing,
    Inconsistent,
    Stale,
}

impl GenerationMarkerState {
    fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "UNAVAILABLE",
            Self::Consistent => "CONSISTENT",
            Self::Missing => "MISSING",
            Self::Inconsistent => "INCONSISTENT",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingTransactionState {
    Unknown,
    Absent,
    Pending,
}

impl PendingTransactionState {
    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Absent => "ABSENT",
            Self::Pending => "PENDING",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeState {
    Unverified,
    NotConfigured,
    Match,
    Stale,
}

impl ScopeState {
    fn label(self) -> &'static str {
        match self {
            Self::Unverified => "UNVERIFIED",
            Self::NotConfigured => "NOT_CONFIGURED",
            Self::Match => "MATCH (directory only)",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedPathState {
    Unknown,
    NotClassifiedProtected,
    KnownProtected,
}

impl ProtectedPathState {
    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::NotClassifiedProtected => "NOT_CLASSIFIED_PROTECTED",
            Self::KnownProtected => "KNOWN_PROTECTED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevalidationState {
    NotRun,
    Current,
    ArtifactReplaced,
    ArtifactMutated,
    IdentityUnverified,
    ManifestStale,
    TrustStale,
    PolicyStale,
}

impl RevalidationState {
    fn label(self) -> &'static str {
        match self {
            Self::NotRun => "NOT_RUN",
            Self::Current => "CURRENT_AT_RETURN",
            Self::ArtifactReplaced => "ARTIFACT_REPLACED",
            Self::ArtifactMutated => "ARTIFACT_MUTATED",
            Self::IdentityUnverified => "IDENTITY_UNVERIFIED",
            Self::ManifestStale => "MANIFEST_STALE",
            Self::TrustStale => "TRUST_SNAPSHOT_STALE",
            Self::PolicyStale => "POLICY_SCOPE_STALE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureState {
    ArtifactUnavailable,
    ArtifactUnsafe,
    ArtifactIdentityMismatch,
    ArtifactReplaced,
    ArtifactMutated,
    UnsupportedArtifact,
    InvalidAbi,
    P012PreviewFailed,
    ManifestUnavailable,
    ManifestMalformed,
    ManifestIdentityMismatch,
    TrustStoreUnavailable,
    TrustTransactionPending,
    TrustGenerationInconsistent,
    TrustSnapshotStale,
    SignatureInvalid,
    KeyUnknown,
    KeyRevoked,
    KeyInvalid,
    PublisherMismatch,
    ManifestStale,
    PolicyScopeStale,
}

impl FailureState {
    fn label(self) -> &'static str {
        match self {
            Self::ArtifactUnavailable => "ARTIFACT_UNAVAILABLE",
            Self::ArtifactUnsafe => "ARTIFACT_UNSAFE",
            Self::ArtifactIdentityMismatch => "ARTIFACT_IDENTITY_MISMATCH",
            Self::ArtifactReplaced => "ARTIFACT_REPLACED",
            Self::ArtifactMutated => "ARTIFACT_MUTATED",
            Self::UnsupportedArtifact => "UNSUPPORTED_ARTIFACT",
            Self::InvalidAbi => "INVALID_ABI_OR_ENUM",
            Self::P012PreviewFailed => "P012_PREVIEW_FAILED",
            Self::ManifestUnavailable => "MANIFEST_UNAVAILABLE",
            Self::ManifestMalformed => "MANIFEST_MALFORMED",
            Self::ManifestIdentityMismatch => "MANIFEST_IDENTITY_MISMATCH",
            Self::TrustStoreUnavailable => "TRUST_STORE_UNAVAILABLE",
            Self::TrustTransactionPending => "TRUST_TRANSACTION_PENDING",
            Self::TrustGenerationInconsistent => "TRUST_GENERATION_INCONSISTENT",
            Self::TrustSnapshotStale => "TRUST_SNAPSHOT_STALE",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::KeyUnknown => "KEY_UNKNOWN",
            Self::KeyRevoked => "KEY_REVOKED",
            Self::KeyInvalid => "KEY_INVALID",
            Self::PublisherMismatch => "PUBLISHER_IDENTITY_MISMATCH",
            Self::ManifestStale => "MANIFEST_STALE",
            Self::PolicyScopeStale => "POLICY_SCOPE_STALE",
        }
    }
}

/// A diagnostic snapshot only. It contains no authority token, and launch
/// eligibility is not a property this type can represent.
#[derive(Debug)]
pub struct CompositePreviewV2 {
    pub abi_version: u32,
    pub artifact_identity: ArtifactIdentityState,
    pub macho_classification: MachoClassification,
    pub manifest_state: ManifestState,
    pub signature_state: SignatureState,
    pub key_state: KeyState,
    pub publisher_state: PublisherState,
    pub trust_snapshot_state: TrustSnapshotState,
    pub trust_generation: Option<u64>,
    pub trust_store_digest: Option<[u8; 32]>,
    pub generation_marker_state: GenerationMarkerState,
    pub pending_transaction_state: PendingTransactionState,
    pub key_id: Option<String>,
    pub publisher_identity: Option<String>,
    pub policy_scope: ScopeState,
    pub policy_scope_path: Option<String>,
    pub protected_path: ProtectedPathState,
    pub revalidation_state: RevalidationState,
    pub failure: Option<FailureState>,
    pub detail: Option<String>,
    pub build_attestation: Option<VerificationResult>,
    pub build_origin_verified: bool,
    pub protected_origin_known: bool,
    pub amethyst_runtime_verified: bool,
    pub launch_boundary_implemented: bool,
    pub operational_authorization: bool,
}

impl Default for CompositePreviewV2 {
    fn default() -> Self {
        Self {
            abi_version: COMPOSITE_ABI_VERSION,
            artifact_identity: ArtifactIdentityState::Unverified,
            macho_classification: MachoClassification::Unverified,
            manifest_state: ManifestState::NotRead,
            signature_state: SignatureState::NotVerified,
            key_state: KeyState::Unknown,
            publisher_state: PublisherState::Unverified,
            trust_snapshot_state: TrustSnapshotState::Unavailable,
            trust_generation: None,
            trust_store_digest: None,
            generation_marker_state: GenerationMarkerState::Unavailable,
            pending_transaction_state: PendingTransactionState::Unknown,
            key_id: None,
            publisher_identity: None,
            policy_scope: ScopeState::Unverified,
            policy_scope_path: None,
            protected_path: ProtectedPathState::Unknown,
            revalidation_state: RevalidationState::NotRun,
            failure: None,
            detail: None,
            build_attestation: None,
            build_origin_verified: false,
            protected_origin_known: false,
            amethyst_runtime_verified: false,
            launch_boundary_implemented: false,
            operational_authorization: false,
        }
    }
}

impl CompositePreviewV2 {
    fn fail(&mut self, failure: FailureState, detail: impl Into<String>) {
        if self.failure.is_none() {
            self.failure = Some(failure);
            self.detail = Some(detail.into());
        }
    }

    fn fail_stale(&mut self, failure: FailureState, detail: impl Into<String>) {
        self.failure = Some(failure);
        self.detail = Some(detail.into());
    }

    pub fn diagnostic_success(&self) -> bool {
        self.failure.is_none()
            && self.artifact_identity == ArtifactIdentityState::Verified
            && self.manifest_state == ManifestState::Valid
            && self.signature_state == SignatureState::Valid
            && self.key_state == KeyState::Active
            && self.publisher_state == PublisherState::Authenticated
            && self.trust_snapshot_state == TrustSnapshotState::Consistent
            && self.revalidation_state == RevalidationState::Current
    }

    pub fn render(&self) -> String {
        let generation = self
            .trust_generation
            .map_or_else(|| "UNAVAILABLE".to_owned(), |value| value.to_string());
        let digest = self
            .trust_store_digest
            .map_or_else(|| "UNAVAILABLE".to_owned(), |value| hex(&value));
        let key_id = self.key_id.as_deref().unwrap_or("UNAVAILABLE");
        let publisher = self.publisher_identity.as_deref().unwrap_or("UNVERIFIED");
        let scope_path = self.policy_scope_path.as_deref().unwrap_or("UNAVAILABLE");
        let failure = self.failure.map_or("NONE", FailureState::label);
        let detail = self.detail.as_deref().unwrap_or("none");
        let attestation = self
            .build_attestation
            .as_ref()
            .map(VerificationResult::render)
            .unwrap_or_else(|| "Attestation verification: NOT_REQUESTED\n".to_owned());
        format!(
            "Composite result ABI: v{}\nArtifact identity: {}\nMach-O classification: {}\nManifest integrity: {}\nManifest identity: {}\nEd25519 signature: {}\nTrusted publisher: {}\nPublisher identity: {}\nKey ID: {}\nKey state: {}\nTrust generation: {}\nTrust-store digest: {}\nTrust snapshot: {}\nGeneration marker: {}\nPending transaction: {}\nRollback protection: ROLLBACK_PROTECTION_UNVERIFIED\nP011 scope: {} (path={})\nP003 operational policy: DISABLED\nP003 protected-path classification: {}\nBuild origin: {}\nProtected origin: {}\nP009 Amethyst runtime: {}\nLaunch boundary: {}\nSnapshot revalidation: {}\nLaunch decision: BLOCKED\nExecution activation: DISABLED\nOperational authorization: {}\nFailure: {}\nDetail: {}\n{}",
            self.abi_version,
            self.artifact_identity.label(),
            self.macho_classification.label(),
            self.manifest_state.label(),
            if self.manifest_state == ManifestState::IdentityMismatch {
                "MISMATCH"
            } else if self.manifest_state == ManifestState::Valid {
                "MATCH"
            } else {
                "UNVERIFIED"
            },
            self.signature_state.label(),
            self.publisher_state.label(),
            publisher,
            key_id,
            self.key_state.label(),
            generation,
            digest,
            self.trust_snapshot_state.label(),
            self.generation_marker_state.label(),
            self.pending_transaction_state.label(),
            self.policy_scope.label(),
            scope_path,
            self.protected_path.label(),
            if self.build_origin_verified {
                "VERIFIED"
            } else {
                "ORIGIN_UNVERIFIED"
            },
            if self.protected_origin_known {
                "KNOWN"
            } else {
                "UNKNOWN"
            },
            if self.amethyst_runtime_verified {
                "VERIFIED"
            } else {
                "UNVERIFIED"
            },
            if self.launch_boundary_implemented {
                "IMPLEMENTED"
            } else {
                "NOT IMPLEMENTED"
            },
            self.revalidation_state.label(),
            if self.operational_authorization {
                "TRUE"
            } else {
                "FALSE"
            },
            failure,
            detail,
            attestation,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileStamp {
    fn from_metadata(meta: &fs::Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.size(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            links: meta.nlink(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }

    fn matches_plan(self, plan: &PlanV1) -> bool {
        self.device == plan.device_number
            && self.inode == plan.inode
            && self.size == plan.file_size
            && self.uid == plan.owner_uid
            && self.gid == plan.owner_gid
            && self.mode & 0o7777 == plan.mode
            && self.links == plan.link_count as u64
            && self.mtime == plan.modification_seconds
            && self.mtime_nsec == plan.modification_nanoseconds as i64
            && self.ctime == plan.change_seconds
            && self.ctime_nsec == plan.change_nanoseconds as i64
    }
}

struct OpenedArtifact {
    file: File,
    path: PathBuf,
    stamp: FileStamp,
    identity: crate::provenance::ArtifactIdentity,
    plan: PlanV1,
}

struct OpenedManifest {
    file: File,
    path: PathBuf,
    stamp: FileStamp,
    bytes: Vec<u8>,
}

struct OpenedAttestation {
    file: File,
    path: PathBuf,
    stamp: FileStamp,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingError {
    ArtifactReplaced,
    ArtifactMutated,
    ArtifactIdentityMismatch,
    ManifestStale,
    PolicyStale,
    InvalidAbi,
    P012Failure,
}

trait P012Binding {
    fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError>;
    fn revalidate(&self, file: &File, previous: &P012SummaryV2) -> Result<(), BindingError>;
}

struct C17P012Binding;

impl P012Binding for C17P012Binding {
    fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
        let path = CString::new(path.as_bytes()).map_err(|_| BindingError::InvalidAbi)?;
        let mut summary: P012SummaryV2 = unsafe { std::mem::zeroed() };
        summary.abi_version = P012_SUMMARY_ABI_VERSION;
        summary.struct_size = P012_SUMMARY_SIZE;
        let rc = unsafe {
            iu_launch_binding_preview_fd_summary_v2(file.as_raw_fd(), path.as_ptr(), &mut summary)
        };
        if rc != 0 {
            return Err(if rc == -1 {
                BindingError::InvalidAbi
            } else if rc == -2 {
                BindingError::ArtifactIdentityMismatch
            } else {
                BindingError::P012Failure
            });
        }
        validate_p012_summary(&summary, path.as_bytes_with_nul())?;
        Ok(summary)
    }

    fn revalidate(&self, file: &File, previous: &P012SummaryV2) -> Result<(), BindingError> {
        let rc = unsafe { iu_launch_binding_revalidate_fd_summary_v2(file.as_raw_fd(), previous) };
        match rc {
            P012_REVALIDATION_SAME_OPEN_OBJECT => Ok(()),
            P012_REVALIDATION_PATH_REPLACED => Err(BindingError::ArtifactReplaced),
            P012_REVALIDATION_OBJECT_MODIFIED => Err(BindingError::ArtifactMutated),
            P012_REVALIDATION_IDENTITY_UNVERIFIED => Err(BindingError::ArtifactIdentityMismatch),
            P012_REVALIDATION_STALE_EVIDENCE => Err(BindingError::ManifestStale),
            P012_REVALIDATION_STALE_POLICY => Err(BindingError::PolicyStale),
            _ => Err(BindingError::InvalidAbi),
        }
    }
}

fn fixed_c_bytes(value: &[c_char]) -> Option<&[u8]> {
    let end = value.iter().position(|byte| *byte == 0)?;
    Some(unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), end) })
}

fn validate_p012_summary(
    summary: &P012SummaryV2,
    expected_requested_path: &[u8],
) -> Result<(), BindingError> {
    if summary.abi_version != P012_SUMMARY_ABI_VERSION
        || summary.struct_size as usize != std::mem::size_of::<P012SummaryV2>()
        || summary.scope_state > 2
        || summary.store_state > 5
        || summary.hypothetical_p003_outcome > 8
        || !(1..=7).contains(&summary.decision)
        || summary.boundary_status != P012_BOUNDARY_NOT_IMPLEMENTED
        || summary.operational_authorization != 0
        || summary.artifact.abi_version != PLAN_ABI_VERSION
        || summary.artifact.struct_size != PLAN_SIZE
        || summary.artifact.inspection_status != 1
        || summary.artifact.identity_status != 1
        || summary.artifact.file_type != 1
        || summary.artifact.link_count != 1
        || summary.artifact.policy_outcome != P003_POLICY_DISABLED
        || summary.artifact.operational_authorization != 0
        || summary.artifact.device_runtime_verified != 0
        || summary.artifact.file_size > MAX_ARTIFACT_SIZE
        || summary.artifact.canonical_path_length < 2
        || summary.artifact.canonical_path_length as usize >= PATH_CAPACITY
    {
        return Err(BindingError::InvalidAbi);
    }
    let requested = fixed_c_bytes(&summary.requested_path).ok_or(BindingError::InvalidAbi)?;
    if requested
        != expected_requested_path
            .strip_suffix(&[0])
            .unwrap_or(expected_requested_path)
    {
        return Err(BindingError::InvalidAbi);
    }
    let canonical =
        fixed_c_bytes(&summary.artifact.canonical_path).ok_or(BindingError::InvalidAbi)?;
    if canonical.len() != summary.artifact.canonical_path_length as usize
        || canonical.first() != Some(&b'/')
        || canonical.contains(&0)
        || fixed_c_bytes(&summary.scope_path).is_none()
    {
        return Err(BindingError::InvalidAbi);
    }
    Ok(())
}

fn open_artifact(path: &OsStr) -> Result<(File, PathBuf, FileStamp), FailureState> {
    let path = PathBuf::from(path);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(_) => {
            return Err(
                if fs::symlink_metadata(&path)
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    FailureState::ArtifactUnsafe
                } else {
                    FailureState::ArtifactUnavailable
                },
            );
        }
    };
    let meta = file
        .metadata()
        .map_err(|_| FailureState::ArtifactUnavailable)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.size() == 0 || meta.size() > MAX_ARTIFACT_SIZE {
        return Err(FailureState::ArtifactUnsafe);
    }
    let stamp = FileStamp::from_metadata(&meta);
    if !path_matches_stamp(&path, stamp) {
        return Err(FailureState::ArtifactReplaced);
    }
    Ok((file, path, stamp))
}

fn open_manifest(path: &Path) -> Result<OpenedManifest, FailureState> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| FailureState::ManifestUnavailable)?;
    let meta = file
        .metadata()
        .map_err(|_| FailureState::ManifestUnavailable)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.mode() & 0o7000 != 0
        || meta.size() == 0
        || meta.size() > MAX_MANIFEST_SIZE as u64
    {
        return Err(FailureState::ManifestMalformed);
    }
    let stamp = FileStamp::from_metadata(&meta);
    if !path_matches_stamp(path, stamp) {
        return Err(FailureState::ManifestStale);
    }
    let bytes = read_exact_at(&file, stamp.size as usize, MAX_MANIFEST_SIZE)
        .map_err(|_| FailureState::ManifestMalformed)?;
    if FileStamp::from_metadata(&file.metadata().map_err(|_| FailureState::ManifestStale)?) != stamp
        || !path_matches_stamp(path, stamp)
    {
        return Err(FailureState::ManifestStale);
    }
    Ok(OpenedManifest {
        file,
        path: path.to_owned(),
        stamp,
        bytes,
    })
}

fn open_attestation(path: &Path) -> Result<OpenedAttestation, AttestationError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| AttestationError::AttestationFileUnavailable)?;
    let meta = file
        .metadata()
        .map_err(|_| AttestationError::AttestationFileUnavailable)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.mode() & 0o7000 != 0
        || meta.size() == 0
        || meta.size() > MAX_ATTESTATION_SIZE as u64
    {
        return Err(AttestationError::AttestationFileUnavailable);
    }
    let stamp = FileStamp::from_metadata(&meta);
    if !path_matches_stamp(path, stamp) {
        return Err(AttestationError::AttestationFileStale);
    }
    let bytes = read_exact_at(&file, stamp.size as usize, MAX_ATTESTATION_SIZE)
        .map_err(|_| AttestationError::AttestationFileUnavailable)?;
    if FileStamp::from_metadata(
        &file
            .metadata()
            .map_err(|_| AttestationError::AttestationFileStale)?,
    ) != stamp
        || !path_matches_stamp(path, stamp)
    {
        return Err(AttestationError::AttestationFileStale);
    }
    Ok(OpenedAttestation {
        file,
        path: path.to_owned(),
        stamp,
        bytes,
    })
}

fn revalidate_attestation(attestation: &OpenedAttestation) -> bool {
    let Ok(bytes) = read_exact_at(
        &attestation.file,
        attestation.stamp.size as usize,
        MAX_ATTESTATION_SIZE,
    ) else {
        return false;
    };
    let Ok(meta) = attestation.file.metadata() else {
        return false;
    };
    bytes == attestation.bytes
        && FileStamp::from_metadata(&meta) == attestation.stamp
        && path_matches_stamp(&attestation.path, attestation.stamp)
}

fn read_exact_at(file: &File, size: usize, maximum: usize) -> io::Result<Vec<u8>> {
    if size > maximum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "size limit"));
    }
    let mut bytes = vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
        match file.read_at(&mut bytes[offset..], offset as u64) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let mut extra = [0u8; 1];
    match file.read_at(&mut extra, size as u64) {
        Ok(0) => Ok(bytes),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "file grew")),
        Err(error) => Err(error),
    }
}

fn hash_open_file(file: &File, size: u64) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < size {
        let amount = usize::try_from((size - offset).min(buffer.len() as u64)).unwrap();
        match file.read_at(&mut buffer[..amount], offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => {
                hasher.update(&buffer[..count]);
                offset += count as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let mut extra = [0u8; 1];
    match file.read_at(&mut extra, size) {
        Ok(0) => Ok(hasher.finalize().into()),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "file grew")),
        Err(error) => Err(error),
    }
}

fn path_matches_stamp(path: &Path, stamp: FileStamp) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_file() && FileStamp::from_metadata(&meta) == stamp
}

fn path_matches_identity(path: &Path, stamp: FileStamp) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_file() && meta.dev() == stamp.device && meta.ino() == stamp.inode
}

fn artifact_identity(plan: &PlanV1) -> crate::provenance::ArtifactIdentity {
    crate::provenance::ArtifactIdentity {
        sha256: plan.sha256,
        size: plan.file_size,
        architecture: plan.architecture,
        filetype: plan.macho_filetype,
        device: plan.device_number,
        inode: plan.inode,
    }
}

fn classify_macho(plan: &PlanV1) -> MachoClassification {
    if plan.architecture != ARCH_ARM64 {
        MachoClassification::UnsupportedArchitecture
    } else if plan.macho_filetype != MACHO_EXECUTABLE {
        MachoClassification::UnsupportedFileType
    } else if matches!(
        plan.macho_state,
        MACHO_UNSUPPORTED_FORMAT | MACHO_TRUNCATED_OR_CORRUPT | MACHO_IO_ERROR
    ) {
        MachoClassification::Malformed
    } else {
        MachoClassification::Arm64
    }
}

fn map_generation_marker(status: GenerationMarkerStatus) -> GenerationMarkerState {
    match status {
        GenerationMarkerStatus::Consistent => GenerationMarkerState::Consistent,
        GenerationMarkerStatus::Missing => GenerationMarkerState::Missing,
    }
}

fn map_trust_error(
    error: &TrustLoadError,
) -> (TrustSnapshotState, PendingTransactionState, FailureState) {
    match error {
        TrustLoadError::Pending(_) => (
            TrustSnapshotState::Pending,
            PendingTransactionState::Pending,
            FailureState::TrustTransactionPending,
        ),
        TrustLoadError::GenerationInconsistent(_) => (
            TrustSnapshotState::Inconsistent,
            PendingTransactionState::Unknown,
            FailureState::TrustGenerationInconsistent,
        ),
        TrustLoadError::Unavailable(_) => (
            TrustSnapshotState::Unavailable,
            PendingTransactionState::Unknown,
            FailureState::TrustStoreUnavailable,
        ),
    }
}

fn snapshot_matches(a: &TrustSnapshot, b: &TrustSnapshot) -> bool {
    a.store.generation == b.store.generation
        && a.digest == b.digest
        && a.generation_marker_status == b.generation_marker_status
}

fn invalidate_authentication(output: &mut CompositePreviewV2) {
    output.signature_state = SignatureState::NotVerified;
    output.key_state = KeyState::Unknown;
    output.publisher_state = PublisherState::Unverified;
}

fn invalidate_artifact_binding(output: &mut CompositePreviewV2) {
    if output.manifest_state == ManifestState::Valid {
        output.manifest_state = ManifestState::Stale;
    }
    invalidate_authentication(output);
}

fn revalidate_manifest(manifest: &OpenedManifest) -> bool {
    let Ok(current_bytes) = read_exact_at(
        &manifest.file,
        manifest.stamp.size as usize,
        MAX_MANIFEST_SIZE,
    ) else {
        return false;
    };
    let Ok(current_meta) = manifest.file.metadata() else {
        return false;
    };
    current_bytes == manifest.bytes
        && FileStamp::from_metadata(&current_meta) == manifest.stamp
        && path_matches_stamp(&manifest.path, manifest.stamp)
}

fn revalidate_artifact(artifact: &OpenedArtifact) -> Result<(), BindingError> {
    if !path_matches_identity(&artifact.path, artifact.stamp) {
        return Err(BindingError::ArtifactReplaced);
    }
    let Ok(meta) = artifact.file.metadata() else {
        return Err(BindingError::ArtifactIdentityMismatch);
    };
    if FileStamp::from_metadata(&meta) != artifact.stamp {
        return Err(BindingError::ArtifactMutated);
    }
    if !path_matches_stamp(&artifact.path, artifact.stamp) {
        return Err(BindingError::ArtifactReplaced);
    }
    let digest = hash_open_file(&artifact.file, artifact.stamp.size)
        .map_err(|_| BindingError::ArtifactMutated)?;
    if digest != artifact.identity.sha256 {
        return Err(BindingError::ArtifactMutated);
    }
    let Ok(meta_after) = artifact.file.metadata() else {
        return Err(BindingError::ArtifactIdentityMismatch);
    };
    if FileStamp::from_metadata(&meta_after) != artifact.stamp {
        return Err(BindingError::ArtifactMutated);
    }
    Ok(())
}

/// The production entry point. It opens the target once and retains that
/// descriptor through P012 inspection, Rust hashing, Ed25519 verification,
/// and final P012/Rust revalidation.
pub fn preview(manifest_path: &Path, artifact_path: &OsStr) -> CompositePreviewV2 {
    preview_with(
        manifest_path,
        artifact_path,
        &C17P012Binding,
        provenance::load_production_snapshot,
    )
}

/// Read-only P013D attestation diagnostic. The production builder provider is
/// intentionally unconfigured until an independent root and policy exist.
pub fn preview_attestation(attestation_path: &Path, artifact_path: &OsStr) -> CompositePreviewV2 {
    preview_attestation_with(
        attestation_path,
        artifact_path,
        &C17P012Binding,
        &UnconfiguredBuilderProviderV1,
    )
}

fn preview_attestation_with<B, P>(
    attestation_path: &Path,
    artifact_path: &OsStr,
    binding: &B,
    provider: &P,
) -> CompositePreviewV2
where
    B: P012Binding + ?Sized,
    P: BuilderVerificationProviderV1 + ?Sized,
{
    let mut output = CompositePreviewV2::default();
    let (artifact_file, artifact_path_buf, artifact_stamp) = match open_artifact(artifact_path) {
        Ok(opened) => opened,
        Err(failure) => {
            output.fail(failure, "artifact could not be safely opened");
            return output;
        }
    };
    let requested_path = artifact_path_buf.as_os_str();
    let summary = match binding.preview(&artifact_file, requested_path) {
        Ok(summary) => summary,
        Err(error) => {
            apply_binding_failure(&mut output, error);
            return output;
        }
    };
    if validate_p012_summary(&summary, requested_path.as_bytes()).is_err() {
        output.fail(
            FailureState::InvalidAbi,
            "P012 v2 result contained an invalid size, enum, path, or authorization value",
        );
        return output;
    }
    output.policy_scope = match summary.scope_state {
        1 => ScopeState::NotConfigured,
        2 => ScopeState::Match,
        _ => ScopeState::Unverified,
    };
    output.policy_scope_path = fixed_c_bytes(&summary.scope_path)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned());
    output.protected_path = if summary.hypothetical_p003_outcome == P003_DENY_PROTECTED_PATH {
        ProtectedPathState::KnownProtected
    } else if summary.hypothetical_p003_outcome == 8 {
        ProtectedPathState::Unknown
    } else {
        ProtectedPathState::NotClassifiedProtected
    };

    let identity = artifact_identity(&summary.artifact);
    let artifact = OpenedArtifact {
        file: artifact_file,
        path: artifact_path_buf,
        stamp: artifact_stamp,
        identity,
        plan: summary.artifact,
    };
    let plan_meta_matches = artifact.stamp.matches_plan(&artifact.plan);
    let hash_matches = hash_open_file(&artifact.file, artifact.stamp.size)
        .map(|digest| digest == artifact.identity.sha256)
        .unwrap_or(false);
    let stable = artifact
        .file
        .metadata()
        .map(|meta| FileStamp::from_metadata(&meta) == artifact.stamp)
        .unwrap_or(false)
        && path_matches_stamp(&artifact.path, artifact.stamp);
    if !plan_meta_matches || !hash_matches || !stable {
        output.artifact_identity = ArtifactIdentityState::Mutated;
        output.fail(
            FailureState::ArtifactMutated,
            "Rust and C did not observe stable identical descriptor bytes and metadata",
        );
        return output;
    }
    output.artifact_identity = ArtifactIdentityState::Verified;
    output.macho_classification = classify_macho(&artifact.plan);

    let mut attestation_result = match open_attestation(attestation_path) {
        Ok(attestation) => {
            let mut result = build_attestation::verify_bytes(
                &attestation.bytes,
                &artifact.identity.sha256,
                provider,
            );
            let p012 = binding.revalidate(&artifact.file, &summary);
            let artifact_state = revalidate_artifact(&artifact);
            let attestation_current = revalidate_attestation(&attestation);
            if !attestation_current {
                result.invalidate_attestation_file();
            }
            match p012 {
                Ok(()) => {}
                Err(error) => {
                    invalidate_attestation_for_artifact_error(&mut result, &mut output, error);
                }
            }
            if let Err(error) = artifact_state {
                invalidate_attestation_for_artifact_error(&mut result, &mut output, error);
            }
            if attestation_current
                && artifact_state.is_ok()
                && result.build_origin == BuildOriginStatus::Verified
            {
                output.build_origin_verified = true;
            }
            output.revalidation_state = if output.failure.is_some() {
                output.revalidation_state
            } else if attestation_current && artifact_state.is_ok() && p012.is_ok() {
                RevalidationState::Current
            } else {
                RevalidationState::IdentityUnverified
            };
            result
        }
        Err(error) => VerificationResult {
            artifact_sha256: Some(artifact.identity.sha256),
            error: Some(error),
            ..VerificationResult::default()
        },
    };
    if !path_matches_identity(&artifact.path, artifact.stamp) {
        attestation_result.invalidate_artifact_binding();
        output.artifact_identity = ArtifactIdentityState::Replaced;
        output.build_origin_verified = false;
        output.revalidation_state = RevalidationState::ArtifactReplaced;
        output.fail_stale(
            FailureState::ArtifactReplaced,
            "artifact pathname changed during attestation verification",
        );
    }
    output.build_origin_verified = output.build_origin_verified
        && attestation_result.build_origin == BuildOriginStatus::Verified;
    output.build_attestation = Some(attestation_result);
    output
}

fn invalidate_attestation_for_artifact_error(
    result: &mut VerificationResult,
    output: &mut CompositePreviewV2,
    error: BindingError,
) {
    output.build_origin_verified = false;
    match error {
        BindingError::ArtifactReplaced => {
            result.invalidate_artifact_binding();
            output.artifact_identity = ArtifactIdentityState::Replaced;
            output.revalidation_state = RevalidationState::ArtifactReplaced;
            output.fail_stale(
                FailureState::ArtifactReplaced,
                "P012 detected pathname replacement during attestation verification",
            );
        }
        BindingError::ArtifactIdentityMismatch => {
            result.invalidate_artifact_binding();
            output.artifact_identity = ArtifactIdentityState::Mismatch;
            output.revalidation_state = RevalidationState::IdentityUnverified;
            output.fail_stale(
                FailureState::ArtifactIdentityMismatch,
                "P012 could not establish the same descriptor identity during attestation verification",
            );
        }
        BindingError::ArtifactMutated => {
            result.invalidate_artifact_binding();
            output.artifact_identity = ArtifactIdentityState::Mutated;
            output.revalidation_state = RevalidationState::ArtifactMutated;
            output.fail_stale(
                FailureState::ArtifactMutated,
                "artifact bytes or metadata changed during attestation verification",
            );
        }
        _ => {
            result.invalidate_composite_snapshot();
            apply_binding_failure(output, error);
        }
    }
}

fn preview_with<B, F>(
    manifest_path: &Path,
    artifact_path: &OsStr,
    binding: &B,
    mut load_trust: F,
) -> CompositePreviewV2
where
    B: P012Binding,
    F: FnMut() -> Result<TrustSnapshot, TrustLoadError>,
{
    let mut output = CompositePreviewV2::default();
    let (artifact_file, artifact_path_buf, artifact_stamp) = match open_artifact(artifact_path) {
        Ok(opened) => opened,
        Err(failure) => {
            output.fail(failure, "artifact could not be safely opened");
            return output;
        }
    };
    let artifact_path_os = artifact_path_buf.as_os_str();
    let summary = match binding.preview(&artifact_file, artifact_path_os) {
        Ok(summary) => summary,
        Err(BindingError::ArtifactReplaced) => {
            output.artifact_identity = ArtifactIdentityState::Replaced;
            output.fail(
                FailureState::ArtifactReplaced,
                "P012 detected pathname replacement",
            );
            return output;
        }
        Err(BindingError::ArtifactMutated) => {
            output.artifact_identity = ArtifactIdentityState::Mutated;
            output.fail(
                FailureState::ArtifactMutated,
                "P012 detected descriptor mutation",
            );
            return output;
        }
        Err(BindingError::ArtifactIdentityMismatch) => {
            output.artifact_identity = ArtifactIdentityState::Mismatch;
            output.fail(
                FailureState::ArtifactIdentityMismatch,
                "P012 descriptor identity did not match the requested path",
            );
            return output;
        }
        Err(BindingError::InvalidAbi) => {
            output.fail(
                FailureState::InvalidAbi,
                "P012 v2 descriptor preview returned an invalid ABI value",
            );
            return output;
        }
        Err(_) => {
            output.fail(
                FailureState::P012PreviewFailed,
                "P012 descriptor preview failed",
            );
            return output;
        }
    };
    if validate_p012_summary(&summary, artifact_path_os.as_bytes()).is_err() {
        output.fail(
            FailureState::InvalidAbi,
            "P012 v2 result contained an invalid size, enum, path, or authorization value",
        );
        return output;
    }
    output.policy_scope = match summary.scope_state {
        1 => ScopeState::NotConfigured,
        2 => ScopeState::Match,
        _ => ScopeState::Unverified,
    };
    output.policy_scope_path = fixed_c_bytes(&summary.scope_path)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned());
    output.protected_path = if summary.hypothetical_p003_outcome == P003_DENY_PROTECTED_PATH {
        ProtectedPathState::KnownProtected
    } else if summary.hypothetical_p003_outcome == 8 {
        ProtectedPathState::Unknown
    } else {
        ProtectedPathState::NotClassifiedProtected
    };

    let identity = artifact_identity(&summary.artifact);
    let artifact = OpenedArtifact {
        file: artifact_file,
        path: artifact_path_buf,
        stamp: artifact_stamp,
        identity,
        plan: summary.artifact,
    };
    let plan_meta_matches = artifact.stamp.matches_plan(&artifact.plan);
    let hash_matches = hash_open_file(&artifact.file, artifact.stamp.size)
        .map(|digest| digest == artifact.identity.sha256)
        .unwrap_or(false);
    let stable = artifact
        .file
        .metadata()
        .map(|meta| FileStamp::from_metadata(&meta) == artifact.stamp)
        .unwrap_or(false)
        && path_matches_stamp(&artifact.path, artifact.stamp);
    if !plan_meta_matches || !hash_matches || !stable {
        output.artifact_identity = ArtifactIdentityState::Mutated;
        output.fail(
            FailureState::ArtifactMutated,
            "Rust and C did not observe stable identical descriptor bytes and metadata",
        );
        return output;
    }
    output.artifact_identity = ArtifactIdentityState::Verified;
    output.macho_classification = classify_macho(&artifact.plan);
    if output.macho_classification != MachoClassification::Arm64 {
        output.fail(
            FailureState::UnsupportedArtifact,
            "artifact is not a supported ARM64 Mach-O executable",
        );
    }

    let manifest = match open_manifest(manifest_path) {
        Ok(manifest) => manifest,
        Err(failure) => {
            output.fail(
                failure,
                "manifest could not be read as a stable canonical input",
            );
            revalidate_without_trust(&mut output, binding, &artifact, &summary);
            return output;
        }
    };
    let parsed = match provenance::parse_manifest(&manifest.bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            output.manifest_state = ManifestState::Malformed;
            output.fail(FailureState::ManifestMalformed, error);
            revalidate_without_trust(&mut output, binding, &artifact, &summary);
            return output;
        }
    };
    output.manifest_state = ManifestState::Valid;
    output.key_id = Some(parsed.key_id.clone());
    if parsed.digest != artifact.identity.sha256
        || parsed.size != artifact.identity.size
        || parsed.architecture != artifact.identity.architecture
        || parsed.filetype != artifact.identity.filetype
    {
        output.manifest_state = ManifestState::IdentityMismatch;
        output.fail(
            FailureState::ManifestIdentityMismatch,
            "canonical manifest does not describe the opened descriptor",
        );
        revalidate_without_trust(&mut output, binding, &artifact, &summary);
        return output;
    }

    let trust_snapshot = match load_trust() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let (state, pending, failure) = map_trust_error(&error);
            output.trust_snapshot_state = state;
            output.pending_transaction_state = pending;
            output.generation_marker_state = if state == TrustSnapshotState::Inconsistent {
                GenerationMarkerState::Inconsistent
            } else {
                GenerationMarkerState::Unavailable
            };
            output.fail(failure, error.to_string());
            revalidate_without_trust(&mut output, binding, &artifact, &summary);
            return output;
        }
    };
    output.trust_snapshot_state = TrustSnapshotState::Consistent;
    output.pending_transaction_state = PendingTransactionState::Absent;
    output.trust_generation = Some(trust_snapshot.store.generation);
    output.trust_store_digest = Some(trust_snapshot.digest);
    output.generation_marker_state = map_generation_marker(trust_snapshot.generation_marker_status);

    let anchor = match trust_snapshot.store.keys.get(&parsed.key_id) {
        Some(anchor) => anchor,
        None => {
            output.key_state = KeyState::Unknown;
            output.fail(
                FailureState::KeyUnknown,
                "manifest key ID is absent from the trusted-publisher store",
            );
            revalidate_all(
                &mut output,
                binding,
                &artifact,
                &summary,
                &manifest,
                &trust_snapshot,
                &mut load_trust,
            );
            return output;
        }
    };
    output.key_state = if anchor.state == "revoked" {
        KeyState::Revoked
    } else {
        KeyState::Active
    };
    output.publisher_identity = Some(parsed.publisher.clone());
    match provenance::check_ed25519_signature(&parsed, anchor) {
        SignatureCheck::Valid => output.signature_state = SignatureState::Valid,
        SignatureCheck::Invalid => {
            output.signature_state = SignatureState::Invalid;
            output.fail(
                FailureState::SignatureInvalid,
                "Ed25519 signature verification failed",
            );
        }
        SignatureCheck::InvalidPublicKey => {
            output.key_state = KeyState::Invalid;
            output.fail(
                FailureState::KeyInvalid,
                "trusted store contains an invalid Ed25519 public key",
            );
        }
    }
    if output.signature_state == SignatureState::Valid {
        if anchor.state == "revoked" {
            output.fail(FailureState::KeyRevoked, "the signing key is revoked");
        } else if anchor.algorithm != parsed.algorithm {
            output.key_state = KeyState::Invalid;
            output.fail(
                FailureState::KeyInvalid,
                "the active key does not authorize this algorithm",
            );
        } else if anchor.publisher != parsed.publisher {
            output.publisher_state = PublisherState::Mismatch;
            output.fail(
                FailureState::PublisherMismatch,
                "the active key is scoped to a different publisher identity",
            );
        } else {
            output.publisher_state = PublisherState::Authenticated;
        }
    }
    // `origin=unprotected` is a signed publisher claim only. This provider has
    // no independent source/build attestation or complete protected catalog.
    revalidate_all(
        &mut output,
        binding,
        &artifact,
        &summary,
        &manifest,
        &trust_snapshot,
        &mut load_trust,
    );
    output.operational_authorization = false;
    output
}

fn revalidate_without_trust<B: P012Binding>(
    output: &mut CompositePreviewV2,
    binding: &B,
    artifact: &OpenedArtifact,
    summary: &P012SummaryV2,
) {
    match binding.revalidate(&artifact.file, summary) {
        Ok(()) => match revalidate_artifact(artifact) {
            Ok(()) => output.revalidation_state = RevalidationState::Current,
            Err(BindingError::ArtifactReplaced) => {
                output.artifact_identity = ArtifactIdentityState::Replaced;
                invalidate_artifact_binding(output);
                output.revalidation_state = RevalidationState::ArtifactReplaced;
                output.fail_stale(
                    FailureState::ArtifactReplaced,
                    "artifact pathname changed during preview",
                );
            }
            Err(_) => {
                output.artifact_identity = ArtifactIdentityState::Mutated;
                invalidate_artifact_binding(output);
                output.revalidation_state = RevalidationState::ArtifactMutated;
                output.fail_stale(
                    FailureState::ArtifactMutated,
                    "artifact descriptor changed during preview",
                );
            }
        },
        Err(error) => apply_binding_failure(output, error),
    }
}

fn revalidate_all<B, F>(
    output: &mut CompositePreviewV2,
    binding: &B,
    artifact: &OpenedArtifact,
    summary: &P012SummaryV2,
    manifest: &OpenedManifest,
    initial_trust: &TrustSnapshot,
    load_trust: &mut F,
) where
    B: P012Binding,
    F: FnMut() -> Result<TrustSnapshot, TrustLoadError>,
{
    let mut current = true;
    if let Err(error) = binding.revalidate(&artifact.file, summary) {
        current = false;
        if matches!(
            error,
            BindingError::ArtifactReplaced
                | BindingError::ArtifactMutated
                | BindingError::ArtifactIdentityMismatch
                | BindingError::ManifestStale
        ) {
            invalidate_artifact_binding(output);
            if error == BindingError::ManifestStale {
                output.manifest_state = ManifestState::Stale;
            }
        }
        apply_binding_failure(output, error);
    }
    if let Err(error) = revalidate_artifact(artifact) {
        current = false;
        match error {
            BindingError::ArtifactReplaced => {
                output.artifact_identity = ArtifactIdentityState::Replaced;
                invalidate_artifact_binding(output);
                output.revalidation_state = RevalidationState::ArtifactReplaced;
                output.fail_stale(
                    FailureState::ArtifactReplaced,
                    "artifact pathname changed during preview",
                );
            }
            _ => {
                output.artifact_identity = ArtifactIdentityState::Mutated;
                invalidate_artifact_binding(output);
                output.revalidation_state = RevalidationState::ArtifactMutated;
                output.fail_stale(
                    FailureState::ArtifactMutated,
                    "artifact bytes or metadata changed during preview",
                );
            }
        }
    }
    if !revalidate_manifest(manifest) {
        current = false;
        output.manifest_state = ManifestState::Stale;
        invalidate_authentication(output);
        output.revalidation_state = RevalidationState::ManifestStale;
        output.fail_stale(
            FailureState::ManifestStale,
            "manifest bytes, metadata, or pathname changed during preview",
        );
    }
    match load_trust() {
        Ok(snapshot) if snapshot_matches(initial_trust, &snapshot) => {}
        Ok(_) => {
            current = false;
            output.trust_snapshot_state = TrustSnapshotState::Stale;
            output.generation_marker_state = GenerationMarkerState::Stale;
            output.revalidation_state = RevalidationState::TrustStale;
            invalidate_authentication(output);
            output.fail_stale(
                FailureState::TrustSnapshotStale,
                "trust generation, digest, or generation-marker state changed during preview",
            );
        }
        Err(error) => {
            current = false;
            let (state, pending, _) = map_trust_error(&error);
            output.trust_snapshot_state = match &error {
                TrustLoadError::Pending(_) => TrustSnapshotState::Pending,
                TrustLoadError::GenerationInconsistent(_) => TrustSnapshotState::Inconsistent,
                TrustLoadError::Unavailable(_) => TrustSnapshotState::Stale,
            };
            output.pending_transaction_state = pending;
            output.generation_marker_state = if state == TrustSnapshotState::Inconsistent {
                GenerationMarkerState::Inconsistent
            } else {
                GenerationMarkerState::Stale
            };
            output.revalidation_state = RevalidationState::TrustStale;
            invalidate_authentication(output);
            output.fail_stale(
                match &error {
                    TrustLoadError::Pending(_) => FailureState::TrustTransactionPending,
                    TrustLoadError::GenerationInconsistent(_) => {
                        FailureState::TrustGenerationInconsistent
                    }
                    TrustLoadError::Unavailable(_) => FailureState::TrustSnapshotStale,
                },
                error.to_string(),
            );
        }
    }
    if current {
        output.revalidation_state = RevalidationState::Current;
    }
}

fn apply_binding_failure(output: &mut CompositePreviewV2, error: BindingError) {
    match error {
        BindingError::ArtifactReplaced => {
            output.artifact_identity = ArtifactIdentityState::Replaced;
            output.revalidation_state = RevalidationState::ArtifactReplaced;
            output.fail_stale(
                FailureState::ArtifactReplaced,
                "P012 detected pathname replacement during revalidation",
            );
        }
        BindingError::ArtifactMutated => {
            output.artifact_identity = ArtifactIdentityState::Mutated;
            output.revalidation_state = RevalidationState::ArtifactMutated;
            output.fail_stale(
                FailureState::ArtifactMutated,
                "P012 detected descriptor mutation during revalidation",
            );
        }
        BindingError::ArtifactIdentityMismatch => {
            output.artifact_identity = ArtifactIdentityState::Mismatch;
            output.revalidation_state = RevalidationState::IdentityUnverified;
            output.fail_stale(
                FailureState::ArtifactIdentityMismatch,
                "P012 could not establish the same descriptor identity",
            );
        }
        BindingError::ManifestStale => {
            output.revalidation_state = RevalidationState::ManifestStale;
            output.fail_stale(
                FailureState::ManifestStale,
                "P012 evidence snapshot became stale",
            );
        }
        BindingError::PolicyStale => {
            output.policy_scope = ScopeState::Stale;
            output.revalidation_state = RevalidationState::PolicyStale;
            output.fail_stale(
                FailureState::PolicyScopeStale,
                "P011 policy or scope snapshot changed during preview",
            );
        }
        BindingError::InvalidAbi => {
            output.revalidation_state = RevalidationState::IdentityUnverified;
            output.fail_stale(
                FailureState::InvalidAbi,
                "P012 revalidation rejected an ABI or enum value",
            );
        }
        BindingError::P012Failure => {
            output.revalidation_state = RevalidationState::IdentityUnverified;
            output.fail_stale(FailureState::P012PreviewFailed, "P012 revalidation failed");
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_attestation::{
        BuildOriginStatus, BuildParametersStatus, BuilderAuthorityV1, BuilderPolicyV1,
        BuilderTrustStatus, SignatureAlgorithmV1, SignerV1, SubjectStatus, SyntaxStatus,
    };
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "iu-p013c-{label}-{}-{nonce}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone)]
    struct KeyFixture {
        signing: SigningKey,
        id: String,
        public: [u8; 32],
        publisher: String,
        state: String,
    }

    impl KeyFixture {
        fn new(seed: u8, publisher: &str, state: &str) -> Self {
            let signing = SigningKey::from_bytes(&[seed; 32]);
            let public = signing.verifying_key().to_bytes();
            let hash = Sha256::digest(public);
            let id = hex(&hash[..16]);
            Self {
                signing,
                id,
                public,
                publisher: publisher.to_owned(),
                state: state.to_owned(),
            }
        }
    }

    struct TrustFixture {
        root: PathBuf,
        keys: Vec<KeyFixture>,
        generation: u64,
    }

    impl TrustFixture {
        fn new(keys: Vec<KeyFixture>) -> Self {
            let temp = TempDir::new("trust");
            let root = temp.0.clone();
            std::mem::forget(temp);
            let directory = root.join("var/lib/ios-unsandboxed/trusted-publishers");
            fs::create_dir_all(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let fixture = Self {
                root,
                keys,
                generation: 1,
            };
            fixture.write_store();
            fixture
        }

        fn directory(&self) -> PathBuf {
            self.root.join("var/lib/ios-unsandboxed/trusted-publishers")
        }

        fn write_store(&self) {
            self.write_store_generation(self.generation);
        }

        fn write_store_generation(&self, generation: u64) {
            self.write_store_records(generation, &self.keys);
        }

        fn write_store_records(&self, generation: u64, keys: &[KeyFixture]) {
            let mut sorted = BTreeMap::new();
            for key in keys {
                sorted.insert(key.id.clone(), key);
            }
            let mut bytes = format!(
                "ios-unsandboxed-trust-store\nschema_version=1\ngeneration={}\nkey_count={}\n",
                generation,
                sorted.len()
            );
            for (index, (id, key)) in sorted.iter().enumerate() {
                bytes.push_str(&format!(
                    "key_{index}={id}|ed25519|{}|publisher|{}|{}\n",
                    hex(&key.public),
                    key.publisher,
                    key.state
                ));
            }
            let path = self.directory().join("store.v1");
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn load(&self) -> Result<TrustSnapshot, TrustLoadError> {
            let root = File::open(&self.root).map_err(|error| error.to_string())?;
            let components = ["var", "lib", "ios-unsandboxed", "trusted-publishers"]
                .map(|name| CString::new(name).unwrap());
            let refs: Vec<_> = components.iter().map(|name| name.as_c_str()).collect();
            let meta = fs::metadata(&self.root).map_err(|error| error.to_string())?;
            provenance::load_store_from_root(root, &refs, meta.uid(), meta.gid())
        }

        fn add_pending_transaction(&self, name: &str, bytes: &[u8]) {
            let path = self.directory().join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn corrupt_generation_marker(&self) {
            let path = self.directory().join("generation.v1");
            fs::write(
                &path,
                b"ios-unsandboxed-trust-generation\nschema_version=1\ngeneration=99\nstore_sha256=0000000000000000000000000000000000000000000000000000000000000000\n",
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    impl Drop for TrustFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn macho(cpu: u32) -> Vec<u8> {
        fn le32(value: u32) -> [u8; 4] {
            value.to_le_bytes()
        }
        fn be32(value: u32) -> [u8; 4] {
            value.to_be_bytes()
        }
        let mut data = vec![0u8; 140];
        data[0..4].copy_from_slice(&le32(0xfeedfacf));
        data[4..8].copy_from_slice(&le32(cpu));
        data[12..16].copy_from_slice(&le32(2));
        data[16..20].copy_from_slice(&le32(1));
        data[20..24].copy_from_slice(&le32(16));
        data[32..36].copy_from_slice(&le32(0x1d));
        data[36..40].copy_from_slice(&le32(16));
        data[40..44].copy_from_slice(&le32(48));
        data[44..48].copy_from_slice(&le32(92));
        data[48..52].copy_from_slice(&be32(0xfade0cc0));
        data[52..56].copy_from_slice(&be32(92));
        data[56..60].copy_from_slice(&be32(1));
        data[60..64].copy_from_slice(&be32(0));
        data[64..68].copy_from_slice(&be32(20));
        data[68..72].copy_from_slice(&be32(0xfade0c02));
        data[72..76].copy_from_slice(&be32(72));
        data[76..80].copy_from_slice(&be32(0));
        data[80..84].copy_from_slice(&be32(0));
        data[84..88].copy_from_slice(&be32(52));
        data[88..92].copy_from_slice(&be32(44));
        data[96..100].copy_from_slice(&be32(1));
        data[100..104].copy_from_slice(&be32(1));
        data[104] = 20;
        data[105] = 2;
        data[107] = 12;
        data[112..116].copy_from_slice(b"app\0");
        data
    }

    fn write_artifact(root: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.0.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn manifest_for(bytes: &[u8], key: &KeyFixture, publisher: &str, origin: &str) -> Vec<u8> {
        let digest = hex(&Sha256::digest(bytes));
        let signed = format!(
            "schema_version=1\nartifact_sha256={digest}\nartifact_size={}\narchitecture=1\nfiletype=2\nartifact_id=fixture-bin\nrepository=https://example.invalid/org/repo\nrevision=deadbeef\nworkflow=ci-release\nbuilder=fixture-builder\npublisher={publisher}\nalgorithm=ed25519\nkey_id={}\norigin={origin}\n",
            bytes.len(), key.id
        );
        let mut message = provenance::SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(signed.as_bytes());
        let signature = key.signing.sign(&message).to_bytes();
        format!("{signed}signature={}\n", hex(&signature)).into_bytes()
    }

    fn write_manifest(root: &TempDir, bytes: &[u8]) -> PathBuf {
        let path = root.0.join("manifest.v1");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn run_preview(
        manifest: &Path,
        artifact: &Path,
        load: impl FnMut() -> Result<TrustSnapshot, TrustLoadError>,
    ) -> CompositePreviewV2 {
        preview_with(manifest, artifact.as_os_str(), &C17P012Binding, load)
    }

    struct AttestationFixtureProvider {
        signing: SigningKey,
        signer: SignerV1,
        policy: BuilderPolicyV1,
    }

    impl AttestationFixtureProvider {
        fn new() -> Self {
            let signing = SigningKey::from_bytes(&[0x52; 32]);
            let signer = SignerV1 {
                identity: Some("independent-fixture-signer".to_owned()),
                algorithm: SignatureAlgorithmV1::Ed25519,
                public_key: signing.verifying_key().to_bytes(),
            };
            Self {
                signing,
                signer,
                policy: BuilderPolicyV1 {
                    builder_identity: "https://example.invalid/builders/fixture-v1".to_owned(),
                    build_type: "https://example.invalid/buildtypes/ios-release/v1".to_owned(),
                    external_parameters: serde_json::json!({"repository": "https://example.invalid/acme/ios-app", "revision": "0123456789abcdef0123456789abcdef01234567"}),
                    source_uri: "git+https://example.invalid/acme/ios-app".to_owned(),
                    trusted_revisions: ["0123456789abcdef0123456789abcdef01234567".to_owned()]
                        .into_iter()
                        .collect(),
                },
            }
        }

        fn signed_envelope(&self, artifact: &[u8]) -> Vec<u8> {
            let statement = serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "fixture", "digest": {"sha256": hex(&Sha256::digest(artifact))}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": self.policy.build_type.clone(),
                        "externalParameters": self.policy.external_parameters.clone(),
                        "resolvedDependencies": [{
                            "uri": self.policy.source_uri.clone(),
                            "digest": {"gitCommit": "0123456789abcdef0123456789abcdef01234567"},
                        }],
                    },
                    "runDetails": {"builder": {"id": self.policy.builder_identity.clone()}},
                },
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
            let signature = self.signing.sign(&pae).to_bytes();
            serde_json::to_vec(&serde_json::json!({
                "payloadType": crate::build_attestation::DSSE_PAYLOAD_TYPE,
                "payload": base64::engine::general_purpose::STANDARD.encode(payload),
                "signatures": [{
                    "keyid": "independent-fixture-key",
                    "sig": base64::engine::general_purpose::STANDARD.encode(signature),
                }],
            }))
            .unwrap()
        }
    }

    impl BuilderVerificationProviderV1 for AttestationFixtureProvider {
        fn signer(&self, key_id: &str) -> Option<SignerV1> {
            (key_id == "independent-fixture-key").then(|| self.signer.clone())
        }

        fn builder_authority(
            &self,
            signer_identity: &str,
            builder_identity: &str,
        ) -> BuilderAuthorityV1 {
            if signer_identity == self.signer.identity.as_deref().unwrap()
                && builder_identity == self.policy.builder_identity
            {
                BuilderAuthorityV1::Trusted(self.policy.clone())
            } else {
                BuilderAuthorityV1::IdentityMismatch
            }
        }
    }

    #[test]
    fn valid_manifest_is_authenticated_on_the_same_descriptor_and_never_authorizes() {
        let root = TempDir::new("valid");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "artifact", &bytes);
        let key = KeyFixture::new(7, "fixture-publisher", "active");
        let trust = TrustFixture::new(vec![key.clone()]);
        let manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );
        let before: Vec<_> = fs::read_dir(&root.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let trust_before = fs::read(trust.directory().join("store.v1")).unwrap();
        let trust_entries_before: Vec<_> = fs::read_dir(trust.directory())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let result = run_preview(&manifest, &artifact, || trust.load());
        assert_eq!(result.abi_version, COMPOSITE_ABI_VERSION);
        assert_eq!(result.artifact_identity, ArtifactIdentityState::Verified);
        assert_eq!(result.macho_classification, MachoClassification::Arm64);
        assert_eq!(result.manifest_state, ManifestState::Valid);
        assert_eq!(result.signature_state, SignatureState::Valid);
        assert_eq!(result.key_state, KeyState::Active);
        assert_eq!(result.publisher_state, PublisherState::Authenticated);
        assert_eq!(result.trust_generation, Some(1));
        assert_eq!(
            result.pending_transaction_state,
            PendingTransactionState::Absent
        );
        assert!(!result.build_origin_verified && !result.protected_origin_known);
        assert!(!result.amethyst_runtime_verified && !result.launch_boundary_implemented);
        assert!(!result.operational_authorization);
        assert_eq!(result.revalidation_state, RevalidationState::Current);
        assert!(result.diagnostic_success());
        let rendered = result.render();
        assert!(rendered.contains("Ed25519 signature: VALID"));
        assert!(rendered.contains("Trusted publisher: AUTHENTICATED"));
        assert!(rendered.contains("Build origin: ORIGIN_UNVERIFIED"));
        assert!(rendered.contains("Protected origin: UNKNOWN"));
        assert!(rendered.contains("Operational authorization: FALSE"));
        let after: Vec<_> = fs::read_dir(&root.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
        assert_eq!(fs::read(&artifact).unwrap(), bytes);
        assert_eq!(
            fs::read(&manifest).unwrap(),
            manifest_for(&bytes, &key, "fixture-publisher", "unprotected")
        );
        assert_eq!(
            fs::read(trust.directory().join("store.v1")).unwrap(),
            trust_before
        );
        let trust_entries_after: Vec<_> = fs::read_dir(trust.directory())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(trust_entries_before, trust_entries_after);
    }

    #[test]
    fn invalid_signature_unknown_key_revocation_rotation_and_publisher_mismatch_fail_closed() {
        let root = TempDir::new("keys");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "artifact", &bytes);
        let active = KeyFixture::new(9, "fixture-publisher", "active");
        let revoked = KeyFixture::new(10, "fixture-publisher", "revoked");
        let rotated = TrustFixture::new(vec![active.clone(), revoked.clone()]);

        let active_manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &active, "fixture-publisher", "unprotected"),
        );
        let accepted = run_preview(&active_manifest, &artifact, || rotated.load());
        assert_eq!(accepted.publisher_state, PublisherState::Authenticated);
        assert!(!accepted.operational_authorization);

        let revoked_manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &revoked, "fixture-publisher", "unprotected"),
        );
        let denied = run_preview(&revoked_manifest, &artifact, || rotated.load());
        assert_eq!(denied.signature_state, SignatureState::Valid);
        assert_eq!(denied.key_state, KeyState::Revoked);
        assert_ne!(denied.publisher_state, PublisherState::Authenticated);
        assert_eq!(denied.failure, Some(FailureState::KeyRevoked));

        let unknown_trust = TrustFixture::new(vec![]);
        let unknown = run_preview(&active_manifest, &artifact, || unknown_trust.load());
        assert_eq!(unknown.key_state, KeyState::Unknown);
        assert_eq!(unknown.failure, Some(FailureState::KeyUnknown));

        let mismatch_manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &active, "another-publisher", "unprotected"),
        );
        let mismatch = run_preview(&mismatch_manifest, &artifact, || rotated.load());
        assert_eq!(mismatch.signature_state, SignatureState::Valid);
        assert_eq!(mismatch.publisher_state, PublisherState::Mismatch);
        assert_eq!(mismatch.failure, Some(FailureState::PublisherMismatch));

        let mut invalid = manifest_for(&bytes, &active, "fixture-publisher", "unprotected");
        let last = invalid.len() - 4;
        invalid[last] = if invalid[last] == b'0' { b'1' } else { b'0' };
        let invalid_path = write_manifest(&root, &invalid);
        let invalid_result = run_preview(&invalid_path, &artifact, || rotated.load());
        assert_eq!(invalid_result.signature_state, SignatureState::Invalid);
        assert_eq!(invalid_result.failure, Some(FailureState::SignatureInvalid));
        for result in [accepted, denied, unknown, mismatch, invalid_result] {
            assert!(!result.operational_authorization);
        }
    }

    #[test]
    fn manifest_identity_and_origin_claim_do_not_create_build_origin_evidence() {
        let root = TempDir::new("identity");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "artifact", &bytes);
        let key = KeyFixture::new(11, "fixture-publisher", "active");
        let trust = TrustFixture::new(vec![key.clone()]);
        let mut manifest = manifest_for(&bytes, &key, "fixture-publisher", "unprotected");
        let target = b"artifact_size=140";
        let position = manifest
            .windows(target.len())
            .position(|w| w == target)
            .unwrap()
            + b"artifact_size=".len();
        manifest.splice(position..position + 3, b"141".iter().copied());
        let path = write_manifest(&root, &manifest);
        let result = run_preview(&path, &artifact, || trust.load());
        assert_eq!(result.manifest_state, ManifestState::IdentityMismatch);
        assert_eq!(result.failure, Some(FailureState::ManifestIdentityMismatch));

        let signed_claim = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );
        let claim = run_preview(&signed_claim, &artifact, || trust.load());
        assert_eq!(claim.publisher_state, PublisherState::Authenticated);
        assert!(!claim.build_origin_verified);
        assert!(!claim.protected_origin_known);
        assert_eq!(
            claim.protected_path,
            ProtectedPathState::NotClassifiedProtected
        );
    }

    #[test]
    fn known_protected_path_is_blocked_even_when_publisher_signature_is_valid() {
        struct ProtectedPath;
        impl P012Binding for ProtectedPath {
            fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
                let mut summary = C17P012Binding.preview(file, path)?;
                summary.hypothetical_p003_outcome = P003_DENY_PROTECTED_PATH;
                Ok(summary)
            }

            fn revalidate(
                &self,
                file: &File,
                previous: &P012SummaryV2,
            ) -> Result<(), BindingError> {
                C17P012Binding.revalidate(file, previous)
            }
        }

        let root = TempDir::new("protected");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "copied-protected-fixture", &bytes);
        let key = KeyFixture::new(16, "fixture-publisher", "active");
        let trust = TrustFixture::new(vec![key.clone()]);
        let manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );
        let result = preview_with(&manifest, artifact.as_os_str(), &ProtectedPath, || {
            trust.load()
        });
        assert_eq!(result.signature_state, SignatureState::Valid);
        assert_eq!(result.publisher_state, PublisherState::Authenticated);
        assert_eq!(result.protected_path, ProtectedPathState::KnownProtected);
        assert!(!result.protected_origin_known);
        assert!(!result.operational_authorization);
    }

    #[test]
    fn unsafe_artifact_macho_and_path_replacement_are_rejected() {
        use std::os::unix::fs::symlink;
        let root = TempDir::new("unsafe");
        let key = KeyFixture::new(12, "fixture-publisher", "active");
        let trust = TrustFixture::new(vec![key.clone()]);
        let bytes = macho(0x0100000c);
        let regular = write_artifact(&root, "regular", &bytes);
        let manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );

        let link = root.0.join("symlink");
        symlink(&regular, &link).unwrap();
        let symlink_result = run_preview(&manifest, &link, || trust.load());
        assert!(symlink_result.failure.is_some());
        assert!(!symlink_result.operational_authorization);

        let hard = root.0.join("hardlink");
        fs::hard_link(&regular, &hard).unwrap();
        let hard_result = run_preview(&manifest, &regular, || trust.load());
        assert_eq!(hard_result.failure, Some(FailureState::ArtifactUnsafe));
        fs::remove_file(&hard).unwrap();

        let mut malformed_bytes = macho(0x0100000c);
        malformed_bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        let malformed = write_artifact(&root, "malformed", &malformed_bytes);
        let malformed_manifest = write_manifest(
            &root,
            &manifest_for(&malformed_bytes, &key, "fixture-publisher", "unprotected"),
        );
        let malformed_result = run_preview(&malformed_manifest, &malformed, || trust.load());
        assert_eq!(
            malformed_result.macho_classification,
            MachoClassification::Malformed
        );
        assert_eq!(
            malformed_result.failure,
            Some(FailureState::UnsupportedArtifact)
        );

        let wrong_bytes = macho(0x01000007);
        let wrong = write_artifact(&root, "wrong-architecture", &wrong_bytes);
        let wrong_manifest = write_manifest(
            &root,
            &manifest_for(&wrong_bytes, &key, "fixture-publisher", "unprotected"),
        );
        let wrong_result = run_preview(&wrong_manifest, &wrong, || trust.load());
        assert_eq!(
            wrong_result.macho_classification,
            MachoClassification::UnsupportedArchitecture
        );
        assert!(!wrong_result.operational_authorization);
    }

    #[test]
    fn pending_corrupt_and_inconsistent_trust_state_never_authenticates() {
        let root = TempDir::new("trust-fail");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "artifact", &bytes);
        let key = KeyFixture::new(13, "fixture-publisher", "active");
        let manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );

        let pending = TrustFixture::new(vec![key.clone()]);
        pending.add_pending_transaction("transaction.v1", b"corrupt journal\n");
        let pending_result = run_preview(&manifest, &artifact, || pending.load());
        assert_eq!(
            pending_result.trust_snapshot_state,
            TrustSnapshotState::Pending
        );
        assert_eq!(
            pending_result.pending_transaction_state,
            PendingTransactionState::Pending
        );
        assert_ne!(
            pending_result.publisher_state,
            PublisherState::Authenticated
        );

        let inconsistent = TrustFixture::new(vec![key.clone()]);
        inconsistent.corrupt_generation_marker();
        let inconsistent_result = run_preview(&manifest, &artifact, || inconsistent.load());
        assert_eq!(
            inconsistent_result.trust_snapshot_state,
            TrustSnapshotState::Inconsistent
        );
        assert_eq!(
            inconsistent_result.failure,
            Some(FailureState::TrustGenerationInconsistent)
        );
        assert!(!inconsistent_result.operational_authorization);
    }

    #[test]
    fn changed_trust_generation_digest_manifest_and_policy_are_stale() {
        let root = TempDir::new("stale");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "artifact", &bytes);
        let key = KeyFixture::new(14, "fixture-publisher", "active");
        let trust = TrustFixture::new(vec![key.clone()]);
        let manifest_bytes = manifest_for(&bytes, &key, "fixture-publisher", "unprotected");
        let manifest = write_manifest(&root, &manifest_bytes);
        let mut calls = 0;
        let stale_trust = preview_with(&manifest, artifact.as_os_str(), &C17P012Binding, || {
            calls += 1;
            if calls == 2 {
                trust.write_store_generation(2);
            }
            trust.load()
        });
        assert_eq!(stale_trust.trust_snapshot_state, TrustSnapshotState::Stale);
        assert_eq!(
            stale_trust.revalidation_state,
            RevalidationState::TrustStale
        );
        assert_eq!(stale_trust.failure, Some(FailureState::TrustSnapshotStale));
        assert_eq!(stale_trust.signature_state, SignatureState::NotVerified);
        assert_eq!(stale_trust.key_state, KeyState::Unknown);
        assert_eq!(stale_trust.publisher_state, PublisherState::Unverified);

        let digest_trust = TrustFixture::new(vec![key.clone()]);
        let second_key = KeyFixture::new(17, "another-publisher", "active");
        let mut calls = 0;
        let stale_digest = preview_with(&manifest, artifact.as_os_str(), &C17P012Binding, || {
            calls += 1;
            if calls == 2 {
                digest_trust.write_store_records(1, &[key.clone(), second_key.clone()]);
            }
            digest_trust.load()
        });
        assert_eq!(stale_digest.trust_generation, Some(1));
        assert_eq!(stale_digest.trust_snapshot_state, TrustSnapshotState::Stale);
        assert_eq!(stale_digest.failure, Some(FailureState::TrustSnapshotStale));
        assert_eq!(stale_digest.signature_state, SignatureState::NotVerified);
        assert_eq!(stale_digest.publisher_state, PublisherState::Unverified);

        let revoked_trust = TrustFixture::new(vec![key.clone()]);
        let revoked_key = KeyFixture::new(14, "fixture-publisher", "revoked");
        let mut calls = 0;
        let stale_revocation =
            preview_with(&manifest, artifact.as_os_str(), &C17P012Binding, || {
                calls += 1;
                if calls == 2 {
                    revoked_trust.write_store_records(2, std::slice::from_ref(&revoked_key));
                }
                revoked_trust.load()
            });
        assert_eq!(
            stale_revocation.trust_snapshot_state,
            TrustSnapshotState::Stale
        );
        assert_eq!(
            stale_revocation.failure,
            Some(FailureState::TrustSnapshotStale)
        );
        assert_eq!(stale_revocation.key_state, KeyState::Unknown);
        assert_eq!(stale_revocation.publisher_state, PublisherState::Unverified);

        let corrupt_marker_trust = TrustFixture::new(vec![key.clone()]);
        let mut calls = 0;
        let stale_marker = preview_with(&manifest, artifact.as_os_str(), &C17P012Binding, || {
            calls += 1;
            let snapshot = corrupt_marker_trust.load();
            if calls == 1 {
                corrupt_marker_trust.corrupt_generation_marker();
            }
            snapshot
        });
        assert_eq!(
            stale_marker.trust_snapshot_state,
            TrustSnapshotState::Inconsistent
        );
        assert_eq!(
            stale_marker.generation_marker_state,
            GenerationMarkerState::Inconsistent
        );
        assert_eq!(
            stale_marker.failure,
            Some(FailureState::TrustGenerationInconsistent)
        );
        assert_eq!(stale_marker.signature_state, SignatureState::NotVerified);
        assert_eq!(stale_marker.publisher_state, PublisherState::Unverified);

        let manifest_change_trust = TrustFixture::new(vec![key.clone()]);
        let mut calls = 0;
        let stale_manifest = preview_with(&manifest, artifact.as_os_str(), &C17P012Binding, || {
            calls += 1;
            let snapshot = manifest_change_trust.load();
            if calls == 1 {
                fs::write(&manifest, &manifest_bytes[..manifest_bytes.len() - 1]).unwrap();
            }
            snapshot
        });
        assert_eq!(
            stale_manifest.revalidation_state,
            RevalidationState::ManifestStale
        );
        assert_eq!(stale_manifest.manifest_state, ManifestState::Stale);
        assert_eq!(stale_manifest.signature_state, SignatureState::NotVerified);
        assert_eq!(stale_manifest.publisher_state, PublisherState::Unverified);
        assert_eq!(stale_manifest.failure, Some(FailureState::ManifestStale));

        struct StalePolicy;
        impl P012Binding for StalePolicy {
            fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
                C17P012Binding.preview(file, path)
            }
            fn revalidate(
                &self,
                _file: &File,
                _previous: &P012SummaryV2,
            ) -> Result<(), BindingError> {
                Err(BindingError::PolicyStale)
            }
        }
        let policy = TrustFixture::new(vec![key.clone()]);
        let stale_policy = preview_with(&manifest, artifact.as_os_str(), &StalePolicy, || {
            policy.load()
        });
        assert_eq!(stale_policy.policy_scope, ScopeState::Stale);
        assert_eq!(
            stale_policy.revalidation_state,
            RevalidationState::PolicyStale
        );
        assert!(!stale_policy.operational_authorization);
    }

    #[test]
    fn replacement_and_metadata_mutation_after_preview_are_detected() {
        struct Replaced;
        impl P012Binding for Replaced {
            fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
                C17P012Binding.preview(file, path)
            }
            fn revalidate(
                &self,
                file: &File,
                previous: &P012SummaryV2,
            ) -> Result<(), BindingError> {
                let path = PathBuf::from(OsStr::from_bytes(
                    fixed_c_bytes(&previous.requested_path).ok_or(BindingError::InvalidAbi)?,
                ));
                let replacement = path.with_extension("replacement");
                fs::write(&replacement, macho(0x0100000c))
                    .map_err(|_| BindingError::P012Failure)?;
                fs::rename(&replacement, &path).map_err(|_| BindingError::P012Failure)?;
                C17P012Binding.revalidate(file, previous)
            }
        }
        let root = TempDir::new("replace");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "artifact", &bytes);
        let key = KeyFixture::new(15, "fixture-publisher", "active");
        let trust = TrustFixture::new(vec![key.clone()]);
        let manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );
        let replaced = preview_with(&manifest, artifact.as_os_str(), &Replaced, || trust.load());
        assert_eq!(replaced.artifact_identity, ArtifactIdentityState::Replaced);
        assert_eq!(replaced.failure, Some(FailureState::ArtifactReplaced));
        assert_eq!(replaced.manifest_state, ManifestState::Stale);
        assert_eq!(replaced.signature_state, SignatureState::NotVerified);
        assert_eq!(replaced.publisher_state, PublisherState::Unverified);

        let root = TempDir::new("mode");
        let artifact = write_artifact(&root, "artifact", &bytes);
        let manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );
        struct ModeChanged;
        impl P012Binding for ModeChanged {
            fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
                C17P012Binding.preview(file, path)
            }
            fn revalidate(
                &self,
                file: &File,
                previous: &P012SummaryV2,
            ) -> Result<(), BindingError> {
                let path = PathBuf::from(OsStr::from_bytes(
                    fixed_c_bytes(&previous.requested_path).ok_or(BindingError::InvalidAbi)?,
                ));
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                    .map_err(|_| BindingError::P012Failure)?;
                C17P012Binding.revalidate(file, previous)
            }
        }
        let changed = preview_with(&manifest, artifact.as_os_str(), &ModeChanged, || {
            trust.load()
        });
        assert_eq!(changed.artifact_identity, ArtifactIdentityState::Mutated);
        assert_eq!(
            changed.revalidation_state,
            RevalidationState::ArtifactMutated
        );

        let root = TempDir::new("content");
        let artifact = write_artifact(&root, "artifact", &bytes);
        let manifest = write_manifest(
            &root,
            &manifest_for(&bytes, &key, "fixture-publisher", "unprotected"),
        );
        struct ContentChanged;
        impl P012Binding for ContentChanged {
            fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
                C17P012Binding.preview(file, path)
            }

            fn revalidate(
                &self,
                file: &File,
                previous: &P012SummaryV2,
            ) -> Result<(), BindingError> {
                let path = PathBuf::from(OsStr::from_bytes(
                    fixed_c_bytes(&previous.requested_path).ok_or(BindingError::InvalidAbi)?,
                ));
                fs::write(&path, b"mutated in-place on the same inode")
                    .map_err(|_| BindingError::P012Failure)?;
                C17P012Binding.revalidate(file, previous)
            }
        }
        let changed = preview_with(&manifest, artifact.as_os_str(), &ContentChanged, || {
            trust.load()
        });
        assert_eq!(changed.artifact_identity, ArtifactIdentityState::Mutated);
        assert_eq!(changed.failure, Some(FailureState::ArtifactMutated));
        assert_eq!(changed.manifest_state, ManifestState::Stale);
        assert_eq!(changed.signature_state, SignatureState::NotVerified);
        assert_eq!(changed.publisher_state, PublisherState::Unverified);
    }

    #[test]
    fn attestation_composite_binds_descriptor_and_never_authorizes_without_runtime_evidence() {
        let root = TempDir::new("attestation-composite");
        let bytes = macho(0x0100000c);
        let artifact = write_artifact(&root, "artifact", &bytes);
        let attestation = root.0.join("attestation.dsse.json");
        let provider = AttestationFixtureProvider::new();
        fs::write(&attestation, provider.signed_envelope(&bytes)).unwrap();
        fs::set_permissions(&attestation, fs::Permissions::from_mode(0o600)).unwrap();

        let result = preview_attestation_with(
            &attestation,
            artifact.as_os_str(),
            &C17P012Binding,
            &provider,
        );
        let attestation_result = result.build_attestation.as_ref().unwrap();
        assert_eq!(result.artifact_identity, ArtifactIdentityState::Verified);
        assert_eq!(result.revalidation_state, RevalidationState::Current);
        assert_eq!(attestation_result.syntax, SyntaxStatus::Valid);
        assert_eq!(
            attestation_result.signature,
            crate::build_attestation::SignatureStatus::Valid
        );
        assert_eq!(attestation_result.subject, SubjectStatus::Matched);
        assert_eq!(
            attestation_result.builder_trust,
            BuilderTrustStatus::Trusted
        );
        assert_eq!(
            attestation_result.build_parameters,
            BuildParametersStatus::Accepted
        );
        assert_eq!(attestation_result.build_origin, BuildOriginStatus::Verified);
        assert!(result.build_origin_verified);
        assert!(!result.protected_origin_known);
        assert!(!result.amethyst_runtime_verified);
        assert!(!result.launch_boundary_implemented);
        assert!(!result.operational_authorization);
        let rendered = result.render();
        assert!(rendered.contains("Attestation signature: VALID"));
        assert!(rendered.contains("Builder identity trust: TRUSTED"));
        assert!(rendered.contains("Protected origin: UNKNOWN"));
        assert!(rendered.contains("P009 Amethyst runtime: UNVERIFIED"));
        assert!(rendered.contains("Launch boundary: NOT IMPLEMENTED"));
        assert!(rendered.contains("Execution activation: DISABLED"));
        assert!(rendered.contains("Operational authorization: FALSE"));
    }

    #[test]
    fn attestation_subject_is_invalidated_when_artifact_is_replaced_or_mutated() {
        struct Replaced;
        impl P012Binding for Replaced {
            fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
                C17P012Binding.preview(file, path)
            }
            fn revalidate(
                &self,
                file: &File,
                previous: &P012SummaryV2,
            ) -> Result<(), BindingError> {
                let path = PathBuf::from(OsStr::from_bytes(
                    fixed_c_bytes(&previous.requested_path).ok_or(BindingError::InvalidAbi)?,
                ));
                let replacement = path.with_extension("replacement");
                fs::write(&replacement, macho(0x0100000c))
                    .map_err(|_| BindingError::P012Failure)?;
                fs::rename(&replacement, &path).map_err(|_| BindingError::P012Failure)?;
                C17P012Binding.revalidate(file, previous)
            }
        }
        struct Mutated;
        impl P012Binding for Mutated {
            fn preview(&self, file: &File, path: &OsStr) -> Result<P012SummaryV2, BindingError> {
                C17P012Binding.preview(file, path)
            }
            fn revalidate(
                &self,
                file: &File,
                previous: &P012SummaryV2,
            ) -> Result<(), BindingError> {
                let path = PathBuf::from(OsStr::from_bytes(
                    fixed_c_bytes(&previous.requested_path).ok_or(BindingError::InvalidAbi)?,
                ));
                fs::write(&path, b"changed descriptor bytes")
                    .map_err(|_| BindingError::P012Failure)?;
                C17P012Binding.revalidate(file, previous)
            }
        }

        for (label, binding, expected) in [
            (
                "replaced",
                &Replaced as &dyn P012Binding,
                ArtifactIdentityState::Replaced,
            ),
            (
                "mutated",
                &Mutated as &dyn P012Binding,
                ArtifactIdentityState::Mutated,
            ),
        ] {
            let root = TempDir::new(label);
            let bytes = macho(0x0100000c);
            let artifact = write_artifact(&root, "artifact", &bytes);
            let attestation = root.0.join("attestation.dsse.json");
            let provider = AttestationFixtureProvider::new();
            fs::write(&attestation, provider.signed_envelope(&bytes)).unwrap();
            fs::set_permissions(&attestation, fs::Permissions::from_mode(0o600)).unwrap();
            let result =
                preview_attestation_with(&attestation, artifact.as_os_str(), binding, &provider);
            let attestation_result = result.build_attestation.as_ref().unwrap();
            assert_eq!(result.artifact_identity, expected);
            assert_eq!(attestation_result.subject, SubjectStatus::StaleArtifact);
            assert_eq!(
                attestation_result.build_origin,
                BuildOriginStatus::Unverified
            );
            assert!(!result.build_origin_verified);
            assert!(!result.operational_authorization);
        }
    }

    #[test]
    fn p012_abi_and_enum_validation_is_fail_closed_and_snapshot_has_no_authority() {
        let mut summary: P012SummaryV2 = unsafe { std::mem::zeroed() };
        summary.abi_version = P012_SUMMARY_ABI_VERSION;
        summary.struct_size = P012_SUMMARY_SIZE;
        summary.scope_state = 99;
        assert_eq!(
            validate_p012_summary(&summary, b"x"),
            Err(BindingError::InvalidAbi)
        );
        summary.scope_state = 0;
        summary.struct_size -= 1;
        assert_eq!(
            validate_p012_summary(&summary, b"x"),
            Err(BindingError::InvalidAbi)
        );
        let result = CompositePreviewV2::default();
        assert!(!result.operational_authorization);
        assert!(!result.diagnostic_success());
        assert!(std::mem::size_of::<CompositePreviewV2>() > 0);
    }
}
