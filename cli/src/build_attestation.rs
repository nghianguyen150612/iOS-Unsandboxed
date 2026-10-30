//! Offline DSSE/in-toto/SLSA build-attestation verification.
//!
//! This module implements a bounded profile. DSSE's signature algorithm is
//! supplied by the independent versioned provider, never selected by payload
//! fields. Production uses a separate local builder root/policy provider and
//! never imports publisher trust; local installation alone cannot establish
//! independent enrollment trust.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;

pub const PROVIDER_VERSION_V1: u32 = 1;
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

const MAX_ENVELOPE_SIZE: usize = 2 * 1024 * 1024;
const MAX_PAYLOAD_SIZE: usize = 768 * 1024;
const MAX_JSON_STRING_SIZE: usize = 16 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 8192;
const MAX_ARRAY_LENGTH: usize = 256;
const MAX_OBJECT_FIELDS: usize = 256;
const MAX_SIGNATURES: usize = 1;
const MAX_KEY_ID_SIZE: usize = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxStatus {
    NotChecked,
    Valid,
    Malformed,
    Unsupported,
    Stale,
}

impl SyntaxStatus {
    fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "NOT_CHECKED",
            Self::Valid => "VALID",
            Self::Malformed => "MALFORMED",
            Self::Unsupported => "UNSUPPORTED_SCHEMA",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    NotChecked,
    Valid,
    Invalid,
    UnknownSigner,
    RevokedSigner,
    UnsupportedAlgorithm,
    Truncated,
}

impl SignatureStatus {
    fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "NOT_CHECKED",
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::UnknownSigner => "UNKNOWN_SIGNER",
            Self::RevokedSigner => "REVOKED_SIGNER",
            Self::UnsupportedAlgorithm => "UNSUPPORTED_ALGORITHM",
            Self::Truncated => "TRUNCATED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerIdentityStatus {
    NotChecked,
    Verified,
    Unknown,
    Unverified,
}

impl SignerIdentityStatus {
    fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "NOT_CHECKED",
            Self::Verified => "VERIFIED",
            Self::Unknown => "UNKNOWN",
            Self::Unverified => "UNVERIFIED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectStatus {
    NotChecked,
    Matched,
    Missing,
    Mismatch,
    Ambiguous,
    Malformed,
    StaleArtifact,
    StaleAttestation,
}

impl SubjectStatus {
    fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "NOT_CHECKED",
            Self::Matched => "MATCHED_DESCRIPTOR_SHA256",
            Self::Missing => "MISSING",
            Self::Mismatch => "DIGEST_MISMATCH",
            Self::Ambiguous => "AMBIGUOUS",
            Self::Malformed => "MALFORMED",
            Self::StaleArtifact => "STALE_ARTIFACT",
            Self::StaleAttestation => "STALE_ATTESTATION",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderTrustStatus {
    NotChecked,
    Trusted,
    Untrusted,
    Unknown,
    IdentityMismatch,
}

impl BuilderTrustStatus {
    fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "NOT_CHECKED",
            Self::Trusted => "TRUSTED",
            Self::Untrusted => "UNTRUSTED",
            Self::Unknown => "UNKNOWN_AUTHORITY",
            Self::IdentityMismatch => "IDENTITY_MISMATCH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildParametersStatus {
    NotChecked,
    Accepted,
    Unexpected,
    UntrustedSourceRevision,
    Rejected,
}

impl BuildParametersStatus {
    fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "NOT_CHECKED",
            Self::Accepted => "ACCEPTED",
            Self::Unexpected => "UNEXPECTED_PARAMETERS",
            Self::UntrustedSourceRevision => "UNTRUSTED_SOURCE_REVISION",
            Self::Rejected => "REJECTED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOriginStatus {
    Unverified,
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSnapshotStatus {
    Unavailable,
    Consistent,
    Stale,
}

impl TrustSnapshotStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "UNAVAILABLE",
            Self::Consistent => "CONSISTENT",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEstablishmentStatus {
    Verified,
    Unverified,
}

impl TrustEstablishmentStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Unverified => "UNVERIFIED",
        }
    }
}

impl BuildOriginStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Unverified => "BUILD_ORIGIN_UNVERIFIED",
            Self::Verified => "BUILD_ORIGIN_VERIFIED",
            Self::Rejected => "BUILD_ORIGIN_REJECTED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationError {
    EnvelopeTooLarge,
    EnvelopeMalformed,
    UnsupportedEnvelopeSchema,
    UnsupportedPayloadType,
    PayloadTooLarge,
    PayloadMalformed,
    UnsupportedStatementVersion,
    UnsupportedPredicateType,
    UnsupportedPredicateSchema,
    SubjectMissing,
    SubjectMalformed,
    SubjectMismatch,
    SubjectAmbiguous,
    UnknownSigner,
    RevokedSigner,
    BuilderTransactionPending,
    BuilderTransactionCorrupt,
    BuilderMarkerInconsistent,
    SignerIdentityUnverified,
    InvalidSignature,
    UnsupportedSignatureAlgorithm,
    BuilderAuthorityUnknown,
    BuilderUntrusted,
    BuilderIdentityMismatch,
    UnexpectedBuildParameters,
    UntrustedSourceRevision,
    ProviderVersionUnsupported,
    ArtifactStale,
    CompositeSnapshotStale,
    AttestationFileUnavailable,
    AttestationFileStale,
}

impl AttestationError {
    fn label(self) -> &'static str {
        match self {
            Self::EnvelopeTooLarge => "ENVELOPE_TOO_LARGE",
            Self::EnvelopeMalformed => "ENVELOPE_MALFORMED",
            Self::UnsupportedEnvelopeSchema => "UNSUPPORTED_ENVELOPE_SCHEMA",
            Self::UnsupportedPayloadType => "UNSUPPORTED_PAYLOAD_TYPE",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::PayloadMalformed => "PAYLOAD_MALFORMED",
            Self::UnsupportedStatementVersion => "UNSUPPORTED_STATEMENT_VERSION",
            Self::UnsupportedPredicateType => "UNSUPPORTED_PREDICATE_TYPE",
            Self::UnsupportedPredicateSchema => "UNSUPPORTED_PREDICATE_SCHEMA",
            Self::SubjectMissing => "SUBJECT_MISSING",
            Self::SubjectMalformed => "SUBJECT_MALFORMED",
            Self::SubjectMismatch => "SUBJECT_DIGEST_MISMATCH",
            Self::SubjectAmbiguous => "SUBJECT_AMBIGUOUS",
            Self::UnknownSigner => "UNKNOWN_SIGNER",
            Self::RevokedSigner => "REVOKED_SIGNER",
            Self::BuilderTransactionPending => "BUILDER_TRANSACTION_PENDING",
            Self::BuilderTransactionCorrupt => "BUILDER_TRANSACTION_CORRUPT",
            Self::BuilderMarkerInconsistent => "BUILDER_GENERATION_MARKER_INCONSISTENT",
            Self::SignerIdentityUnverified => "SIGNER_IDENTITY_UNVERIFIED",
            Self::InvalidSignature => "SIGNATURE_INVALID",
            Self::UnsupportedSignatureAlgorithm => "UNSUPPORTED_SIGNATURE_ALGORITHM",
            Self::BuilderAuthorityUnknown => "BUILDER_AUTHORITY_UNKNOWN",
            Self::BuilderUntrusted => "BUILDER_UNTRUSTED",
            Self::BuilderIdentityMismatch => "BUILDER_IDENTITY_MISMATCH",
            Self::UnexpectedBuildParameters => "UNEXPECTED_BUILD_PARAMETERS",
            Self::UntrustedSourceRevision => "UNTRUSTED_SOURCE_REVISION",
            Self::ProviderVersionUnsupported => "PROVIDER_VERSION_UNSUPPORTED",
            Self::ArtifactStale => "ARTIFACT_IDENTITY_STALE",
            Self::CompositeSnapshotStale => "COMPOSITE_SNAPSHOT_STALE",
            Self::AttestationFileUnavailable => "ATTESTATION_FILE_UNAVAILABLE",
            Self::AttestationFileStale => "ATTESTATION_FILE_STALE",
        }
    }
}

/// Typed results preserve syntax, cryptographic signature, signer identity,
/// builder identity/trust, parameter acceptance, and origin as separate facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub syntax: SyntaxStatus,
    pub signature: SignatureStatus,
    pub signer_identity: SignerIdentityStatus,
    pub subject: SubjectStatus,
    pub artifact_sha256: Option<[u8; 32]>,
    pub builder_identity_claimed: Option<String>,
    pub builder_trust: BuilderTrustStatus,
    pub source_uri: Option<String>,
    pub source_revision: Option<String>,
    pub build_type: Option<String>,
    pub build_parameters: BuildParametersStatus,
    pub signer_key_id: Option<String>,
    pub signer_identity_value: Option<String>,
    pub applicable_policy_identity: Option<String>,
    pub trust_snapshot: Option<crate::builder_trust::BuilderTrustSnapshotV1>,
    pub trust_snapshot_status: TrustSnapshotStatus,
    pub independent_trust_establishment: TrustEstablishmentStatus,
    pub build_origin: BuildOriginStatus,
    pub error: Option<AttestationError>,
}

impl Default for VerificationResult {
    fn default() -> Self {
        Self {
            syntax: SyntaxStatus::NotChecked,
            signature: SignatureStatus::NotChecked,
            signer_identity: SignerIdentityStatus::NotChecked,
            subject: SubjectStatus::NotChecked,
            artifact_sha256: None,
            builder_identity_claimed: None,
            builder_trust: BuilderTrustStatus::NotChecked,
            source_uri: None,
            source_revision: None,
            build_type: None,
            build_parameters: BuildParametersStatus::NotChecked,
            signer_key_id: None,
            signer_identity_value: None,
            applicable_policy_identity: None,
            trust_snapshot: None,
            trust_snapshot_status: TrustSnapshotStatus::Unavailable,
            independent_trust_establishment: TrustEstablishmentStatus::Unverified,
            build_origin: BuildOriginStatus::Unverified,
            error: None,
        }
    }
}

impl VerificationResult {
    pub fn render(&self) -> String {
        let digest = self
            .artifact_sha256
            .map_or_else(|| "UNAVAILABLE".to_owned(), |value| hex(&value));
        let builder = self
            .builder_identity_claimed
            .as_deref()
            .map(escape_text)
            .unwrap_or_else(|| "UNAVAILABLE".to_owned());
        let source = self
            .source_revision
            .as_deref()
            .map(escape_text)
            .unwrap_or_else(|| "UNAVAILABLE".to_owned());
        let source_uri = self
            .source_uri
            .as_deref()
            .map(escape_text)
            .unwrap_or_else(|| "UNAVAILABLE".to_owned());
        let build_type = self
            .build_type
            .as_deref()
            .map(escape_text)
            .unwrap_or_else(|| "UNAVAILABLE".to_owned());
        let error = self.error.map_or("NONE", AttestationError::label);
        let snapshot = self
            .trust_snapshot
            .as_ref()
            .map_or_else(|| "UNAVAILABLE".to_owned(), |value| value.render());
        let signer_key_id = self
            .signer_key_id
            .as_deref()
            .map(escape_text)
            .unwrap_or_else(|| "UNAVAILABLE".to_owned());
        let signer_identity_value = self
            .signer_identity_value
            .as_deref()
            .map(escape_text)
            .unwrap_or_else(|| "UNAVAILABLE".to_owned());
        let policy_id = self
            .applicable_policy_identity
            .as_deref()
            .map(escape_text)
            .unwrap_or_else(|| "UNAVAILABLE".to_owned());
        let policy_status = match self.builder_trust {
            BuilderTrustStatus::Trusted
                if self.build_parameters == BuildParametersStatus::Accepted =>
            {
                "ACCEPTED"
            }
            BuilderTrustStatus::Trusted => "REJECTED",
            BuilderTrustStatus::Unknown | BuilderTrustStatus::NotChecked => "UNCONFIGURED",
            BuilderTrustStatus::Untrusted | BuilderTrustStatus::IdentityMismatch => "REJECTED",
        };
        format!(
            "Attestation syntax: {}\nAttestation signature: {}\nSigner identity: {} ({})\nSigner key ID: {}\nAttestation subject: {} (artifact_sha256={})\nBuilder identity claimed: {}\nBuilder identity trust: {}\nBuilder authority: {}\nBuilder policy: {} ({})\nSource revision: {} (uri={})\nBuild type: {}\nBuild parameters accepted: {}\nTrust snapshot: {} ({})\nIndependent trust establishment: {}\nBuild-origin verification: {}\nAttestation error: {}\n",
            self.syntax.label(),
            self.signature.label(),
            self.signer_identity.label(),
            signer_identity_value,
            signer_key_id,
            self.subject.label(),
            digest,
            builder,
            self.builder_trust.label(),
            self.builder_trust.label(),
            policy_status,
            policy_id,
            source,
            source_uri,
            build_type,
            self.build_parameters.label(),
            self.trust_snapshot_status.label(),
            snapshot,
            self.independent_trust_establishment.label(),
            self.build_origin.label(),
            error,
        )
    }

    pub(crate) fn invalidate_artifact_binding(&mut self) {
        self.subject = SubjectStatus::StaleArtifact;
        self.build_origin = BuildOriginStatus::Unverified;
        self.error = Some(AttestationError::ArtifactStale);
    }

    pub(crate) fn invalidate_attestation_file(&mut self) {
        self.syntax = SyntaxStatus::Stale;
        self.signature = SignatureStatus::NotChecked;
        self.signer_identity = SignerIdentityStatus::NotChecked;
        self.subject = SubjectStatus::StaleAttestation;
        self.builder_identity_claimed = None;
        self.signer_key_id = None;
        self.signer_identity_value = None;
        self.applicable_policy_identity = None;
        self.trust_snapshot = None;
        self.trust_snapshot_status = TrustSnapshotStatus::Unavailable;
        self.builder_trust = BuilderTrustStatus::NotChecked;
        self.source_uri = None;
        self.source_revision = None;
        self.build_type = None;
        self.build_parameters = BuildParametersStatus::NotChecked;
        self.build_origin = BuildOriginStatus::Unverified;
        self.error = Some(AttestationError::AttestationFileStale);
    }

    pub(crate) fn invalidate_composite_snapshot(&mut self) {
        self.build_origin = BuildOriginStatus::Unverified;
        self.error = Some(AttestationError::CompositeSnapshotStale);
    }

    pub(crate) fn invalidate_trust_snapshot(&mut self) {
        self.trust_snapshot_status = TrustSnapshotStatus::Stale;
        self.signer_identity = SignerIdentityStatus::Unverified;
        self.signer_identity_value = None;
        self.builder_trust = BuilderTrustStatus::Unknown;
        self.applicable_policy_identity = None;
        self.build_parameters = BuildParametersStatus::Rejected;
        self.build_origin = BuildOriginStatus::Unverified;
        self.error = Some(AttestationError::CompositeSnapshotStale);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Non-Ed25519 algorithms are represented and rejected by this provider contract.
pub enum SignatureAlgorithmV1 {
    Ed25519,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerV1 {
    /// The provider may have a verification key without an independently
    /// authenticated principal mapping; that yields a valid signature but an
    /// unverified signer identity.
    pub identity: Option<String>,
    pub algorithm: SignatureAlgorithmV1,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct BuilderPolicyV1 {
    pub builder_identity: String,
    pub build_type: String,
    pub external_parameters: Value,
    pub source_uri: String,
    pub trusted_revisions: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Production outcomes are supplied by the local D2A provider.
pub enum BuilderAuthorityV1 {
    Trusted(BuilderPolicyV1),
    Untrusted,
    Unknown,
    IdentityMismatch,
}

/// Independent builder verification interface. Implementations must not
/// translate publisher trust into builder trust. `key_id` is only a lookup
/// hint; this provider owns the key and identity mapping.
pub trait BuilderVerificationProviderV1 {
    fn version(&self) -> u32 {
        PROVIDER_VERSION_V1
    }

    fn signer(&self, key_id: &str) -> Option<SignerV1>;

    fn signer_revoked(&self, _key_id: &str) -> bool {
        false
    }

    fn diagnostic_error(&self) -> Option<AttestationError> {
        None
    }

    fn builder_authority(
        &self,
        signer_identity: &str,
        builder_identity: &str,
    ) -> BuilderAuthorityV1;

    /// Snapshot metadata is diagnostic context only and never authorizes use.
    fn trust_snapshot(&self) -> Option<crate::builder_trust::BuilderTrustSnapshotV1> {
        None
    }

    /// Providers with mutable backing stores must re-read and compare them.
    fn revalidate_trust_snapshot(&self) -> bool {
        true
    }

    fn policy_identity(&self, _signer_identity: &str, _builder_identity: &str) -> Option<String> {
        None
    }

    /// Synthetic providers may model an independently reviewed enrollment
    /// chain. The local D2A provider intentionally always returns false.
    fn independent_trust_established(&self) -> bool {
        false
    }
}

/// Explicit no-configuration fallback. The production composite uses the
/// separate local provider, which still fails closed without provisioned
/// roots and cannot establish independent enrollment trust.
#[derive(Debug, Default, Clone, Copy)]
#[allow(dead_code)] // Retained as the explicit fail-closed no-configuration provider.
pub struct UnconfiguredBuilderProviderV1;

impl BuilderVerificationProviderV1 for UnconfiguredBuilderProviderV1 {
    fn signer(&self, _key_id: &str) -> Option<SignerV1> {
        None
    }

    fn builder_authority(
        &self,
        _signer_identity: &str,
        _builder_identity: &str,
    ) -> BuilderAuthorityV1 {
        BuilderAuthorityV1::Unknown
    }
}

/// Verify a DSSE envelope against the SHA-256 snapshot already taken from the
/// P013C opened artifact descriptor. This function never opens a pathname.
pub(crate) fn verify_bytes<P: BuilderVerificationProviderV1 + ?Sized>(
    envelope_bytes: &[u8],
    descriptor_sha256: &[u8; 32],
    provider: &P,
) -> VerificationResult {
    let mut result = VerificationResult {
        artifact_sha256: Some(*descriptor_sha256),
        ..VerificationResult::default()
    };

    if provider.version() != PROVIDER_VERSION_V1 {
        return reject(&mut result, AttestationError::ProviderVersionUnsupported);
    }
    if envelope_bytes.len() > MAX_ENVELOPE_SIZE {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeTooLarge);
    }
    let envelope = match parse_bounded_json(envelope_bytes, MAX_ENVELOPE_SIZE) {
        Ok(value) => value,
        Err(_) => {
            result.syntax = SyntaxStatus::Malformed;
            return reject(&mut result, AttestationError::EnvelopeMalformed);
        }
    };
    let Some(envelope) = envelope.as_object() else {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    };
    if has_unknown_fields(envelope, &["payloadType", "payload", "signatures"]) {
        result.syntax = SyntaxStatus::Unsupported;
        return reject(&mut result, AttestationError::UnsupportedEnvelopeSchema);
    }
    let Some(payload_type) = envelope.get("payloadType").and_then(Value::as_str) else {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    };
    if payload_type != DSSE_PAYLOAD_TYPE {
        result.syntax = SyntaxStatus::Unsupported;
        return reject(&mut result, AttestationError::UnsupportedPayloadType);
    }
    let Some(payload_encoded) = envelope.get("payload").and_then(Value::as_str) else {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    };
    let Some(signatures) = envelope.get("signatures").and_then(Value::as_array) else {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    };
    if signatures.len() != MAX_SIGNATURES {
        result.syntax = SyntaxStatus::Unsupported;
        return reject(&mut result, AttestationError::UnsupportedEnvelopeSchema);
    }
    if payload_encoded.len() > encoded_limit(MAX_PAYLOAD_SIZE) {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::PayloadTooLarge);
    }
    let payload = match decode_base64(payload_encoded, MAX_PAYLOAD_SIZE) {
        Ok(bytes) => bytes,
        Err(DecodeError::TooLarge) => {
            result.syntax = SyntaxStatus::Malformed;
            return reject(&mut result, AttestationError::PayloadTooLarge);
        }
        Err(DecodeError::Invalid) => {
            result.syntax = SyntaxStatus::Malformed;
            return reject(&mut result, AttestationError::EnvelopeMalformed);
        }
    };
    let signature_entry = match signatures.first().and_then(Value::as_object) {
        Some(value) if !has_unknown_fields(value, &["keyid", "sig"]) => value,
        Some(_) => {
            result.syntax = SyntaxStatus::Unsupported;
            return reject(&mut result, AttestationError::UnsupportedEnvelopeSchema);
        }
        None => {
            result.syntax = SyntaxStatus::Malformed;
            return reject(&mut result, AttestationError::EnvelopeMalformed);
        }
    };
    let Some(key_id) = signature_entry.get("keyid").and_then(Value::as_str) else {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    };
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_SIZE {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    }
    let Some(signature_encoded) = signature_entry.get("sig").and_then(Value::as_str) else {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    };
    if signature_encoded.len() > 128 {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::EnvelopeMalformed);
    }
    let signature_bytes = match decode_base64(signature_encoded, 64) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(_) => {
            result.syntax = SyntaxStatus::Malformed;
            result.signature = SignatureStatus::Truncated;
            return reject(&mut result, AttestationError::EnvelopeMalformed);
        }
        Err(DecodeError::TooLarge) => {
            result.syntax = SyntaxStatus::Malformed;
            return reject(&mut result, AttestationError::EnvelopeMalformed);
        }
        Err(DecodeError::Invalid) => {
            result.syntax = SyntaxStatus::Malformed;
            return reject(&mut result, AttestationError::EnvelopeMalformed);
        }
    };
    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(signature) => signature,
        Err(_) => {
            result.syntax = SyntaxStatus::Malformed;
            result.signature = SignatureStatus::Truncated;
            return reject(&mut result, AttestationError::EnvelopeMalformed);
        }
    };

    let signer = provider.signer(key_id);
    result.signer_key_id = signer.as_ref().map(|_| key_id.to_owned());
    result.signer_identity_value = signer.as_ref().and_then(|signer| signer.identity.clone());
    result.trust_snapshot = provider.trust_snapshot();
    result.trust_snapshot_status = if result.trust_snapshot.is_some() {
        TrustSnapshotStatus::Consistent
    } else {
        TrustSnapshotStatus::Unavailable
    };
    match signer.as_ref() {
        None => {
            result.signature = if provider.signer_revoked(key_id) {
                SignatureStatus::RevokedSigner
            } else {
                SignatureStatus::UnknownSigner
            };
            result.signer_identity = SignerIdentityStatus::Unknown;
            result.error = Some(if let Some(error) = provider.diagnostic_error() {
                error
            } else if provider.signer_revoked(key_id) {
                AttestationError::RevokedSigner
            } else {
                AttestationError::UnknownSigner
            });
        }
        Some(signer) if signer.algorithm != SignatureAlgorithmV1::Ed25519 => {
            result.signature = SignatureStatus::UnsupportedAlgorithm;
            result.signer_identity = SignerIdentityStatus::Unverified;
            result.error = Some(AttestationError::UnsupportedSignatureAlgorithm);
        }
        Some(signer) => {
            let pae = dsse_pae(payload_type.as_bytes(), &payload);
            let verified = VerifyingKey::from_bytes(&signer.public_key)
                .ok()
                .is_some_and(|key| key.verify_strict(&pae, &signature).is_ok());
            result.signature = if verified {
                if signer
                    .identity
                    .as_deref()
                    .is_some_and(|identity| !identity.is_empty() && identity.len() <= 256)
                {
                    result.signer_identity = SignerIdentityStatus::Verified;
                } else {
                    result.signer_identity = SignerIdentityStatus::Unknown;
                    result.error = Some(AttestationError::SignerIdentityUnverified);
                }
                SignatureStatus::Valid
            } else {
                result.signer_identity = SignerIdentityStatus::Unverified;
                SignatureStatus::Invalid
            };
            if !verified {
                result.error = Some(AttestationError::InvalidSignature);
            }
        }
    }

    if payload.len() > MAX_PAYLOAD_SIZE {
        result.syntax = SyntaxStatus::Malformed;
        return reject(&mut result, AttestationError::PayloadTooLarge);
    }
    let statement = match parse_bounded_json(&payload, MAX_JSON_STRING_SIZE) {
        Ok(value) => value,
        Err(_) => {
            result.syntax = SyntaxStatus::Malformed;
            return reject(&mut result, AttestationError::PayloadMalformed);
        }
    };
    let parsed_statement = match validate_statement(&statement, descriptor_sha256, &mut result) {
        Ok(statement) => statement,
        Err(error) => {
            result.syntax = if matches!(
                error,
                AttestationError::UnsupportedStatementVersion
                    | AttestationError::UnsupportedPredicateType
                    | AttestationError::UnsupportedPredicateSchema
            ) {
                SyntaxStatus::Unsupported
            } else {
                SyntaxStatus::Malformed
            };
            return reject(&mut result, error);
        }
    };
    result.syntax = SyntaxStatus::Valid;

    if result.signature != SignatureStatus::Valid
        || result.signer_identity != SignerIdentityStatus::Verified
    {
        if result.signature == SignatureStatus::UnknownSigner
            || result.signer_identity == SignerIdentityStatus::Unknown
        {
            result.builder_trust = BuilderTrustStatus::Unknown;
        }
        result.build_origin = BuildOriginStatus::Unverified;
        return result;
    }

    if result.subject != SubjectStatus::Matched {
        result.build_origin = BuildOriginStatus::Rejected;
        result.error = Some(match result.subject {
            SubjectStatus::Missing => AttestationError::SubjectMissing,
            SubjectStatus::Mismatch => AttestationError::SubjectMismatch,
            SubjectStatus::Ambiguous => AttestationError::SubjectAmbiguous,
            SubjectStatus::Malformed => AttestationError::SubjectMalformed,
            _ => AttestationError::SubjectMismatch,
        });
        return result;
    }

    let signer_identity = signer
        .as_ref()
        .and_then(|signer| signer.identity.as_deref())
        .expect("verified signer identity has a provider principal");
    let Some(builder_identity) = result.builder_identity_claimed.as_deref() else {
        result.build_origin = BuildOriginStatus::Rejected;
        return reject(&mut result, AttestationError::UnsupportedPredicateSchema);
    };
    match provider.builder_authority(signer_identity, builder_identity) {
        BuilderAuthorityV1::Unknown => {
            result.builder_trust = BuilderTrustStatus::Unknown;
            result.build_origin = BuildOriginStatus::Unverified;
            result.error = Some(AttestationError::BuilderAuthorityUnknown);
        }
        BuilderAuthorityV1::Untrusted => {
            result.builder_trust = BuilderTrustStatus::Untrusted;
            result.build_origin = BuildOriginStatus::Rejected;
            result.error = Some(AttestationError::BuilderUntrusted);
        }
        BuilderAuthorityV1::IdentityMismatch => {
            result.builder_trust = BuilderTrustStatus::IdentityMismatch;
            result.build_origin = BuildOriginStatus::Rejected;
            result.error = Some(AttestationError::BuilderIdentityMismatch);
        }
        BuilderAuthorityV1::Trusted(policy) => {
            if policy.builder_identity != builder_identity {
                result.builder_trust = BuilderTrustStatus::IdentityMismatch;
                result.build_origin = BuildOriginStatus::Rejected;
                result.error = Some(AttestationError::BuilderIdentityMismatch);
                return result;
            }
            result.builder_trust = BuilderTrustStatus::Trusted;
            result.applicable_policy_identity =
                provider.policy_identity(signer_identity, builder_identity);
            match check_build_parameters(parsed_statement.statement, &policy) {
                Ok(()) => {
                    result.build_parameters = BuildParametersStatus::Accepted;
                    if !provider.revalidate_trust_snapshot() {
                        result.invalidate_trust_snapshot();
                        return result;
                    }
                    result.independent_trust_establishment =
                        if provider.independent_trust_established() {
                            TrustEstablishmentStatus::Verified
                        } else {
                            TrustEstablishmentStatus::Unverified
                        };
                    result.build_origin = if result.subject == SubjectStatus::Matched
                        && provider.independent_trust_established()
                    {
                        BuildOriginStatus::Verified
                    } else {
                        BuildOriginStatus::Unverified
                    };
                }
                Err(AttestationError::UnexpectedBuildParameters) => {
                    result.build_parameters = BuildParametersStatus::Unexpected;
                    result.build_origin = BuildOriginStatus::Rejected;
                    result.error = Some(AttestationError::UnexpectedBuildParameters);
                }
                Err(AttestationError::UntrustedSourceRevision) => {
                    result.build_parameters = BuildParametersStatus::UntrustedSourceRevision;
                    result.build_origin = BuildOriginStatus::Rejected;
                    result.error = Some(AttestationError::UntrustedSourceRevision);
                }
                Err(error) => {
                    result.build_parameters = BuildParametersStatus::Rejected;
                    result.build_origin = BuildOriginStatus::Rejected;
                    result.error = Some(error);
                }
            }
        }
    }
    result
}

fn reject(result: &mut VerificationResult, error: AttestationError) -> VerificationResult {
    result.error = Some(error);
    result.build_origin = if matches!(
        error,
        AttestationError::SubjectMismatch
            | AttestationError::SubjectMissing
            | AttestationError::SubjectAmbiguous
            | AttestationError::SubjectMalformed
            | AttestationError::UnexpectedBuildParameters
            | AttestationError::UntrustedSourceRevision
            | AttestationError::BuilderUntrusted
            | AttestationError::BuilderIdentityMismatch
    ) {
        BuildOriginStatus::Rejected
    } else {
        BuildOriginStatus::Unverified
    };
    result.clone()
}

struct ParsedStatement<'a> {
    statement: &'a Value,
}

fn validate_statement<'a>(
    statement: &'a Value,
    descriptor_sha256: &[u8; 32],
    result: &mut VerificationResult,
) -> Result<ParsedStatement<'a>, AttestationError> {
    let object = statement
        .as_object()
        .ok_or(AttestationError::PayloadMalformed)?;
    if object.get("_type").and_then(Value::as_str) != Some(IN_TOTO_STATEMENT_V1) {
        return Err(AttestationError::UnsupportedStatementVersion);
    }
    let predicate_type = object
        .get("predicateType")
        .and_then(Value::as_str)
        .ok_or(AttestationError::PayloadMalformed)?;
    if predicate_type != SLSA_PROVENANCE_V1 {
        return Err(AttestationError::UnsupportedPredicateType);
    }
    let Some(subjects) = object.get("subject").and_then(Value::as_array) else {
        result.subject = SubjectStatus::Missing;
        return Err(AttestationError::SubjectMissing);
    };
    if subjects.is_empty() {
        result.subject = SubjectStatus::Missing;
        return Err(AttestationError::SubjectMissing);
    }
    result.subject = SubjectStatus::Malformed;
    let mut matching = 0usize;
    for subject in subjects {
        let subject_object = subject
            .as_object()
            .ok_or(AttestationError::SubjectMalformed)?;
        let digest_object = subject_object
            .get("digest")
            .and_then(Value::as_object)
            .ok_or(AttestationError::SubjectMalformed)?;
        if digest_object.len() != 1 || !digest_object.contains_key("sha256") {
            return Err(AttestationError::SubjectMalformed);
        }
        let digest_text = digest_object
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or(AttestationError::SubjectMalformed)?;
        let digest = decode_sha256(digest_text).ok_or(AttestationError::SubjectMalformed)?;
        if &digest == descriptor_sha256 {
            matching += 1;
        }
    }
    result.subject = match matching {
        0 => SubjectStatus::Mismatch,
        1 => SubjectStatus::Matched,
        _ => SubjectStatus::Ambiguous,
    };
    let predicate = object
        .get("predicate")
        .and_then(Value::as_object)
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let build_definition = predicate
        .get("buildDefinition")
        .and_then(Value::as_object)
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let build_type = build_definition
        .get("buildType")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let external_parameters = build_definition
        .get("externalParameters")
        .and_then(Value::as_object)
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let _ = external_parameters;
    let run_details = predicate
        .get("runDetails")
        .and_then(Value::as_object)
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let builder = run_details
        .get("builder")
        .and_then(Value::as_object)
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let builder_identity = builder
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    result.build_type = Some(build_type.to_owned());
    result.builder_identity_claimed = Some(builder_identity.to_owned());
    if let Some(dependencies) = build_definition.get("resolvedDependencies") {
        let dependencies = dependencies
            .as_array()
            .ok_or(AttestationError::UnsupportedPredicateSchema)?;
        let mut source_entries = Vec::new();
        for dependency in dependencies {
            let Some(dependency) = dependency.as_object() else {
                return Err(AttestationError::UnsupportedPredicateSchema);
            };
            let uri = dependency
                .get("uri")
                .and_then(Value::as_str)
                .filter(|uri| !uri.is_empty())
                .ok_or(AttestationError::UnsupportedPredicateSchema)?;
            let digest = dependency
                .get("digest")
                .and_then(Value::as_object)
                .ok_or(AttestationError::UnsupportedPredicateSchema)?;
            if digest.values().any(|value| !value.is_string()) {
                return Err(AttestationError::UnsupportedPredicateSchema);
            }
            if let Some(revision) = digest.get("gitCommit") {
                let revision = revision
                    .as_str()
                    .filter(|revision| valid_git_revision(revision))
                    .ok_or(AttestationError::UnsupportedPredicateSchema)?;
                source_entries.push((uri.to_owned(), revision.to_owned()));
            }
        }
        if source_entries.len() == 1 {
            let (uri, revision) = source_entries.pop().unwrap();
            result.source_uri = Some(uri);
            result.source_revision = Some(revision);
        }
    }
    Ok(ParsedStatement { statement })
}

fn check_build_parameters(
    statement: &Value,
    policy: &BuilderPolicyV1,
) -> Result<(), AttestationError> {
    let build_definition = statement
        .get("predicate")
        .and_then(|value| value.get("buildDefinition"))
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let build_type = build_definition
        .get("buildType")
        .and_then(Value::as_str)
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    let external_parameters = build_definition
        .get("externalParameters")
        .ok_or(AttestationError::UnsupportedPredicateSchema)?;
    if build_type != policy.build_type || external_parameters != &policy.external_parameters {
        return Err(AttestationError::UnexpectedBuildParameters);
    }
    if statement
        .get("predicate")
        .and_then(|value| value.get("buildDefinition"))
        .and_then(|value| value.get("resolvedDependencies"))
        .and_then(Value::as_array)
        .is_none()
    {
        return Err(AttestationError::UntrustedSourceRevision);
    }
    let mut source_matches = Vec::new();
    for dependency in statement
        .get("predicate")
        .and_then(|value| value.get("buildDefinition"))
        .and_then(|value| value.get("resolvedDependencies"))
        .and_then(Value::as_array)
        .ok_or(AttestationError::UntrustedSourceRevision)?
    {
        let Some(uri) = dependency.get("uri").and_then(Value::as_str) else {
            continue;
        };
        let Some(revision) = dependency
            .get("digest")
            .and_then(|value| value.get("gitCommit"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        source_matches.push((uri, revision));
    }
    if source_matches.len() != 1 || source_matches[0].0 != policy.source_uri {
        return Err(AttestationError::UntrustedSourceRevision);
    }
    if !policy.trusted_revisions.contains(source_matches[0].1) {
        return Err(AttestationError::UntrustedSourceRevision);
    }
    Ok(())
}

fn has_unknown_fields(object: &Map<String, Value>, known: &[&str]) -> bool {
    object.keys().any(|key| !known.contains(&key.as_str()))
}

fn valid_git_revision(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| {
            if byte.is_ascii_digit() {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        output[index] = (digit(chunk[0]) << 4) | digit(chunk[1]);
    }
    Some(output)
}

enum DecodeError {
    Invalid,
    TooLarge,
}

fn decode_base64(value: &str, maximum: usize) -> Result<Vec<u8>, DecodeError> {
    let decoded = [
        STANDARD.decode(value),
        STANDARD_NO_PAD.decode(value),
        URL_SAFE.decode(value),
        URL_SAFE_NO_PAD.decode(value),
    ]
    .into_iter()
    .filter_map(Result::ok)
    .collect::<Vec<_>>();
    let Some(first) = decoded.first() else {
        return Err(DecodeError::Invalid);
    };
    if decoded.iter().any(|candidate| candidate != first) {
        return Err(DecodeError::Invalid);
    }
    if first.len() > maximum {
        return Err(DecodeError::TooLarge);
    }
    Ok(first.clone())
}

fn encoded_limit(decoded_size: usize) -> usize {
    decoded_size.saturating_add(2) / 3 * 4 + 4
}

fn dsse_pae(payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::with_capacity(payload_type.len() + payload.len() + 48);
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type);
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

#[derive(Default)]
struct ParseBudget {
    nodes: usize,
    max_string: usize,
}

struct ValueSeed<'a> {
    budget: &'a mut ParseBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH || self.budget.nodes >= MAX_JSON_NODES {
            return Err(serde::de::Error::custom("JSON complexity limit"));
        }
        self.budget.nodes += 1;
        deserializer.deserialize_any(ValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct ValueVisitor<'a> {
    budget: &'a mut ParseBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > self.budget.max_string {
            return Err(E::custom("JSON string limit"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > self.budget.max_string {
            return Err(E::custom("JSON string limit"));
        }
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        ValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            budget: &mut *self.budget,
            depth: self.depth + 1,
        })? {
            if values.len() >= MAX_ARRAY_LENGTH {
                return Err(serde::de::Error::custom("JSON array limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map_access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map_access.next_key::<String>()? {
            if key.len() > self.budget.max_string {
                return Err(serde::de::Error::custom("JSON key limit"));
            }
            if values.len() >= MAX_OBJECT_FIELDS || values.contains_key(&key) {
                return Err(serde::de::Error::custom(
                    "duplicate key or JSON object limit",
                ));
            }
            let value = map_access.next_value_seed(ValueSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub(crate) fn parse_bounded_json(
    bytes: &[u8],
    max_string: usize,
) -> Result<Value, serde_json::Error> {
    let mut budget = ParseBudget {
        nodes: 0,
        max_string,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = ValueSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn escape_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.push_str(&format!("\\u{{{:04x}}}", character as u32));
        } else {
            escaped.push(character);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const SOURCE_URI: &str = "git+https://example.invalid/acme/ios-app";
    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const BUILD_TYPE: &str = "https://example.invalid/buildtypes/ios-release/v1";

    struct FixtureProvider {
        signing: SigningKey,
        signer: SignerV1,
        policy: Option<BuilderPolicyV1>,
    }

    impl FixtureProvider {
        fn trusted() -> Self {
            let signing = SigningKey::from_bytes(&[0x41; 32]);
            let signer = SignerV1 {
                identity: Some("fixture-signing-service".to_owned()),
                algorithm: SignatureAlgorithmV1::Ed25519,
                public_key: signing.verifying_key().to_bytes(),
            };
            let mut trusted_revisions = BTreeSet::new();
            trusted_revisions.insert(REVISION.to_owned());
            Self {
                signing,
                signer,
                policy: Some(BuilderPolicyV1 {
                    builder_identity: "https://example.invalid/builders/fixture-v1".to_owned(),
                    build_type: BUILD_TYPE.to_owned(),
                    external_parameters: json!({"repository": SOURCE_URI, "revision": REVISION}),
                    source_uri: SOURCE_URI.to_owned(),
                    trusted_revisions,
                }),
            }
        }

        fn key_id(&self) -> &'static str {
            "synthetic-builder-key-v1"
        }

        fn signed_envelope(&self, payload: &[u8], payload_type: &str) -> Vec<u8> {
            let signature = self
                .signing
                .sign(&dsse_pae(payload_type.as_bytes(), payload));
            serde_json::to_vec(&json!({
                "payloadType": payload_type,
                "payload": STANDARD.encode(payload),
                "signatures": [{
                    "keyid": self.key_id(),
                    "sig": STANDARD.encode(signature.to_bytes()),
                }],
            }))
            .unwrap()
        }
    }

    impl BuilderVerificationProviderV1 for FixtureProvider {
        fn signer(&self, key_id: &str) -> Option<SignerV1> {
            (key_id == self.key_id()).then(|| self.signer.clone())
        }

        fn builder_authority(
            &self,
            signer_identity: &str,
            builder_identity: &str,
        ) -> BuilderAuthorityV1 {
            if Some(signer_identity) != self.signer.identity.as_deref() {
                return BuilderAuthorityV1::Unknown;
            }
            match &self.policy {
                Some(policy) if policy.builder_identity == builder_identity => {
                    BuilderAuthorityV1::Trusted(policy.clone())
                }
                Some(_) => BuilderAuthorityV1::IdentityMismatch,
                None => BuilderAuthorityV1::Untrusted,
            }
        }

        fn independent_trust_established(&self) -> bool {
            true
        }
    }

    fn descriptor_digest() -> [u8; 32] {
        Sha256::digest(b"opened descriptor bytes").into()
    }

    fn statement_json(digest: &str, revision: &str) -> Value {
        json!({
            "_type": IN_TOTO_STATEMENT_V1,
            "subject": [{"name": "ios-app", "digest": {"sha256": digest}}],
            "predicateType": SLSA_PROVENANCE_V1,
            "predicate": {
                "buildDefinition": {
                    "buildType": BUILD_TYPE,
                    "externalParameters": {"repository": SOURCE_URI, "revision": REVISION},
                    "resolvedDependencies": [{
                        "uri": SOURCE_URI,
                        "digest": {"gitCommit": revision},
                    }],
                },
                "runDetails": {
                    "builder": {"id": "https://example.invalid/builders/fixture-v1"},
                },
            },
        })
    }

    fn signed_statement(provider: &FixtureProvider, statement: &Value) -> Vec<u8> {
        provider.signed_envelope(&serde_json::to_vec(statement).unwrap(), DSSE_PAYLOAD_TYPE)
    }

    fn good(provider: &FixtureProvider) -> Vec<u8> {
        let digest = hex(&descriptor_digest());
        signed_statement(provider, &statement_json(&digest, REVISION))
    }

    #[test]
    fn verifies_dsse_statement_subject_builder_and_parameters_with_real_ed25519() {
        let provider = FixtureProvider::trusted();
        let result = verify_bytes(&good(&provider), &descriptor_digest(), &provider);
        assert_eq!(result.syntax, SyntaxStatus::Valid);
        assert_eq!(result.signature, SignatureStatus::Valid);
        assert_eq!(result.signer_identity, SignerIdentityStatus::Verified);
        assert_eq!(result.subject, SubjectStatus::Matched);
        assert_eq!(result.builder_trust, BuilderTrustStatus::Trusted);
        assert_eq!(result.build_parameters, BuildParametersStatus::Accepted);
        assert_eq!(result.build_origin, BuildOriginStatus::Verified);
        assert_eq!(result.source_revision.as_deref(), Some(REVISION));
        assert_eq!(result.build_type.as_deref(), Some(BUILD_TYPE));
    }

    #[test]
    fn exact_external_parameters_compare_structurally_across_json_key_order() {
        let provider = FixtureProvider::trusted();
        let statement = statement_json(&hex(&descriptor_digest()), REVISION);
        let canonical = String::from_utf8(serde_json::to_vec(&statement).unwrap()).unwrap();
        let reordered = canonical.replace(
            "\"externalParameters\":{\"repository\":\"git+https://example.invalid/acme/ios-app\",\"revision\":\"0123456789abcdef0123456789abcdef01234567\"}",
            "\"externalParameters\":{\"revision\":\"0123456789abcdef0123456789abcdef01234567\",\"repository\":\"git+https://example.invalid/acme/ios-app\"}",
        );
        assert_ne!(canonical, reordered);
        let envelope = provider.signed_envelope(reordered.as_bytes(), DSSE_PAYLOAD_TYPE);
        let result = verify_bytes(&envelope, &descriptor_digest(), &provider);
        assert_eq!(result.signature, SignatureStatus::Valid);
        assert_eq!(result.build_parameters, BuildParametersStatus::Accepted);
        assert_eq!(result.build_origin, BuildOriginStatus::Verified);
    }

    #[test]
    fn invalid_dsse_signature_and_payload_change_after_signing_fail() {
        let provider = FixtureProvider::trusted();
        let mut envelope: Value = serde_json::from_slice(&good(&provider)).unwrap();
        let mut payload = STANDARD
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap();
        let changed = payload
            .windows(b"fixture-v1".len())
            .position(|window| window == b"fixture-v1")
            .unwrap();
        payload[changed] ^= 1;
        envelope["payload"] = Value::String(STANDARD.encode(payload));
        let changed = serde_json::to_vec(&envelope).unwrap();
        let result = verify_bytes(&changed, &descriptor_digest(), &provider);
        assert_eq!(result.signature, SignatureStatus::Invalid);
        assert_eq!(result.build_origin, BuildOriginStatus::Unverified);
    }

    #[test]
    fn rejects_wrong_payload_type_statement_version_and_predicate_version() {
        let provider = FixtureProvider::trusted();
        let statement = statement_json(&hex(&descriptor_digest()), REVISION);
        let wrong_type =
            provider.signed_envelope(&serde_json::to_vec(&statement).unwrap(), "application/json");
        assert_eq!(
            verify_bytes(&wrong_type, &descriptor_digest(), &provider).error,
            Some(AttestationError::UnsupportedPayloadType)
        );

        let mut unsupported_statement = statement.clone();
        unsupported_statement["_type"] = json!("https://in-toto.io/Statement/v2");
        let result = verify_bytes(
            &signed_statement(&provider, &unsupported_statement),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(
            result.error,
            Some(AttestationError::UnsupportedStatementVersion)
        );

        let mut unsupported_predicate = statement;
        unsupported_predicate["predicateType"] = json!("https://slsa.dev/provenance/v2");
        let result = verify_bytes(
            &signed_statement(&provider, &unsupported_predicate),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(
            result.error,
            Some(AttestationError::UnsupportedPredicateType)
        );
    }

    #[test]
    fn enforces_unique_exact_sha256_subject_binding() {
        let provider = FixtureProvider::trusted();
        let good_statement = statement_json(&hex(&descriptor_digest()), REVISION);
        let good_result = verify_bytes(
            &signed_statement(&provider, &good_statement),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(good_result.subject, SubjectStatus::Matched);

        let wrong = statement_json(&"00".repeat(32), REVISION);
        let wrong_result = verify_bytes(
            &signed_statement(&provider, &wrong),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(wrong_result.subject, SubjectStatus::Mismatch);
        assert_eq!(wrong_result.syntax, SyntaxStatus::Valid);

        let mut ambiguous = good_statement;
        ambiguous["subject"]
            .as_array_mut()
            .unwrap()
            .push(json!({"digest": {"sha256": hex(&descriptor_digest())}}));
        let ambiguous_result = verify_bytes(
            &signed_statement(&provider, &ambiguous),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(ambiguous_result.subject, SubjectStatus::Ambiguous);
        assert_eq!(ambiguous_result.syntax, SyntaxStatus::Valid);
    }

    #[test]
    fn unknown_signer_and_untrusted_builder_are_independent_failures() {
        let provider = FixtureProvider::trusted();
        let envelope = good(&provider);
        struct UnknownSigner;
        impl BuilderVerificationProviderV1 for UnknownSigner {
            fn signer(&self, _: &str) -> Option<SignerV1> {
                None
            }
            fn builder_authority(&self, _: &str, _: &str) -> BuilderAuthorityV1 {
                BuilderAuthorityV1::Unknown
            }
        }
        let unknown = verify_bytes(&envelope, &descriptor_digest(), &UnknownSigner);
        assert_eq!(unknown.signature, SignatureStatus::UnknownSigner);
        assert_eq!(unknown.signer_identity, SignerIdentityStatus::Unknown);
        assert_eq!(
            unknown.builder_identity_claimed.as_deref(),
            Some("https://example.invalid/builders/fixture-v1")
        );

        struct UnmappedSigner(FixtureProvider);
        impl BuilderVerificationProviderV1 for UnmappedSigner {
            fn signer(&self, key_id: &str) -> Option<SignerV1> {
                self.0.signer(key_id).map(|mut signer| {
                    signer.identity = None;
                    signer
                })
            }
            fn builder_authority(&self, _: &str, _: &str) -> BuilderAuthorityV1 {
                BuilderAuthorityV1::Unknown
            }
        }
        let unmapped = verify_bytes(
            &envelope,
            &descriptor_digest(),
            &UnmappedSigner(FixtureProvider::trusted()),
        );
        assert_eq!(unmapped.signature, SignatureStatus::Valid);
        assert_eq!(unmapped.signer_identity, SignerIdentityStatus::Unknown);
        assert_eq!(unmapped.builder_trust, BuilderTrustStatus::Unknown);
        assert_eq!(unmapped.build_origin, BuildOriginStatus::Unverified);

        struct UnknownBuilder(FixtureProvider);
        impl BuilderVerificationProviderV1 for UnknownBuilder {
            fn signer(&self, key_id: &str) -> Option<SignerV1> {
                self.0.signer(key_id)
            }
            fn builder_authority(&self, _: &str, _: &str) -> BuilderAuthorityV1 {
                BuilderAuthorityV1::Unknown
            }
        }
        let unknown_builder = verify_bytes(
            &envelope,
            &descriptor_digest(),
            &UnknownBuilder(FixtureProvider::trusted()),
        );
        assert_eq!(unknown_builder.signature, SignatureStatus::Valid);
        assert_eq!(
            unknown_builder.signer_identity,
            SignerIdentityStatus::Verified
        );
        assert_eq!(unknown_builder.builder_trust, BuilderTrustStatus::Unknown);
        assert_eq!(unknown_builder.build_origin, BuildOriginStatus::Unverified);

        let mut untrusted = FixtureProvider::trusted();
        untrusted.policy = None;
        let result = verify_bytes(&envelope, &descriptor_digest(), &untrusted);
        assert_eq!(result.signature, SignatureStatus::Valid);
        assert_eq!(result.builder_trust, BuilderTrustStatus::Untrusted);
        assert_eq!(result.build_origin, BuildOriginStatus::Rejected);
    }

    #[test]
    fn rejects_builder_mismatch_unexpected_parameters_and_modified_source_revision() {
        let provider = FixtureProvider::trusted();
        let mut wrong_builder = statement_json(&hex(&descriptor_digest()), REVISION);
        wrong_builder["predicate"]["runDetails"]["builder"]["id"] =
            json!("https://example.invalid/builders/wrong-v1");
        let mismatch_result = verify_bytes(
            &signed_statement(&provider, &wrong_builder),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(
            mismatch_result.builder_trust,
            BuilderTrustStatus::IdentityMismatch
        );

        let mut unexpected = statement_json(&hex(&descriptor_digest()), REVISION);
        unexpected["predicate"]["buildDefinition"]["externalParameters"]["flag"] = json!(true);
        let unexpected_result = verify_bytes(
            &signed_statement(&provider, &unexpected),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(
            unexpected_result.build_parameters,
            BuildParametersStatus::Unexpected
        );

        let modified_source = statement_json(
            &hex(&descriptor_digest()),
            "ffffffffffffffffffffffffffffffffffffffff",
        );
        let source_result = verify_bytes(
            &signed_statement(&provider, &modified_source),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(
            source_result.build_parameters,
            BuildParametersStatus::UntrustedSourceRevision
        );
    }

    #[test]
    fn malformed_duplicate_oversized_and_truncated_envelopes_fail_closed() {
        let provider = FixtureProvider::trusted();
        let malformed = b"{\"payloadType\":";
        assert_eq!(
            verify_bytes(malformed, &descriptor_digest(), &provider).error,
            Some(AttestationError::EnvelopeMalformed)
        );
        let duplicate = br#"{"payloadType":"application/vnd.in-toto+json","payloadType":"application/vnd.in-toto+json","payload":"","signatures":[]}"#;
        assert_eq!(
            verify_bytes(duplicate, &descriptor_digest(), &provider).error,
            Some(AttestationError::EnvelopeMalformed)
        );
        let oversized = vec![b' '; MAX_ENVELOPE_SIZE + 1];
        assert_eq!(
            verify_bytes(&oversized, &descriptor_digest(), &provider).error,
            Some(AttestationError::EnvelopeTooLarge)
        );

        let mut envelope: Value = serde_json::from_slice(&good(&provider)).unwrap();
        let shortened = STANDARD
            .decode(envelope["signatures"][0]["sig"].as_str().unwrap())
            .unwrap();
        envelope["signatures"][0]["sig"] = json!(STANDARD.encode(&shortened[..60]));
        let truncated = verify_bytes(
            &serde_json::to_vec(&envelope).unwrap(),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(truncated.signature, SignatureStatus::Truncated);
    }

    #[test]
    fn enforces_payload_nesting_array_and_string_limits() {
        let too_deep = format!(
            "{}null{}",
            "[".repeat(MAX_JSON_DEPTH + 2),
            "]".repeat(MAX_JSON_DEPTH + 2)
        );
        assert!(parse_bounded_json(too_deep.as_bytes(), MAX_JSON_STRING_SIZE).is_err());

        let too_many = format!(
            "[{}]",
            std::iter::repeat("null")
                .take(MAX_ARRAY_LENGTH + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(parse_bounded_json(too_many.as_bytes(), MAX_JSON_STRING_SIZE).is_err());

        let too_long = format!("\"{}\"", "x".repeat(MAX_JSON_STRING_SIZE + 1));
        assert!(parse_bounded_json(too_long.as_bytes(), MAX_JSON_STRING_SIZE).is_err());
    }

    #[test]
    fn rejects_decoded_payload_above_its_separate_limit() {
        let provider = FixtureProvider::trusted();
        let payload = vec![b'x'; MAX_PAYLOAD_SIZE + 1];
        let envelope = serde_json::to_vec(&json!({
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": STANDARD.encode(payload),
            "signatures": [{"keyid": provider.key_id(), "sig": STANDARD.encode([0u8; 64])}],
        }))
        .unwrap();
        assert!(envelope.len() < MAX_ENVELOPE_SIZE);
        assert_eq!(
            verify_bytes(&envelope, &descriptor_digest(), &provider).error,
            Some(AttestationError::PayloadTooLarge)
        );
    }

    #[test]
    fn malformed_signed_json_and_duplicate_security_fields_are_rejected() {
        let provider = FixtureProvider::trusted();
        let malformed = provider.signed_envelope(b"{", DSSE_PAYLOAD_TYPE);
        let malformed_result = verify_bytes(&malformed, &descriptor_digest(), &provider);
        assert_eq!(malformed_result.signature, SignatureStatus::Valid);
        assert_eq!(malformed_result.syntax, SyntaxStatus::Malformed);

        let duplicate_payload = br#"{"_type":"https://in-toto.io/Statement/v1","_type":"https://in-toto.io/Statement/v1"}"#;
        let duplicate_result = verify_bytes(
            &provider.signed_envelope(duplicate_payload, DSSE_PAYLOAD_TYPE),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(
            duplicate_result.error,
            Some(AttestationError::PayloadMalformed)
        );
    }

    #[test]
    fn provider_algorithm_is_out_of_band_and_unsupported_algorithms_fail() {
        struct UnsupportedProvider(FixtureProvider);
        impl BuilderVerificationProviderV1 for UnsupportedProvider {
            fn signer(&self, key_id: &str) -> Option<SignerV1> {
                self.0.signer(key_id).map(|mut signer| {
                    signer.algorithm = SignatureAlgorithmV1::Unsupported;
                    signer
                })
            }
            fn builder_authority(&self, signer: &str, builder: &str) -> BuilderAuthorityV1 {
                self.0.builder_authority(signer, builder)
            }
        }
        let provider = FixtureProvider::trusted();
        let result = verify_bytes(
            &good(&provider),
            &descriptor_digest(),
            &UnsupportedProvider(provider),
        );
        assert_eq!(result.signature, SignatureStatus::UnsupportedAlgorithm);
    }

    #[test]
    fn production_provider_has_no_signers_or_builder_roots() {
        let fixture = FixtureProvider::trusted();
        let result = verify_bytes(
            &good(&fixture),
            &descriptor_digest(),
            &UnconfiguredBuilderProviderV1,
        );
        assert_eq!(result.signature, SignatureStatus::UnknownSigner);
        assert_eq!(result.builder_trust, BuilderTrustStatus::Unknown);
        assert_eq!(result.build_origin, BuildOriginStatus::Unverified);
    }

    #[test]
    fn rejects_unsupported_builder_provider_version() {
        struct UnsupportedVersion;
        impl BuilderVerificationProviderV1 for UnsupportedVersion {
            fn version(&self) -> u32 {
                PROVIDER_VERSION_V1 + 1
            }
            fn signer(&self, _: &str) -> Option<SignerV1> {
                None
            }
            fn builder_authority(&self, _: &str, _: &str) -> BuilderAuthorityV1 {
                BuilderAuthorityV1::Unknown
            }
        }
        let result = verify_bytes(b"{}", &descriptor_digest(), &UnsupportedVersion);
        assert_eq!(
            result.error,
            Some(AttestationError::ProviderVersionUnsupported)
        );
    }

    #[test]
    fn diagnostic_escapes_control_characters_from_signed_claims() {
        let result = VerificationResult {
            builder_identity_claimed: Some("builder\n\u{1b}[31m".to_owned()),
            ..VerificationResult::default()
        };
        let rendered = result.render();
        assert!(rendered.contains(r"builder\u{000a}\u{001b}[31m"));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn rejects_missing_subject_wrong_digest_algorithm_and_malformed_digest() {
        let provider = FixtureProvider::trusted();
        let mut missing = statement_json(&hex(&descriptor_digest()), REVISION);
        missing["subject"] = json!([]);
        let missing_result = verify_bytes(
            &signed_statement(&provider, &missing),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(missing_result.subject, SubjectStatus::Missing);

        let mut wrong_algorithm = statement_json(&hex(&descriptor_digest()), REVISION);
        wrong_algorithm["subject"][0]["digest"] = json!({"sha512": "00".repeat(64)});
        let algorithm_result = verify_bytes(
            &signed_statement(&provider, &wrong_algorithm),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(algorithm_result.subject, SubjectStatus::Malformed);

        let mut malformed = statement_json(&hex(&descriptor_digest()), REVISION);
        malformed["subject"][0]["digest"]["sha256"] = json!("not-a-digest");
        let malformed_result = verify_bytes(
            &signed_statement(&provider, &malformed),
            &descriptor_digest(),
            &provider,
        );
        assert_eq!(malformed_result.subject, SubjectStatus::Malformed);
    }
}
