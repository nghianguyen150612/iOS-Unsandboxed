//! Deterministic, read-only builder trust mutation planning.
//!
//! Plans are diagnostics only. This module never writes the builder trust
//! directory and its output is not authority for a future privileged helper.

use crate::builder_transaction::{parse_journal, parse_marker};
use crate::builder_trust::{
    checked_identity, checked_uri, decode_hex, derive_key_id, derive_policy_id, hex, lower_hex,
    parse_policy_store, parse_root_store, valid_revision, BuilderMutationBaseV1,
    LocalBuilderVerificationProviderV1, PolicyRecordV1, PolicyStoreV1, RootRecordV1, RootStoreV1,
    MAX_POLICIES, MAX_SIGNING_KEYS, MAX_STORE_BYTES,
};
use ed25519_dalek::VerifyingKey;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_POLICY_INPUT_BYTES: usize = MAX_STORE_BYTES;
const MAX_KEY_INPUT_BYTES: usize = 65;

#[derive(Debug, Clone, PartialEq)]
pub enum BuilderMutationRequestV1 {
    AddSigner {
        public_key: [u8; 32],
        signer_identity: String,
        enrollment_reference: Option<String>,
    },
    RevokeSigner {
        key_id: String,
    },
    RotateSigner {
        old_key_id: String,
        new_public_key: [u8; 32],
        new_signer_identity: String,
        enrollment_reference: Option<String>,
    },
    AddPolicy {
        policy: PolicyRecordV1,
    },
    RevokePolicy {
        policy_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderMutationKindV1 {
    AddSigner,
    RevokeSigner,
    RotateSigner,
    AddPolicy,
    RevokePolicy,
}

impl BuilderMutationKindV1 {
    fn label(self) -> &'static str {
        match self {
            Self::AddSigner => "ADD_SIGNER",
            Self::RevokeSigner => "REVOKE_SIGNER",
            Self::RotateSigner => "ROTATE_SIGNER",
            Self::AddPolicy => "ADD_POLICY",
            Self::RevokePolicy => "REVOKE_POLICY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderMutationPlanV1 {
    pub operation: BuilderMutationKindV1,
    pub changed: bool,
    pub current_roots_generation: Option<u64>,
    pub proposed_roots_generation: Option<u64>,
    pub current_policies_generation: Option<u64>,
    pub proposed_policies_generation: Option<u64>,
    pub current_roots_sha256: Option<String>,
    pub proposed_roots_sha256: Option<String>,
    pub current_policies_sha256: Option<String>,
    pub proposed_policies_sha256: Option<String>,
    pub affected_key_ids: Vec<String>,
    pub affected_policy_ids: Vec<String>,
    pub proposed_roots_bytes: Option<Vec<u8>>,
    pub proposed_policies_bytes: Option<Vec<u8>>,
    pub expected_transaction: Option<Vec<u8>>,
    pub proposed_state_marker: Option<Vec<u8>>,
    pub warnings: Vec<String>,
}

impl BuilderMutationPlanV1 {
    pub fn render(&self) -> String {
        let mut output = format!(
            "Builder mutation plan: {}\nChange: {}\nRoot generation: {} -> {}\nRoot SHA-256: {} -> {}\nPolicy generation: {} -> {}\nPolicy SHA-256: {} -> {}\n",
            self.operation.label(),
            if self.changed { "PROPOSED" } else { "NO_OP" },
            opt_number(self.current_roots_generation),
            opt_number(self.proposed_roots_generation),
            opt_text(&self.current_roots_sha256),
            opt_text(&self.proposed_roots_sha256),
            opt_number(self.current_policies_generation),
            opt_number(self.proposed_policies_generation),
            opt_text(&self.current_policies_sha256),
            opt_text(&self.proposed_policies_sha256),
        );
        output.push_str(&format!(
            "Affected key IDs: {}\nAffected policy IDs: {}\nTransaction: {}\nPersistence: NOT_APPLIED\nIndependent trust establishment: UNVERIFIED\nOperational authorization: FALSE\nExecution activation: disabled\n",
            list(&self.affected_key_ids),
            list(&self.affected_policy_ids),
            if self.expected_transaction.is_some() { "PLANNED_PREPARED_JOURNAL" } else { "NONE (NO_OP)" },
        ));
        if let Some(bytes) = &self.proposed_roots_bytes {
            output.push_str("Proposed roots.v1 (canonical JSON):\n");
            output.push_str(std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8>"));
            output.push('\n');
        }
        if let Some(bytes) = &self.proposed_policies_bytes {
            output.push_str("Proposed policies.v1 (canonical JSON):\n");
            output.push_str(std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8>"));
            output.push('\n');
        }
        if let Some(bytes) = &self.expected_transaction {
            output.push_str("Expected transaction.v1 (not written):\n");
            output.push_str(std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8>"));
        }
        if let Some(bytes) = &self.proposed_state_marker {
            output.push_str("Proposed state.v1 (not written):\n");
            output.push_str(std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8>"));
        }
        for warning in &self.warnings {
            output.push_str(&format!("Warning: {warning}\n"));
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationError(pub String);

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MutationError {}

/// Loads one canonical Ed25519 public-key text file: 64 lowercase hexadecimal
/// characters followed by exactly one LF. Private-key formats are rejected.
pub fn read_public_key_file(path: &Path) -> Result<[u8; 32], MutationError> {
    let bytes = read_bounded_input(path, MAX_KEY_INPUT_BYTES)?;
    if bytes.len() != 65 || bytes[64] != b'\n' || bytes[..64].contains(&b'\n') {
        return Err(MutationError(
            "public key must be 64 lowercase hexadecimal characters followed by LF".into(),
        ));
    }
    let text = std::str::from_utf8(&bytes[..64])
        .map_err(|_| MutationError("public key input is not ASCII hexadecimal".into()))?;
    let key = decode_hex::<32>(text).ok_or_else(|| {
        MutationError("public key must use canonical lowercase hexadecimal".into())
    })?;
    validate_public_key(&key)?;
    Ok(key)
}

/// Parses a bounded policy request JSON document. Input key order and
/// whitespace are immaterial; duplicate JSON fields are rejected by the
/// existing bounded parser and output is always serialized canonically.
pub fn read_policy_file(path: &Path) -> Result<PolicyRecordV1, MutationError> {
    let bytes = read_bounded_input(path, MAX_POLICY_INPUT_BYTES)?;
    parse_policy_request(&bytes)
}

pub fn plan_production(
    request: BuilderMutationRequestV1,
) -> Result<BuilderMutationPlanV1, MutationError> {
    let provider = LocalBuilderVerificationProviderV1::production();
    plan_with_provider(&provider, request)
}

fn plan_with_provider(
    provider: &LocalBuilderVerificationProviderV1,
    request: BuilderMutationRequestV1,
) -> Result<BuilderMutationPlanV1, MutationError> {
    let base = provider.mutation_base().map_err(|error| {
        MutationError(format!(
            "builder trust state is not plannable: {}",
            error.message
        ))
    })?;
    let plan = plan_from_base(&base, request)?;
    provider.revalidate_mutation_base(&base).map_err(|error| {
        MutationError(format!("builder trust snapshot changed: {}", error.message))
    })?;
    Ok(plan)
}

fn plan_from_base(
    base: &BuilderMutationBaseV1,
    request: BuilderMutationRequestV1,
) -> Result<BuilderMutationPlanV1, MutationError> {
    validate_base_digest(base)?;
    let operation = match request {
        BuilderMutationRequestV1::AddSigner { .. } => BuilderMutationKindV1::AddSigner,
        BuilderMutationRequestV1::RevokeSigner { .. } => BuilderMutationKindV1::RevokeSigner,
        BuilderMutationRequestV1::RotateSigner { .. } => BuilderMutationKindV1::RotateSigner,
        BuilderMutationRequestV1::AddPolicy { .. } => BuilderMutationKindV1::AddPolicy,
        BuilderMutationRequestV1::RevokePolicy { .. } => BuilderMutationKindV1::RevokePolicy,
    };
    let mut roots = base.roots.clone().unwrap_or_else(empty_roots);
    let mut policies = base.policies.clone().unwrap_or_else(empty_policies);
    let initial_root_keys = roots.keys.clone();
    let initial_policy_records = policies.policies.clone();
    let mut affected_key_ids = Vec::new();
    let mut affected_policy_ids = Vec::new();
    let mut warnings = Vec::new();

    match request {
        BuilderMutationRequestV1::AddSigner {
            public_key,
            signer_identity,
            enrollment_reference,
        } => {
            let signer_identity = exact_identity(signer_identity)?;
            validate_public_key(&public_key)?;
            validate_enrollment_reference(enrollment_reference.as_deref())?;
            let key_id = derive_key_id(&public_key);
            if roots.keys.contains_key(&key_id) {
                return Err(MutationError(
                    "key ID already exists; revoked keys cannot be re-enrolled".into(),
                ));
            }
            if roots
                .keys
                .values()
                .any(|record| record.signer_identity == signer_identity)
            {
                return Err(MutationError(
                    "signer identity already exists in schema v1".into(),
                ));
            }
            if roots.keys.len() >= MAX_SIGNING_KEYS {
                return Err(MutationError("signer key count limit reached".into()));
            }
            roots.keys.insert(
                key_id.clone(),
                RootRecordV1 {
                    key_id: key_id.clone(),
                    algorithm: "Ed25519".into(),
                    public_key,
                    signer_identity,
                    state: "active".into(),
                    enrollment_reference,
                },
            );
            affected_key_ids.push(key_id);
            warnings.push(
                "local key installation is not independent authentication of a CI identity".into(),
            );
        }
        BuilderMutationRequestV1::RevokeSigner { key_id } => {
            validate_key_id(&key_id)?;
            let record = roots
                .keys
                .get_mut(&key_id)
                .ok_or_else(|| MutationError("unknown signer key ID".into()))?;
            if record.state == "active" {
                record.state = "revoked".into();
                affected_key_ids.push(key_id.clone());
                for policy in policies.policies.values().filter(|policy| {
                    policy.signer_identity == record.signer_identity && policy.state == "active"
                }) {
                    affected_policy_ids.push(policy.policy_id.clone());
                }
                if !affected_policy_ids.is_empty() {
                    warnings.push("revoking this signer makes its listed active policies unusable; policies are retained".into());
                }
            }
        }
        BuilderMutationRequestV1::RotateSigner {
            old_key_id,
            new_public_key,
            new_signer_identity,
            enrollment_reference,
        } => {
            validate_key_id(&old_key_id)?;
            validate_public_key(&new_public_key)?;
            validate_enrollment_reference(enrollment_reference.as_deref())?;
            let identity = exact_identity(new_signer_identity)?;
            let old = roots
                .keys
                .get(&old_key_id)
                .ok_or_else(|| MutationError("unknown old signer key ID".into()))?;
            if old.state != "active" {
                return Err(MutationError("rotation requires an active old key".into()));
            }
            if old.signer_identity == identity {
                return Err(MutationError(
                    "schema v1 rotation requires a different signer identity".into(),
                ));
            }
            let new_key_id = derive_key_id(&new_public_key);
            if roots.keys.contains_key(&new_key_id) {
                return Err(MutationError(
                    "new key ID already exists; revoked keys cannot be reactivated".into(),
                ));
            }
            if roots
                .keys
                .values()
                .any(|record| record.signer_identity == identity)
            {
                return Err(MutationError(
                    "new signer identity already exists in schema v1".into(),
                ));
            }
            if roots.keys.len() >= MAX_SIGNING_KEYS {
                return Err(MutationError("signer key count limit reached".into()));
            }
            let old_identity = old.signer_identity.clone();
            roots
                .keys
                .get_mut(&old_key_id)
                .expect("looked up above")
                .state = "revoked".into();
            roots.keys.insert(
                new_key_id.clone(),
                RootRecordV1 {
                    key_id: new_key_id.clone(),
                    algorithm: "Ed25519".into(),
                    public_key: new_public_key,
                    signer_identity: identity,
                    state: "active".into(),
                    enrollment_reference,
                },
            );
            affected_key_ids.extend([old_key_id, new_key_id]);
            for policy in policies
                .policies
                .values()
                .filter(|policy| policy.signer_identity == old_identity && policy.state == "active")
            {
                affected_policy_ids.push(policy.policy_id.clone());
            }
            warnings.push("builder policies were not migrated; create separately reviewed policies for the new identity".into());
            warnings.push(
                "schema v1 does not support same-identity rotation with retained tombstones".into(),
            );
        }
        BuilderMutationRequestV1::AddPolicy { mut policy } => {
            let roots_store = base.roots.as_ref().ok_or_else(|| {
                MutationError("an active signer must be enrolled before policy planning".into())
            })?;
            let signer = roots_store
                .keys
                .values()
                .find(|record| record.signer_identity == policy.signer_identity)
                .ok_or_else(|| MutationError("policy signer identity is unknown".into()))?;
            if signer.state != "active" {
                return Err(MutationError(
                    "revoked signer cannot receive an active policy".into(),
                ));
            }
            policy.state = "active".into();
            policy.policy_id.clear();
            validate_policy_record(&policy)?;
            if policies.policies.values().any(|existing| {
                existing.signer_identity == policy.signer_identity
                    && existing.builder_id == policy.builder_id
            }) {
                return Err(MutationError(
                    "schema v1 already contains this signer/builder pair".into(),
                ));
            }
            if policies.policies.len() >= MAX_POLICIES {
                return Err(MutationError("builder policy count limit reached".into()));
            }
            policy.policy_id = derive_policy_id(&policy).map_err(store_error)?;
            if policies.policies.contains_key(&policy.policy_id) {
                return Err(MutationError("derived policy ID already exists".into()));
            }
            affected_policy_ids.push(policy.policy_id.clone());
            policies.policies.insert(policy.policy_id.clone(), policy);
            warnings.push("policy authorization remains local policy only; independent trust establishment is unverified".into());
        }
        BuilderMutationRequestV1::RevokePolicy { policy_id } => {
            validate_policy_id(&policy_id)?;
            let Some(old) = policies.policies.get(&policy_id).cloned() else {
                // Revocation changes the v1 policy ID because state is part of
                // its digest. Accept the original active ID as a no-op alias
                // once its corresponding revoked record is present.
                let already_revoked = policies.policies.values().any(|record| {
                    if record.state != "revoked" {
                        return false;
                    }
                    let mut active = record.clone();
                    active.state = "active".into();
                    derive_policy_id(&active).is_ok_and(|active_id| active_id == policy_id)
                });
                if already_revoked {
                    return Ok(BuilderMutationPlanV1 {
                        operation,
                        changed: false,
                        current_roots_generation: base.root_generation,
                        proposed_roots_generation: base.root_generation,
                        current_policies_generation: base.policy_generation,
                        proposed_policies_generation: base.policy_generation,
                        current_roots_sha256: base.root_digest.map(|digest| hex(&digest)),
                        proposed_roots_sha256: base.root_digest.map(|digest| hex(&digest)),
                        current_policies_sha256: base.policy_digest.map(|digest| hex(&digest)),
                        proposed_policies_sha256: base.policy_digest.map(|digest| hex(&digest)),
                        affected_key_ids,
                        affected_policy_ids: vec![policy_id],
                        proposed_roots_bytes: None,
                        proposed_policies_bytes: None,
                        expected_transaction: None,
                        proposed_state_marker: None,
                        warnings,
                    });
                }
                return Err(MutationError("unknown policy ID".into()));
            };
            if old.state == "active" {
                let mut revoked = old;
                revoked.state = "revoked".into();
                let old_id = revoked.policy_id.clone();
                revoked.policy_id = derive_policy_id(&revoked).map_err(store_error)?;
                if policies.policies.contains_key(&revoked.policy_id) {
                    return Err(MutationError("revoked policy ID already exists".into()));
                }
                policies.policies.remove(&old_id);
                affected_policy_ids.extend([old_id, revoked.policy_id.clone()]);
                policies.policies.insert(revoked.policy_id.clone(), revoked);
                warnings.push("the retained revoked record has a new policy ID; future no-op revocation uses that current ID".into());
            }
        }
    }

    let semantic_roots_changed = roots.keys != initial_root_keys;
    let semantic_policies_changed = policies.policies != initial_policy_records;
    let semantic_change = semantic_roots_changed || semantic_policies_changed;
    if !semantic_change {
        return Ok(BuilderMutationPlanV1 {
            operation,
            changed: false,
            current_roots_generation: base.root_generation,
            proposed_roots_generation: base.root_generation,
            current_policies_generation: base.policy_generation,
            proposed_policies_generation: base.policy_generation,
            current_roots_sha256: base.root_digest.map(|digest| hex(&digest)),
            proposed_roots_sha256: base.root_digest.map(|digest| hex(&digest)),
            current_policies_sha256: base.policy_digest.map(|digest| hex(&digest)),
            proposed_policies_sha256: base.policy_digest.map(|digest| hex(&digest)),
            affected_key_ids,
            affected_policy_ids,
            proposed_roots_bytes: None,
            proposed_policies_bytes: None,
            expected_transaction: None,
            proposed_state_marker: None,
            warnings,
        });
    }

    let roots_changed = base.roots.is_none() || semantic_roots_changed;
    let policies_changed = base.policies.is_none() || semantic_policies_changed;
    roots.generation = next_generation(base.root_generation, roots_changed)?;
    policies.generation = next_generation(base.policy_generation, policies_changed)?;
    let roots_bytes = serialize_roots(&roots)?;
    let policies_bytes = serialize_policies(&policies)?;
    let (validated_roots, _) = parse_root_store(&roots_bytes).map_err(store_error)?;
    let (validated_policies, _) = parse_policy_store(&policies_bytes).map_err(store_error)?;
    if validated_roots.generation != roots.generation
        || validated_policies.generation != policies.generation
    {
        return Err(MutationError(
            "canonical store self-validation failed".into(),
        ));
    }
    let roots_digest = Sha256::digest(&roots_bytes).to_vec();
    let policies_digest = Sha256::digest(&policies_bytes).to_vec();
    let roots_sha = hex(&roots_digest);
    let policies_sha = hex(&policies_digest);
    let transaction_operation = match (roots_changed, policies_changed) {
        (true, true) => "combined",
        (true, false) => "roots",
        (false, true) => "policies",
        (false, false) => {
            return Err(MutationError(
                "mutation unexpectedly has no changed store".into(),
            ))
        }
    };
    let transaction = transaction_bytes(
        transaction_operation,
        base.root_generation,
        base.root_digest.map(|digest| hex(&digest)).as_deref(),
        roots.generation,
        &roots_sha,
        base.policy_generation,
        base.policy_digest.map(|digest| hex(&digest)).as_deref(),
        policies.generation,
        &policies_sha,
    );
    parse_journal(&transaction).map_err(|error| {
        MutationError(format!("planned transaction failed validation: {error}"))
    })?;
    let marker = marker_bytes(
        roots.generation,
        &roots_sha,
        policies.generation,
        &policies_sha,
    );
    let parsed_marker = parse_marker(&marker)
        .map_err(|error| MutationError(format!("planned marker failed validation: {error}")))?;
    if parsed_marker.roots.generation != roots.generation
        || parsed_marker.roots.digest != roots_sha
        || parsed_marker.policies.generation != policies.generation
        || parsed_marker.policies.digest != policies_sha
    {
        return Err(MutationError(
            "planned marker pair does not match proposed stores".into(),
        ));
    }
    Ok(BuilderMutationPlanV1 {
        operation,
        changed: true,
        current_roots_generation: base.root_generation,
        proposed_roots_generation: Some(roots.generation),
        current_policies_generation: base.policy_generation,
        proposed_policies_generation: Some(policies.generation),
        current_roots_sha256: base.root_digest.map(|digest| hex(&digest)),
        proposed_roots_sha256: Some(roots_sha),
        current_policies_sha256: base.policy_digest.map(|digest| hex(&digest)),
        proposed_policies_sha256: Some(policies_sha),
        affected_key_ids,
        affected_policy_ids,
        proposed_roots_bytes: Some(roots_bytes),
        proposed_policies_bytes: Some(policies_bytes),
        expected_transaction: Some(transaction),
        proposed_state_marker: Some(marker),
        warnings,
    })
}

fn validate_base_digest(base: &BuilderMutationBaseV1) -> Result<(), MutationError> {
    match (&base.roots, base.root_generation, base.root_digest) {
        (Some(store), Some(generation), Some(digest)) => {
            let bytes = serialize_roots(store)?;
            parse_root_store(&bytes).map_err(store_error)?;
            let actual: [u8; 32] = Sha256::digest(bytes).into();
            if store.generation != generation || actual != digest {
                return Err(MutationError(
                    "root-store digest or generation mismatch".into(),
                ));
            }
        }
        (None, None, None) => {}
        _ => return Err(MutationError("root-store snapshot is incomplete".into())),
    }
    match (&base.policies, base.policy_generation, base.policy_digest) {
        (Some(store), Some(generation), Some(digest)) => {
            let bytes = serialize_policies(store)?;
            parse_policy_store(&bytes).map_err(store_error)?;
            let actual: [u8; 32] = Sha256::digest(bytes).into();
            if store.generation != generation || actual != digest {
                return Err(MutationError(
                    "policy-store digest or generation mismatch".into(),
                ));
            }
        }
        (None, None, None) => {}
        _ => return Err(MutationError("policy-store snapshot is incomplete".into())),
    }
    Ok(())
}

fn parse_policy_request(bytes: &[u8]) -> Result<PolicyRecordV1, MutationError> {
    if bytes.len() > MAX_POLICY_INPUT_BYTES {
        return Err(MutationError("policy input exceeds 64 KiB".into()));
    }
    let value = crate::build_attestation::parse_bounded_json(bytes, 4096).map_err(|error| {
        MutationError(format!("invalid or duplicate policy JSON field: {error}"))
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| MutationError("policy request root must be an object".into()))?;
    let required = [
        "allowedGitRevisions",
        "builderId",
        "buildType",
        "externalParameters",
        "signerIdentity",
        "sourceUri",
        "version",
    ];
    if object.len() != required.len() || required.iter().any(|name| !object.contains_key(*name)) {
        return Err(MutationError(
            "policy request has missing or unknown fields".into(),
        ));
    }
    let version = object["version"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|version| *version == 1)
        .ok_or_else(|| MutationError("policy request version must be 1".into()))?;
    let signer_identity = input_string(object, "signerIdentity", 256)?;
    let builder_id = input_string(object, "builderId", 256)?;
    let build_type = input_string(object, "buildType", 2048)?;
    let source_uri = input_string(object, "sourceUri", 2048)?;
    let external_parameters = object["externalParameters"]
        .as_object()
        .map(|_| object["externalParameters"].clone())
        .ok_or_else(|| MutationError("externalParameters must be a complete JSON object".into()))?;
    let revisions = object["allowedGitRevisions"]
        .as_array()
        .filter(|array| !array.is_empty() && array.len() <= 64)
        .ok_or_else(|| MutationError("allowedGitRevisions must contain 1..64 revisions".into()))?;
    let mut allowed_git_revisions = BTreeSet::new();
    for item in revisions {
        let revision = item
            .as_str()
            .ok_or_else(|| MutationError("each allowed revision must be a string".into()))?;
        if !valid_revision(revision) || !allowed_git_revisions.insert(revision.to_owned()) {
            return Err(MutationError(
                "revisions must be unique full lowercase Git object IDs".into(),
            ));
        }
    }
    let policy = PolicyRecordV1 {
        policy_id: String::new(),
        version,
        state: "active".into(),
        signer_identity,
        builder_id,
        build_type,
        external_parameters,
        source_uri,
        allowed_git_revisions,
    };
    validate_policy_record(&policy)?;
    Ok(policy)
}

fn validate_policy_record(policy: &PolicyRecordV1) -> Result<(), MutationError> {
    exact_identity(policy.signer_identity.clone())?;
    exact_identity(policy.builder_id.clone())?;
    checked_uri(policy.build_type.clone()).map_err(store_error)?;
    checked_uri(policy.source_uri.clone()).map_err(store_error)?;
    if policy.builder_id.contains('*') || policy.source_uri.contains('*') {
        return Err(MutationError(
            "wildcard builder or source identities are unsupported".into(),
        ));
    }
    if contains_wildcard(&policy.external_parameters) {
        return Err(MutationError(
            "wildcard values are unsupported in external parameters".into(),
        ));
    }
    if policy.version != 1 || policy.state != "active" {
        return Err(MutationError(
            "new policies require version 1 and active state".into(),
        ));
    }
    if policy.allowed_git_revisions.is_empty()
        || policy.allowed_git_revisions.len() > 64
        || policy
            .allowed_git_revisions
            .iter()
            .any(|revision| !valid_revision(revision))
    {
        return Err(MutationError(
            "policy requires full lowercase Git revisions".into(),
        ));
    }
    let revision = policy
        .external_parameters
        .get("revision")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            MutationError("externalParameters must contain an exact source revision".into())
        })?;
    if !valid_revision(revision) || !policy.allowed_git_revisions.contains(revision) {
        return Err(MutationError(
            "external source revision must be one of the allowed full Git revisions".into(),
        ));
    }
    Ok(())
}

fn contains_wildcard(value: &Value) -> bool {
    match value {
        Value::String(string) => string.contains('*'),
        Value::Array(values) => values.iter().any(contains_wildcard),
        Value::Object(values) => values.values().any(contains_wildcard),
        _ => false,
    }
}

fn serialize_roots(store: &RootStoreV1) -> Result<Vec<u8>, MutationError> {
    let mut root = Map::new();
    root.insert("generation".into(), Value::Number(store.generation.into()));
    root.insert(
        "keyCount".into(),
        Value::Number((store.keys.len() as u64).into()),
    );
    let keys = store
        .keys
        .values()
        .map(|record| {
            let mut item = Map::new();
            item.insert("algorithm".into(), Value::String(record.algorithm.clone()));
            item.insert("keyId".into(), Value::String(record.key_id.clone()));
            if let Some(reference) = &record.enrollment_reference {
                item.insert(
                    "enrollmentReference".into(),
                    Value::String(reference.clone()),
                );
            }
            item.insert("publicKey".into(), Value::String(hex(&record.public_key)));
            item.insert(
                "signerIdentity".into(),
                Value::String(record.signer_identity.clone()),
            );
            item.insert("state".into(), Value::String(record.state.clone()));
            Value::Object(item)
        })
        .collect();
    root.insert("keys".into(), Value::Array(keys));
    root.insert("schemaVersion".into(), Value::Number(1.into()));
    serde_json::to_vec(&Value::Object(root)).map_err(|error| MutationError(error.to_string()))
}

fn serialize_policies(store: &PolicyStoreV1) -> Result<Vec<u8>, MutationError> {
    let mut root = Map::new();
    root.insert("generation".into(), Value::Number(store.generation.into()));
    let policies = store.policies.values().map(policy_value).collect();
    root.insert("policies".into(), Value::Array(policies));
    root.insert("schemaVersion".into(), Value::Number(1.into()));
    serde_json::to_vec(&Value::Object(root)).map_err(|error| MutationError(error.to_string()))
}

fn policy_value(policy: &PolicyRecordV1) -> Value {
    let mut item = Map::new();
    item.insert(
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
    item.insert("builderId".into(), Value::String(policy.builder_id.clone()));
    item.insert("buildType".into(), Value::String(policy.build_type.clone()));
    item.insert(
        "externalParameters".into(),
        policy.external_parameters.clone(),
    );
    item.insert("policyId".into(), Value::String(policy.policy_id.clone()));
    item.insert(
        "signerIdentity".into(),
        Value::String(policy.signer_identity.clone()),
    );
    item.insert("sourceUri".into(), Value::String(policy.source_uri.clone()));
    item.insert("state".into(), Value::String(policy.state.clone()));
    item.insert("version".into(), Value::Number(policy.version.into()));
    Value::Object(item)
}

fn empty_roots() -> RootStoreV1 {
    RootStoreV1 {
        generation: 0,
        keys: BTreeMap::new(),
    }
}

fn empty_policies() -> PolicyStoreV1 {
    PolicyStoreV1 {
        generation: 0,
        policies: BTreeMap::new(),
    }
}

fn next_generation(current: Option<u64>, changed: bool) -> Result<u64, MutationError> {
    match (current, changed) {
        (Some(value), true) => value
            .checked_add(1)
            .ok_or_else(|| MutationError("store generation overflow".into())),
        (Some(value), false) => Ok(value),
        (None, true) => Ok(1),
        (None, false) => Err(MutationError(
            "cannot preserve generation for an absent store".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn transaction_bytes(
    operation: &str,
    old_root_generation: Option<u64>,
    old_root_digest: Option<&str>,
    new_root_generation: u64,
    new_root_digest: &str,
    old_policy_generation: Option<u64>,
    old_policy_digest: Option<&str>,
    new_policy_generation: u64,
    new_policy_digest: &str,
) -> Vec<u8> {
    let old = |generation: Option<u64>, digest: Option<&str>| match (generation, digest) {
        (Some(generation), Some(digest)) => (generation.to_string(), digest.to_owned()),
        _ => ("none".into(), "none".into()),
    };
    let (old_rg, old_rd) = old(old_root_generation, old_root_digest);
    let (old_pg, old_pd) = old(old_policy_generation, old_policy_digest);
    format!(
        "ios-unsandboxed-builder-transaction\nschema_version=1\noperation={operation}\nold_root_generation={old_rg}\nnew_root_generation={new_root_generation}\nold_root_sha256={old_rd}\nnew_root_sha256={new_root_digest}\nold_policy_generation={old_pg}\nnew_policy_generation={new_policy_generation}\nold_policy_sha256={old_pd}\nnew_policy_sha256={new_policy_digest}\nstage_roots=roots.stage.v1\nstage_policies=policies.stage.v1\nphase=prepared\n"
    )
    .into_bytes()
}

fn marker_bytes(
    root_generation: u64,
    root_digest: &str,
    policy_generation: u64,
    policy_digest: &str,
) -> Vec<u8> {
    format!(
        "ios-unsandboxed-builder-state\nschema_version=1\nroot_generation={root_generation}\nroot_sha256={root_digest}\npolicy_generation={policy_generation}\npolicy_sha256={policy_digest}\n"
    )
    .into_bytes()
}

fn read_bounded_input(path: &Path, maximum: usize) -> Result<Vec<u8>, MutationError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            MutationError(format!(
                "cannot open input without following symlinks: {error}"
            ))
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| MutationError(error.to_string()))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum as u64 {
        return Err(MutationError(
            "input must be a bounded regular single-link file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| MutationError(error.to_string()))?;
    if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(MutationError(
            "input changed or exceeded its size limit".into(),
        ));
    }
    Ok(bytes)
}

fn validate_public_key(key: &[u8; 32]) -> Result<(), MutationError> {
    let verifying_key = VerifyingKey::from_bytes(key)
        .map_err(|_| MutationError("public key is not a valid Ed25519 point".into()))?;
    if verifying_key.is_weak() {
        return Err(MutationError(
            "weak small-order Ed25519 public keys are not accepted for enrollment".into(),
        ));
    }
    Ok(())
}

fn exact_identity(identity: String) -> Result<String, MutationError> {
    if identity.is_empty() {
        return Err(MutationError("identity cannot be empty".into()));
    }
    checked_identity(identity).map_err(store_error)
}

fn input_string(
    object: &Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<String, MutationError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
        .ok_or_else(|| MutationError(format!("invalid {key}")))
}

fn validate_enrollment_reference(reference: Option<&str>) -> Result<(), MutationError> {
    if reference.is_some_and(|value| {
        value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
    }) {
        Err(MutationError(
            "invalid enrollment reference metadata".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_key_id(key_id: &str) -> Result<(), MutationError> {
    if lower_hex(key_id, 32) {
        Ok(())
    } else {
        Err(MutationError(
            "key ID must be 32 lowercase hexadecimal characters".into(),
        ))
    }
}

fn validate_policy_id(policy_id: &str) -> Result<(), MutationError> {
    if lower_hex(policy_id, 64) {
        Ok(())
    } else {
        Err(MutationError(
            "policy ID must be 64 lowercase hexadecimal characters".into(),
        ))
    }
}

fn store_error(error: crate::builder_trust::StoreError) -> MutationError {
    MutationError(error.message)
}

fn opt_number(value: Option<u64>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| "ABSENT".into())
}

fn opt_text(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("ABSENT")
}

fn list(values: &[String]) -> String {
    if values.is_empty() {
        "NONE".into()
    } else {
        values.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder_trust::{derive_key_id, parse_policy_store, parse_root_store};
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempTrustRoot(std::path::PathBuf);

    impl TempTrustRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "iu-builder-mutation-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let trust = path.join("builder-trust");
            std::fs::create_dir(&trust).unwrap();
            std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o700)).unwrap();
            let roots = active_roots(key(81), "fixture-ci");
            let policies = PolicyStoreV1 {
                generation: 9,
                policies: BTreeMap::new(),
            };
            write_trust_file(&trust, "roots.v1", &serialize_roots(&roots).unwrap());
            write_trust_file(
                &trust,
                "policies.v1",
                &serialize_policies(&policies).unwrap(),
            );
            Self(path)
        }

        fn provider(&self) -> LocalBuilderVerificationProviderV1 {
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&self.0)
                .unwrap();
            let component = std::ffi::CString::new("builder-trust").unwrap();
            LocalBuilderVerificationProviderV1::from_test_root(
                root,
                &[component.as_c_str()],
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
            )
        }

        fn trust_dir(&self) -> std::path::PathBuf {
            self.0.join("builder-trust")
        }
    }

    impl Drop for TempTrustRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_trust_file(directory: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(directory.join(name), bytes).unwrap();
        std::fs::set_permissions(directory.join(name), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    fn base(roots: Option<RootStoreV1>, policies: Option<PolicyStoreV1>) -> BuilderMutationBaseV1 {
        let root_bytes = roots.as_ref().map(serialize_roots).transpose().unwrap();
        let policy_bytes = policies
            .as_ref()
            .map(serialize_policies)
            .transpose()
            .unwrap();
        BuilderMutationBaseV1 {
            root_generation: roots.as_ref().map(|store| store.generation),
            root_digest: root_bytes
                .as_deref()
                .map(|bytes| Sha256::digest(bytes).into()),
            policy_generation: policies.as_ref().map(|store| store.generation),
            policy_digest: policy_bytes
                .as_deref()
                .map(|bytes| Sha256::digest(bytes).into()),
            roots,
            policies,
            fingerprint: test_fingerprint(),
        }
    }

    fn test_fingerprint() -> crate::builder_trust::MutationFingerprintV1 {
        crate::builder_trust::MutationFingerprintV1 {
            directory_chain: None,
            roots: None,
            policies: None,
            marker: None,
            transaction_status: crate::builder_transaction::TransactionState::NoTransaction,
            marker_status: crate::builder_transaction::MarkerStatus::LegacyUnanchored,
            root_error: None,
            policy_error: None,
        }
    }

    fn key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn active_roots(key: [u8; 32], identity: &str) -> RootStoreV1 {
        let key_id = derive_key_id(&key);
        RootStoreV1 {
            generation: 4,
            keys: [(
                key_id.clone(),
                RootRecordV1 {
                    key_id,
                    algorithm: "Ed25519".into(),
                    public_key: key,
                    signer_identity: identity.into(),
                    state: "active".into(),
                    enrollment_reference: None,
                },
            )]
            .into_iter()
            .collect(),
        }
    }

    fn policy(identity: &str, revision: &str) -> PolicyRecordV1 {
        let mut policy = PolicyRecordV1 {
            policy_id: String::new(),
            version: 1,
            state: "active".into(),
            signer_identity: identity.into(),
            builder_id: "https://ci.example.invalid/builders/prod".into(),
            build_type: "https://ci.example.invalid/types/ios".into(),
            external_parameters: serde_json::json!({"repository":"https://example.invalid/acme/app","revision":revision}),
            source_uri: "git+https://example.invalid/acme/app".into(),
            allowed_git_revisions: [revision.into()].into_iter().collect(),
        };
        policy.policy_id = derive_policy_id(&policy).unwrap();
        policy
    }

    #[test]
    fn first_and_second_signer_enrollment_are_canonical_and_transactional() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/builder-trust/mutation-vectors.json"
        ))
        .unwrap();
        let vector = &vectors["firstSignerPlan"];
        let mut plan = plan_from_base(
            &base(None, None),
            BuilderMutationRequestV1::AddSigner {
                public_key: key(11),
                signer_identity: "local-ci-enrollment-1".into(),
                enrollment_reference: Some("change-17".into()),
            },
        )
        .unwrap();
        assert!(plan.changed);
        assert_eq!(hex(&key(11)), vector["publicKeyHex"].as_str().unwrap());
        assert_eq!(
            plan.proposed_roots_sha256.as_deref(),
            vector["rootSha256"].as_str()
        );
        assert_eq!(
            plan.proposed_policies_sha256.as_deref(),
            vector["policySha256"].as_str()
        );
        assert_eq!(
            plan.expected_transaction.as_deref().unwrap(),
            vector["transaction"].as_str().unwrap().as_bytes()
        );
        assert_eq!(plan.current_roots_generation, None);
        assert_eq!(plan.proposed_roots_generation, Some(1));
        assert_eq!(plan.proposed_policies_generation, Some(1));
        assert_eq!(plan.affected_key_ids, [derive_key_id(&key(11))]);
        assert!(
            std::str::from_utf8(plan.expected_transaction.as_ref().unwrap())
                .unwrap()
                .contains("operation=combined\n")
        );
        assert!(parse_root_store(plan.proposed_roots_bytes.as_ref().unwrap()).is_ok());
        assert!(parse_policy_store(plan.proposed_policies_bytes.as_ref().unwrap()).is_ok());
        let roots = parse_root_store(plan.proposed_roots_bytes.as_ref().unwrap())
            .unwrap()
            .0;
        let next = plan_from_base(
            &base(
                Some(roots),
                Some(PolicyStoreV1 {
                    generation: 1,
                    policies: BTreeMap::new(),
                }),
            ),
            BuilderMutationRequestV1::AddSigner {
                public_key: key(12),
                signer_identity: "local-ci-enrollment-2".into(),
                enrollment_reference: None,
            },
        )
        .unwrap();
        assert_eq!(next.proposed_roots_generation, Some(2));
        assert_eq!(next.proposed_policies_generation, Some(1));
        assert!(
            std::str::from_utf8(next.expected_transaction.as_ref().unwrap())
                .unwrap()
                .contains("operation=roots\n")
        );
        plan.expected_transaction.take();
    }

    #[test]
    fn signer_revocation_is_idempotent_and_retains_tombstone() {
        let root = active_roots(key(21), "runner-a");
        let id = derive_key_id(&key(21));
        let first = plan_from_base(
            &base(
                Some(root),
                Some(PolicyStoreV1 {
                    generation: 7,
                    policies: BTreeMap::new(),
                }),
            ),
            BuilderMutationRequestV1::RevokeSigner { key_id: id.clone() },
        )
        .unwrap();
        assert!(first.changed);
        assert_eq!(first.proposed_roots_generation, Some(5));
        let roots = parse_root_store(first.proposed_roots_bytes.as_ref().unwrap())
            .unwrap()
            .0;
        assert_eq!(roots.keys[&id].state, "revoked");
        let repeat = plan_from_base(
            &base(
                Some(roots),
                parse_policy_store(first.proposed_policies_bytes.as_ref().unwrap())
                    .ok()
                    .map(|x| x.0),
            ),
            BuilderMutationRequestV1::RevokeSigner { key_id: id },
        )
        .unwrap();
        assert!(!repeat.changed);
        assert!(repeat.expected_transaction.is_none());
        assert_eq!(repeat.proposed_roots_generation, Some(5));
    }

    #[test]
    fn rotation_requires_new_identity_and_never_migrates_policies() {
        let root = active_roots(key(31), "old-builder-signer");
        let old_id = derive_key_id(&key(31));
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let mut policies = BTreeMap::new();
        let p = policy("old-builder-signer", revision);
        policies.insert(p.policy_id.clone(), p.clone());
        let initial = base(
            Some(root),
            Some(PolicyStoreV1 {
                generation: 7,
                policies,
            }),
        );
        assert!(plan_from_base(
            &initial,
            BuilderMutationRequestV1::RotateSigner {
                old_key_id: old_id.clone(),
                new_public_key: key(32),
                new_signer_identity: "old-builder-signer".into(),
                enrollment_reference: None
            }
        )
        .is_err());
        let plan = plan_from_base(
            &initial,
            BuilderMutationRequestV1::RotateSigner {
                old_key_id: old_id.clone(),
                new_public_key: key(32),
                new_signer_identity: "new-builder-signer".into(),
                enrollment_reference: None,
            },
        )
        .unwrap();
        assert_eq!(plan.proposed_policies_generation, Some(7));
        assert_eq!(plan.affected_policy_ids, [p.policy_id]);
        let roots = parse_root_store(plan.proposed_roots_bytes.as_ref().unwrap())
            .unwrap()
            .0;
        assert_eq!(roots.keys[&old_id].state, "revoked");
        assert_eq!(
            roots.keys[&derive_key_id(&key(32))].signer_identity,
            "new-builder-signer"
        );
    }

    #[test]
    fn policies_require_active_exact_signer_and_full_source_revision() {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let valid = policy("ci-signer", revision);
        let policy_base = base(
            Some(active_roots(key(41), "ci-signer")),
            Some(PolicyStoreV1 {
                generation: 3,
                policies: BTreeMap::new(),
            }),
        );
        let plan = plan_from_base(
            &policy_base,
            BuilderMutationRequestV1::AddPolicy { policy: valid },
        )
        .unwrap();
        assert_eq!(plan.proposed_policies_generation, Some(4));
        assert!(parse_policy_store(plan.proposed_policies_bytes.as_ref().unwrap()).is_ok());
        let mut missing_revision = policy("ci-signer", revision);
        missing_revision.external_parameters =
            serde_json::json!({"repository":"https://example.invalid/acme/app"});
        assert!(plan_from_base(
            &policy_base,
            BuilderMutationRequestV1::AddPolicy {
                policy: missing_revision
            }
        )
        .is_err());
        let mut wildcard_repository = policy("ci-signer", revision);
        wildcard_repository.external_parameters = serde_json::json!({
            "repository": "https://example.invalid/*/app",
            "revision": revision
        });
        assert!(plan_from_base(
            &policy_base,
            BuilderMutationRequestV1::AddPolicy {
                policy: wildcard_repository
            }
        )
        .is_err());
        assert!(plan_from_base(
            &policy_base,
            BuilderMutationRequestV1::AddPolicy {
                policy: policy("unknown", revision)
            }
        )
        .is_err());
        let revoked = active_roots(key(42), "revoked-signer");
        let mut revoked = revoked;
        revoked.keys.values_mut().next().unwrap().state = "revoked".into();
        assert!(plan_from_base(
            &base(
                Some(revoked),
                Some(PolicyStoreV1 {
                    generation: 3,
                    policies: BTreeMap::new()
                })
            ),
            BuilderMutationRequestV1::AddPolicy {
                policy: policy("revoked-signer", revision)
            }
        )
        .is_err());
    }

    #[test]
    fn policy_revocation_changes_identity_and_repeat_is_noop() {
        let p = policy("ci-signer", "0123456789abcdef0123456789abcdef01234567");
        let id = p.policy_id.clone();
        let policies = PolicyStoreV1 {
            generation: 2,
            policies: [(id.clone(), p)].into_iter().collect(),
        };
        let first = plan_from_base(
            &base(Some(active_roots(key(51), "ci-signer")), Some(policies)),
            BuilderMutationRequestV1::RevokePolicy {
                policy_id: id.clone(),
            },
        )
        .unwrap();
        assert_eq!(first.proposed_policies_generation, Some(3));
        let policies = parse_policy_store(first.proposed_policies_bytes.as_ref().unwrap())
            .unwrap()
            .0;
        let revoked_id = policies.policies.keys().next().unwrap().clone();
        assert_eq!(policies.policies[&revoked_id].state, "revoked");
        let second = plan_from_base(
            &base(
                Some(active_roots(key(51), "ci-signer")),
                Some(policies.clone()),
            ),
            BuilderMutationRequestV1::RevokePolicy {
                policy_id: revoked_id,
            },
        )
        .unwrap();
        assert!(!second.changed);
        assert_eq!(second.proposed_policies_generation, Some(3));
        let original_id_repeat = plan_from_base(
            &base(Some(active_roots(key(51), "ci-signer")), Some(policies)),
            BuilderMutationRequestV1::RevokePolicy { policy_id: id },
        );
        assert!(!original_id_repeat.unwrap().changed);
    }

    #[test]
    fn policy_request_rejects_duplicate_json_and_revision_prefixes() {
        assert!(parse_policy_request(br#"{"version":1,"version":1}"#).is_err());
        let input = serde_json::json!({"version":1,"signerIdentity":"ci","builderId":"https://ci.invalid/builder","buildType":"https://ci.invalid/type","externalParameters":{"revision":"0123456789abcdef"},"sourceUri":"git+https://repo.invalid/x","allowedGitRevisions":["0123456789abcdef"]});
        assert!(parse_policy_request(&serde_json::to_vec(&input).unwrap()).is_err());
    }

    #[test]
    fn public_key_and_policy_inputs_are_bounded_canonical_and_no_follow() {
        let fixture = TempTrustRoot::new();
        let key_path = fixture.0.join("key.txt");
        std::fs::write(&key_path, format!("{}\n", hex(&key(101)))).unwrap();
        assert_eq!(read_public_key_file(&key_path).unwrap(), key(101));
        std::fs::write(&key_path, format!("{}\n", hex(&[0; 32]))).unwrap();
        assert!(read_public_key_file(&key_path).is_err());
        std::fs::write(&key_path, format!("{}\n", hex(&key(101)).to_uppercase())).unwrap();
        assert!(read_public_key_file(&key_path).is_err());
        let key_link = fixture.0.join("key-link.txt");
        std::os::unix::fs::symlink(&key_path, &key_link).unwrap();
        assert!(read_public_key_file(&key_link).is_err());
        let hard_link = fixture.0.join("key-hardlink.txt");
        std::fs::hard_link(&key_path, &hard_link).unwrap();
        assert!(read_public_key_file(&key_path).is_err());

        let policy_path = fixture.0.join("policy.json");
        let revision = "0123456789abcdef0123456789abcdef01234567";
        std::fs::write(
            &policy_path,
            br#"{"sourceUri":"git+https://example.invalid/app","buildType":"https://ci.example.invalid/type","externalParameters":{"revision":"0123456789abcdef0123456789abcdef01234567","repository":"https://example.invalid/app"},"version":1,"builderId":"https://ci.example.invalid/builder","signerIdentity":"ci","allowedGitRevisions":["0123456789abcdef0123456789abcdef01234567"]}"#,
        )
        .unwrap();
        let parsed = read_policy_file(&policy_path).unwrap();
        assert_eq!(
            parsed.allowed_git_revisions,
            [revision.to_owned()].into_iter().collect()
        );
        std::fs::write(&policy_path, br#"{"version":1,"version":1}"#).unwrap();
        assert!(read_policy_file(&policy_path).is_err());
        std::fs::write(&policy_path, vec![b'a'; MAX_POLICY_INPUT_BYTES + 1]).unwrap();
        assert!(read_policy_file(&policy_path).is_err());
    }

    #[test]
    fn key_and_policy_count_limits_duplicate_pairs_and_generation_overflow_reject() {
        let mut full_roots = RootStoreV1 {
            generation: 1,
            keys: BTreeMap::new(),
        };
        for index in 1..=MAX_SIGNING_KEYS as u8 {
            let public_key = key(index);
            let key_id = derive_key_id(&public_key);
            full_roots.keys.insert(
                key_id.clone(),
                RootRecordV1 {
                    key_id,
                    algorithm: "Ed25519".into(),
                    public_key,
                    signer_identity: format!("signer-{index}"),
                    state: "active".into(),
                    enrollment_reference: None,
                },
            );
        }
        let full_base = base(
            Some(full_roots),
            Some(PolicyStoreV1 {
                generation: 1,
                policies: BTreeMap::new(),
            }),
        );
        assert!(plan_from_base(
            &full_base,
            BuilderMutationRequestV1::AddSigner {
                public_key: key(111),
                signer_identity: "overflow-signer".into(),
                enrollment_reference: None,
            }
        )
        .is_err());

        let revision = "0123456789abcdef0123456789abcdef01234567";
        let mut full_policies = BTreeMap::new();
        for index in 0..MAX_POLICIES {
            let mut record = policy("limit-signer", revision);
            record.builder_id = format!("https://ci.example.invalid/builders/{index}");
            record.policy_id = derive_policy_id(&record).unwrap();
            full_policies.insert(record.policy_id.clone(), record);
        }
        let policy_limit_base = base(
            Some(active_roots(key(112), "limit-signer")),
            Some(PolicyStoreV1 {
                generation: 1,
                policies: full_policies,
            }),
        );
        assert!(plan_from_base(
            &policy_limit_base,
            BuilderMutationRequestV1::AddPolicy {
                policy: policy("limit-signer", revision),
            }
        )
        .is_err());

        let duplicate_base = base(
            Some(active_roots(key(113), "same-signer")),
            Some(PolicyStoreV1 {
                generation: 1,
                policies: [(
                    policy("same-signer", revision).policy_id.clone(),
                    policy("same-signer", revision),
                )]
                .into_iter()
                .collect(),
            }),
        );
        assert!(plan_from_base(
            &duplicate_base,
            BuilderMutationRequestV1::AddPolicy {
                policy: policy("same-signer", revision),
            }
        )
        .is_err());

        let mut overflow_roots = active_roots(key(114), "overflow-generation");
        overflow_roots.generation = u64::MAX;
        assert!(plan_from_base(
            &base(
                Some(overflow_roots),
                Some(PolicyStoreV1 {
                    generation: 1,
                    policies: BTreeMap::new(),
                }),
            ),
            BuilderMutationRequestV1::RevokeSigner {
                key_id: derive_key_id(&key(114)),
            }
        )
        .is_err());

        let mut mismatched_policy_base = policy_limit_base.clone();
        mismatched_policy_base.policy_digest = Some([0; 32]);
        assert!(plan_from_base(
            &mismatched_policy_base,
            BuilderMutationRequestV1::RevokeSigner {
                key_id: derive_key_id(&key(112)),
            }
        )
        .is_err());
    }

    #[test]
    fn serialization_is_sorted_and_generation_overflow_rejects() {
        let mut roots = active_roots(key(61), "z-runner");
        let more = key(62);
        let id = derive_key_id(&more);
        roots.keys.insert(
            id.clone(),
            RootRecordV1 {
                key_id: id,
                algorithm: "Ed25519".into(),
                public_key: more,
                signer_identity: "a-runner".into(),
                state: "active".into(),
                enrollment_reference: None,
            },
        );
        let bytes = serialize_roots(&roots).unwrap();
        assert!(parse_root_store(&bytes).is_ok());
        assert!(bytes
            .windows(64)
            .any(|window| window == hex(&more).as_bytes()));
        assert!(next_generation(Some(u64::MAX), true).is_err());
        assert_eq!(next_generation(Some(8), false).unwrap(), 8);
    }

    #[test]
    fn pending_or_corrupt_planning_inputs_are_not_constructible_as_a_valid_base() {
        // Production obtains a base only after the hardened reader has rejected
        // journals, orphan stages, unsafe files and conflicting markers.
        let base = base(None, None);
        let plan = plan_from_base(
            &base,
            BuilderMutationRequestV1::AddSigner {
                public_key: key(71),
                signer_identity: "ci".into(),
                enrollment_reference: None,
            },
        )
        .unwrap();
        assert!(plan.expected_transaction.is_some());
        assert!(plan.render().contains("Operational authorization: FALSE"));
        assert!(plan.render().contains("Persistence: NOT_APPLIED"));
    }

    #[test]
    fn production_planner_uses_isolated_reader_snapshot_and_writes_nothing() {
        let fixture = TempTrustRoot::new();
        let provider = fixture.provider();
        let before = std::fs::read_dir(fixture.trust_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        let roots_before = std::fs::read(fixture.trust_dir().join("roots.v1")).unwrap();
        let policies_before = std::fs::read(fixture.trust_dir().join("policies.v1")).unwrap();
        let plan = plan_with_provider(
            &provider,
            BuilderMutationRequestV1::RevokeSigner {
                key_id: derive_key_id(&key(81)),
            },
        )
        .unwrap();
        assert!(plan.changed);
        assert_eq!(
            std::fs::read(fixture.trust_dir().join("roots.v1")).unwrap(),
            roots_before
        );
        assert_eq!(
            std::fs::read(fixture.trust_dir().join("policies.v1")).unwrap(),
            policies_before
        );
        let after = std::fs::read_dir(fixture.trust_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(before, after);
    }

    #[test]
    fn changed_snapshot_pending_stage_and_corrupt_marker_reject_planning() {
        let fixture = TempTrustRoot::new();
        let provider = fixture.provider();
        let base = provider.mutation_base().unwrap();
        let mut changed_roots = base.roots.clone().unwrap();
        changed_roots.generation += 1;
        write_trust_file(
            &fixture.trust_dir(),
            "roots.v1",
            &serialize_roots(&changed_roots).unwrap(),
        );
        assert!(provider.revalidate_mutation_base(&base).is_err());

        let journal_fixture = TempTrustRoot::new();
        let journal_provider = journal_fixture.provider();
        let journal_base = journal_provider.mutation_base().unwrap();
        let mut replacement = journal_base.roots.clone().unwrap();
        replacement.generation += 1;
        let replacement_bytes = serialize_roots(&replacement).unwrap();
        let replacement_digest = hex(&Sha256::digest(&replacement_bytes));
        let old_root_digest = hex(&journal_base.root_digest.unwrap());
        let old_policy_digest = hex(&journal_base.policy_digest.unwrap());
        let journal = transaction_bytes(
            "roots",
            journal_base.root_generation,
            Some(&old_root_digest),
            replacement.generation,
            &replacement_digest,
            journal_base.policy_generation,
            Some(&old_policy_digest),
            journal_base.policy_generation.unwrap(),
            &old_policy_digest,
        );
        write_trust_file(
            &journal_fixture.trust_dir(),
            "roots.stage.v1",
            &replacement_bytes,
        );
        write_trust_file(&journal_fixture.trust_dir(), "transaction.v1", &journal);
        assert!(journal_fixture.provider().mutation_base().is_err());

        let clean = TempTrustRoot::new();
        let mut staged_roots = clean.provider().mutation_base().unwrap().roots.unwrap();
        staged_roots.generation += 1;
        write_trust_file(
            &clean.trust_dir(),
            "roots.stage.v1",
            &serialize_roots(&staged_roots).unwrap(),
        );
        assert!(clean.provider().mutation_base().is_err());

        let marker_fixture = TempTrustRoot::new();
        write_trust_file(&marker_fixture.trust_dir(), "state.v1", b"bad marker\n");
        assert!(marker_fixture.provider().mutation_base().is_err());
    }

    #[test]
    fn malformed_and_conflicting_operations_fail_without_plans() {
        let root = active_roots(key(91), "ci-one");
        let base = base(
            Some(root.clone()),
            Some(PolicyStoreV1 {
                generation: 4,
                policies: BTreeMap::new(),
            }),
        );
        let existing_id = derive_key_id(&key(91));
        assert!(plan_from_base(
            &base,
            BuilderMutationRequestV1::AddSigner {
                public_key: key(91),
                signer_identity: "ci-two".into(),
                enrollment_reference: None,
            }
        )
        .is_err());
        assert!(plan_from_base(
            &base,
            BuilderMutationRequestV1::AddSigner {
                public_key: key(92),
                signer_identity: "ci-one".into(),
                enrollment_reference: None,
            }
        )
        .is_err());
        assert!(plan_from_base(
            &base,
            BuilderMutationRequestV1::RevokeSigner {
                key_id: "f".repeat(32),
            }
        )
        .is_err());
        assert!(plan_from_base(
            &base,
            BuilderMutationRequestV1::RotateSigner {
                old_key_id: existing_id,
                new_public_key: key(91),
                new_signer_identity: "ci-new".into(),
                enrollment_reference: None,
            }
        )
        .is_err());
        assert!(validate_public_key(&[0; 32]).is_err());
        let mut mismatched = base.clone();
        mismatched.root_digest = Some([0; 32]);
        assert!(plan_from_base(
            &mismatched,
            BuilderMutationRequestV1::RevokeSigner {
                key_id: derive_key_id(&key(91)),
            }
        )
        .is_err());
    }
}
