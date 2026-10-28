//! Offline P013 evidence parser and Ed25519 verifier.
//!
//! The signature covers the domain separator and every canonical manifest byte
//! preceding `signature=` (including the newline immediately before it).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MANIFEST_MAX: usize = 8192;
const STORE_MAX: usize = 16384;
const KEY_MAX: usize = 64;
const SIGNING_DOMAIN: &[u8] = b"ios-unsandboxed-provenance-v1\0";
const TRUST_FILE: &str = "store.v1";
#[cfg(target_os = "macos")]
const OPEN_SAFE_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC;
#[cfg(not(target_os = "macos"))]
const OPEN_SAFE_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIdentity {
    pub sha256: [u8; 32],
    pub size: u64,
    pub architecture: u32,
    pub filetype: u32,
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone)]
struct Manifest {
    signed: Vec<u8>,
    digest: [u8; 32],
    size: u64,
    architecture: u32,
    filetype: u32,
    artifact_id: String,
    repository: String,
    revision: String,
    workflow: String,
    builder: String,
    publisher: String,
    algorithm: String,
    key_id: String,
    origin: String,
    signature: [u8; 64],
}

#[derive(Debug, Clone)]
struct Anchor {
    algorithm: String,
    public_key: [u8; 32],
    publisher: String,
    state: String,
}

#[derive(Debug, Clone, Default)]
struct TrustStore {
    generation: u64,
    keys: BTreeMap<String, Anchor>,
}

#[derive(Debug)]
pub struct Report {
    pub artifact_digest: bool,
    pub document_integrity: bool,
    pub signature_validity: &'static str,
    pub trust_anchor: &'static str,
    pub trust_generation: Option<u64>,
    pub publisher_identity: &'static str,
    pub build_identity: String,
    pub build_origin: &'static str,
    pub protected_origin: &'static str,
    pub policy: &'static str,
    pub error: Option<String>,
}

impl Report {
    fn denied(error: impl Into<String>) -> Self {
        Self {
            artifact_digest: false,
            document_integrity: false,
            signature_validity: "NOT_VERIFIED",
            trust_anchor: "UNAVAILABLE",
            trust_generation: None,
            publisher_identity: "UNVERIFIED",
            build_identity: "UNREADABLE".into(),
            build_origin: "ORIGIN_UNVERIFIED",
            protected_origin: "UNKNOWN",
            policy: "REJECTED",
            error: Some(error.into()),
        }
    }
}

fn hex_decode<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("non-canonical hexadecimal value".into());
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| -> u8 {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        out[i] = (digit(chunk[0]) << 4) | digit(chunk[1]);
    }
    Ok(out)
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 192
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':' | b'+' | b'@')
        })
}

fn canonical_uint(s: &str) -> Result<u64, String> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("non-canonical integer".into());
    }
    s.parse().map_err(|_| "integer overflow".into())
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest, String> {
    if bytes.is_empty()
        || bytes.len() > MANIFEST_MAX
        || !bytes.is_ascii()
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
        || bytes.contains(&0)
    {
        return Err("manifest is oversized or not canonical ASCII/LF".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "manifest is not UTF-8")?;
    let lines: Vec<&str> = text.split_terminator('\n').collect();
    const FIELDS: [&str; 16] = [
        "schema_version",
        "artifact_sha256",
        "artifact_size",
        "architecture",
        "filetype",
        "artifact_id",
        "repository",
        "revision",
        "workflow",
        "builder",
        "publisher",
        "algorithm",
        "key_id",
        "origin",
        "signature",
        "",
    ];
    if lines.len() != 15 || lines.last().is_none() {
        return Err("manifest has missing, duplicate, or extra fields".into());
    }
    let mut values = Vec::with_capacity(15);
    for (index, line) in lines.iter().enumerate() {
        let (key, value) = line.split_once('=').ok_or("manifest field has no value")?;
        let expected = if index == 14 {
            "signature"
        } else {
            FIELDS[index]
        };
        if key != expected || value.is_empty() {
            return Err("manifest fields are not in canonical order".into());
        }
        values.push(value);
    }
    if values[0] != "1" {
        return Err("unsupported manifest schema".into());
    }
    let digest = hex_decode::<32>(values[1])?;
    let size = canonical_uint(values[2])?;
    let architecture =
        u32::try_from(canonical_uint(values[3])?).map_err(|_| "architecture overflow")?;
    let filetype = u32::try_from(canonical_uint(values[4])?).map_err(|_| "filetype overflow")?;
    for value in &values[5..14] {
        if !valid_ident(value) {
            return Err("invalid manifest identifier".into());
        }
    }
    if values[11] != "ed25519" {
        return Err(format!("unsupported signature algorithm: {}", values[11]));
    }
    if !matches!(values[13], "unknown" | "protected" | "unprotected") {
        return Err("unsupported origin classification".into());
    }
    let sig = hex_decode::<64>(values[14])?;
    let signed_len = lines[..14].iter().map(|line| line.len() + 1).sum();
    Ok(Manifest {
        signed: bytes[..signed_len].to_vec(),
        digest,
        size,
        architecture,
        filetype,
        artifact_id: values[5].into(),
        repository: values[6].into(),
        revision: values[7].into(),
        workflow: values[8].into(),
        builder: values[9].into(),
        publisher: values[10].into(),
        algorithm: values[11].into(),
        key_id: values[12].into(),
        origin: values[13].into(),
        signature: sig,
    })
}

fn parse_store(bytes: &[u8]) -> Result<TrustStore, String> {
    if bytes.is_empty()
        || bytes.len() > STORE_MAX
        || !bytes.is_ascii()
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
    {
        return Err("trust store is malformed".into());
    }
    let lines: Vec<&str> = std::str::from_utf8(bytes)
        .map_err(|_| "trust store is not UTF-8")?
        .split_terminator('\n')
        .collect();
    if lines.len() < 4
        || lines[0] != "ios-unsandboxed-trust-store"
        || lines[1] != "schema_version=1"
    {
        return Err("unsupported trust-store schema".into());
    }
    let generation = canonical_uint(
        lines[2]
            .strip_prefix("generation=")
            .ok_or("missing trust-store generation")?,
    )?;
    if generation == 0 {
        return Err("zero trust-store generation".into());
    }
    let count = usize::try_from(canonical_uint(
        lines[3]
            .strip_prefix("key_count=")
            .ok_or("missing key count")?,
    )?)
    .map_err(|_| "key count overflow")?;
    if count > KEY_MAX || lines.len() != count + 4 {
        return Err("trust-store key count mismatch or limit exceeded".into());
    }
    let mut store = TrustStore {
        generation,
        keys: BTreeMap::new(),
    };
    for (i, line) in lines[4..].iter().enumerate() {
        let prefix = format!("key_{i}=");
        let fields: Vec<&str> = line
            .strip_prefix(&prefix)
            .ok_or("non-canonical trust-store key order")?
            .split('|')
            .collect();
        if fields.len() != 6
            || !valid_ident(fields[0])
            || fields[1] != "ed25519"
            || fields[3] != "publisher"
            || !valid_ident(fields[4])
            || !matches!(fields[5], "active" | "revoked")
        {
            return Err("invalid trust-store key metadata".into());
        }
        let key: [u8; 32] = hex_decode(fields[2])?;
        let mut hasher = Sha256::new();
        hasher.update(key);
        let key_hash = hasher.finalize();
        let derived_id = key_hash[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if fields[0] != derived_id {
            return Err("key ID does not match public key".into());
        }
        if store
            .keys
            .insert(
                fields[0].into(),
                Anchor {
                    algorithm: fields[1].into(),
                    public_key: key,
                    publisher: fields[4].into(),
                    state: fields[5].into(),
                },
            )
            .is_some()
        {
            return Err("duplicate key ID".into());
        }
    }
    Ok(store)
}

fn safe_read(
    path: &Path,
    max: usize,
    uid: Option<u32>,
    mode: Option<u32>,
) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_SAFE_FLAGS)
        .open(path)
        .map_err(|e| format!("cannot open evidence file: {e}"))?; // O_NOFOLLOW | O_CLOEXEC
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || uid.is_some_and(|u| before.uid() != u)
        || (uid.is_some() && before.gid() != 0)
        || mode.is_some_and(|m| before.mode() & 0o7777 != m)
        || before.mode() & 0o7000 != 0
        || before.nlink() != 1
        || before.size() > max as u64
    {
        return Err("file ownership, mode, link count, or size is unsafe".into());
    }
    let mut bytes = Vec::with_capacity(before.size() as usize);
    (&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    let current = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if bytes.len() > max
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.size() != after.size()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.nlink() != after.nlink()
        || current.dev() != before.dev()
        || current.ino() != before.ino()
    {
        return Err("file changed while being read".into());
    }
    Ok(bytes)
}

fn open_child(parent: &File, name: &std::ffi::CStr, directory: bool) -> Result<File, String> {
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    // openat returns a new descriptor; File owns it after the success check.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(format!(
            "trust-store open failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn same_metadata(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.size() == b.size()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn load_store_from_root(
    root: File,
    components: &[&std::ffi::CStr],
    uid: u32,
    gid: u32,
) -> Result<TrustStore, String> {
    let mut dirs = vec![root];
    let mut snapshots = Vec::new();
    for (index, component) in components.iter().enumerate() {
        let parent = dirs.last().ok_or("missing root")?;
        let meta = parent.metadata().map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.uid() != uid || meta.gid() != gid || meta.mode() & 0o022 != 0 {
            return Err("unsafe trust-store parent".into());
        }
        let child = open_child(parent, component, true)?;
        let child_meta = child.metadata().map_err(|e| e.to_string())?;
        if !child_meta.is_dir()
            || child_meta.uid() != uid
            || child_meta.gid() != gid
            || child_meta.mode() & 0o022 != 0
            || (index + 1 == components.len() && child_meta.mode() & 0o7777 != 0o700)
        {
            return Err("unsafe trust-store directory".into());
        }
        snapshots.push(child_meta);
        dirs.push(child);
    }
    let dir = dirs.last().ok_or("missing trust directory")?;
    let name = std::ffi::CString::new(TRUST_FILE).map_err(|e| e.to_string())?;
    let mut file = open_child(dir, &name, false)?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.uid() != uid
        || before.gid() != gid
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.size() > STORE_MAX as u64
    {
        return Err("unsafe trust-store file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((STORE_MAX + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    let current = open_child(dir, &name, false)?
        .metadata()
        .map_err(|e| e.to_string())?;
    if bytes.len() > STORE_MAX
        || bytes.len() as u64 != before.size()
        || !same_metadata(&before, &after)
        || !same_metadata(&before, &current)
    {
        return Err("trust-store file changed during read".into());
    }
    for (i, component) in components.iter().enumerate() {
        let current = open_child(&dirs[i], component, true)?
            .metadata()
            .map_err(|e| e.to_string())?;
        let held = dirs[i + 1].metadata().map_err(|e| e.to_string())?;
        if !same_metadata(&snapshots[i], &held) || !same_metadata(&held, &current) {
            return Err("trust-store directory changed during read".into());
        }
    }
    parse_store(&bytes)
}

fn load_production_store() -> Result<TrustStore, String> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_SAFE_FLAGS | libc::O_DIRECTORY)
        .open("/")
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "ios")]
    let components = [
        "private",
        "var",
        "lib",
        "ios-unsandboxed",
        "trusted-publishers",
    ];
    #[cfg(not(target_os = "ios"))]
    let components = ["var", "lib", "ios-unsandboxed", "trusted-publishers"];
    let names: Vec<_> = components
        .iter()
        .map(|s| std::ffi::CString::new(*s).expect("fixed path"))
        .collect();
    let refs: Vec<_> = names.iter().map(|s| s.as_c_str()).collect();
    load_store_from_root(root, &refs, 0, 0)
}

pub fn inspect_manifest(manifest_path: &Path, artifact: &ArtifactIdentity) -> Report {
    let bytes = match safe_read(manifest_path, MANIFEST_MAX, None, None) {
        Ok(bytes) => bytes,
        Err(error) => return Report::denied(error),
    };
    verify_manifest(&bytes, artifact, load_production_store())
}

pub fn verify_cli(
    manifest_path: &Path,
    artifact_path: &std::ffi::OsStr,
) -> Result<(String, bool), String> {
    let identity = crate::planner::artifact_identity(artifact_path)?;
    let scope = crate::planner::scope_preview(artifact_path, &identity)?;
    let report = inspect_manifest(manifest_path, &identity);
    if crate::planner::artifact_identity(artifact_path)? != identity {
        return Err("artifact identity changed during provenance inspection".into());
    }
    let output = format!(
        "Artifact digest: {}\nManifest syntax and canonical integrity: {}\nSignature verification (Ed25519): {}\nTrust anchor: {}\nTrust-store generation: {}\nPublisher identity: {}\nClaimed build identity: {}\nVerified build-origin evidence: {}\nProtected-origin policy: {}\nOrigin policy: {}\nP011 scope: {}\nP009 backend: NOT_VERIFIED\nP012 launch binding: PREVIEW ONLY (signature integration unavailable)\nExecution authorization: FALSE\n",
        if report.artifact_digest { "MATCH" } else { "MISMATCH" },
        if report.document_integrity { "VALID" } else { "INVALID" },
        report.signature_validity,
        report.trust_anchor,
        report.trust_generation.map_or_else(|| "UNAVAILABLE".into(), |g| g.to_string()),
        report.publisher_identity,
        report.build_identity,
        report.build_origin,
        report.protected_origin,
        report.policy,
        scope,
    );
    Ok((
        match report.error {
            Some(e) => format!("{output}Evidence detail: {e}\n"),
            None => output,
        },
        report.policy == "ACCEPTED",
    ))
}

fn verify_manifest(
    bytes: &[u8],
    artifact: &ArtifactIdentity,
    store: Result<TrustStore, String>,
) -> Report {
    let m = match parse_manifest(bytes) {
        Ok(m) => m,
        Err(e) => return Report::denied(e),
    };
    let identity_match = m.digest == artifact.sha256
        && m.size == artifact.size
        && m.architecture == artifact.architecture
        && m.filetype == artifact.filetype;
    let build_identity = format!(
        "{}; repository={}; revision={}; workflow={}; builder={}",
        m.artifact_id, m.repository, m.revision, m.workflow, m.builder
    );
    let mut report = Report {
        artifact_digest: identity_match,
        document_integrity: true,
        signature_validity: "NOT_VERIFIED",
        trust_anchor: "UNAVAILABLE",
        trust_generation: None,
        publisher_identity: "UNVERIFIED",
        build_identity,
        build_origin: "ORIGIN_UNVERIFIED",
        protected_origin: "UNKNOWN",
        policy: "REJECTED",
        error: if identity_match {
            None
        } else {
            Some("manifest/artifact identity mismatch".into())
        },
    };
    if !identity_match {
        return report;
    }
    let store = match store {
        Ok(s) => s,
        Err(e) => {
            report.error = Some(e);
            return report;
        }
    };
    report.trust_generation = Some(store.generation);
    let anchor = match store.keys.get(&m.key_id) {
        Some(k) => k,
        None => {
            report.trust_anchor = "UNKNOWN_KEY";
            report.error = Some("untrusted key ID".into());
            return report;
        }
    };
    let key = match VerifyingKey::from_bytes(&anchor.public_key) {
        Ok(k) => k,
        Err(_) => {
            report.error = Some("malformed Ed25519 public key".into());
            return report;
        }
    };
    let signature = Signature::from_bytes(&m.signature);
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + m.signed.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(&m.signed);
    report.signature_validity = "INVALID";
    if key.verify_strict(&message, &signature).is_err() {
        report.error = Some("Ed25519 signature verification failed".into());
        return report;
    }
    report.signature_validity = "VALID";
    if anchor.state == "revoked" {
        report.trust_anchor = "REVOKED";
        report.error = Some("signing key is revoked".into());
        return report;
    }
    report.trust_anchor = "TRUSTED";
    if anchor.algorithm != m.algorithm {
        report.trust_anchor = "ALGORITHM_MISMATCH";
        report.error = Some("algorithm is not allowed by key".into());
        return report;
    }
    if anchor.publisher != m.publisher {
        report.publisher_identity = "MISMATCH";
        report.error = Some("key is not authorized for claimed publisher".into());
        return report;
    }
    report.publisher_identity = "AUTHENTICATED";
    // A publisher signature authenticates the assertion, not source provenance.
    // This implementation has no independent source/build attestation checker.
    report.error = Some(format!(
        "publisher authenticated; origin claim '{}' remains unverified",
        m.origin
    ));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (Vec<u8>, ArtifactIdentity, TrustStore) {
        let signing = SigningKey::from_bytes(&[0x42; 32]); // Deterministic test fixture only.
        let public = signing.verifying_key().to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(public);
        let hash = hasher.finalize();
        let key_id = hash[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let identity = ArtifactIdentity {
            sha256: [0x24; 32],
            size: 4,
            architecture: 1,
            filetype: 2,
            device: 0,
            inode: 0,
        };
        let hex = identity
            .sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut signed = format!("schema_version=1\nartifact_sha256={hex}\nartifact_size=4\narchitecture=1\nfiletype=2\nartifact_id=fixture-bin\nrepository=https://example.invalid/org/repo\nrevision=deadbeef\nworkflow=ci-release\nbuilder=fixture-builder\npublisher=fixture-publisher\nalgorithm=ed25519\nkey_id={key_id}\norigin=unprotected\n").into_bytes();
        let mut message = SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(&signed);
        let signature = signing.sign(&message).to_bytes();
        signed.extend_from_slice(
            format!(
                "signature={}\n",
                signature
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
            .as_bytes(),
        );
        let mut keys = BTreeMap::new();
        keys.insert(
            key_id,
            Anchor {
                algorithm: "ed25519".into(),
                public_key: public,
                publisher: "fixture-publisher".into(),
                state: "active".into(),
            },
        );
        (
            signed,
            identity,
            TrustStore {
                generation: 1,
                keys,
            },
        )
    }

    #[test]
    fn rfc8032_ed25519_known_answer() {
        let secret =
            hex_decode::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let public =
            hex_decode::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let signature = hex_decode::<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        let key = VerifyingKey::from_bytes(&public).unwrap();
        key.verify_strict(b"", &Signature::from_bytes(&signature))
            .unwrap();
        let _ = secret; // RFC fixture only; never used as a production signing key.
    }

    #[test]
    fn unsupported_and_noncanonical_inputs_reject() {
        assert!(parse_manifest(b"schema_version=1\n").is_err());
        assert!(parse_store(
            b"ios-unsandboxed-trust-store\nschema_version=2\ngeneration=1\nkey_count=0\n"
        )
        .is_err());
        assert_eq!(canonical_uint("01"), Err("non-canonical integer".into()));
    }

    #[test]
    fn trust_store_keys_are_explicit_bounded_and_unique() {
        let (_, _, store) = fixture();
        let (id, anchor) = store.keys.iter().next().unwrap();
        let public = anchor
            .public_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let encoded = format!("ios-unsandboxed-trust-store\nschema_version=1\ngeneration=2\nkey_count=1\nkey_0={id}|ed25519|{public}|publisher|fixture-publisher|active\n");
        assert_eq!(parse_store(encoded.as_bytes()).unwrap().keys.len(), 1);
        let duplicate = format!(
            "{}{}\n",
            encoded.replace("key_count=1\n", "key_count=2\n"),
            encoded.lines().last().unwrap().replace("key_0=", "key_1=")
        );
        assert!(parse_store(duplicate.as_bytes()).is_err());
        let excessive =
            "ios-unsandboxed-trust-store\nschema_version=1\ngeneration=2\nkey_count=65\n";
        assert!(parse_store(excessive.as_bytes()).is_err());
    }

    #[test]
    fn signed_claims_are_authenticated_but_origin_remains_unverified() {
        let (bytes, identity, store) = fixture();
        let report = verify_manifest(&bytes, &identity, Ok(store));
        assert!(report.artifact_digest && report.document_integrity);
        assert_eq!(report.signature_validity, "VALID");
        assert_eq!(report.trust_anchor, "TRUSTED");
        assert_eq!(report.publisher_identity, "AUTHENTICATED");
        assert_eq!(report.build_origin, "ORIGIN_UNVERIFIED");
        assert_eq!(report.protected_origin, "UNKNOWN");
        assert_eq!(report.policy, "REJECTED");
    }

    #[test]
    fn altered_manifest_and_artifact_fail_closed() {
        let (mut bytes, identity, store) = fixture();
        let marker = b"artifact_id=fixture-bin";
        let index = bytes
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap()
            + b"artifact_id=".len();
        bytes[index] = if bytes[index] == b'a' { b'b' } else { b'a' };
        let report = verify_manifest(&bytes, &identity, Ok(store.clone()));
        assert!(report.document_integrity);
        assert_eq!(report.signature_validity, "INVALID");
        let (bytes, mut identity, store) = fixture();
        identity.sha256[0] ^= 1;
        let report = verify_manifest(&bytes, &identity, Ok(store));
        assert!(!report.artifact_digest);
        assert_eq!(report.policy, "REJECTED");
    }

    #[test]
    fn revoked_anchor_has_valid_signature_but_is_not_trusted() {
        let (bytes, identity, mut store) = fixture();
        store.keys.values_mut().next().unwrap().state = "revoked".into();
        let report = verify_manifest(&bytes, &identity, Ok(store));
        assert_eq!(report.signature_validity, "VALID");
        assert_eq!(report.trust_anchor, "REVOKED");
        assert_eq!(report.publisher_identity, "UNVERIFIED");
        assert_eq!(report.policy, "REJECTED");
    }

    #[test]
    fn unknown_key_and_publisher_scope_mismatch_reject() {
        let (bytes, identity, mut store) = fixture();
        store.keys.clear();
        let report = verify_manifest(&bytes, &identity, Ok(store));
        assert_eq!(report.trust_anchor, "UNKNOWN_KEY");
        assert_eq!(report.policy, "REJECTED");

        let (bytes, identity, mut store) = fixture();
        store.keys.values_mut().next().unwrap().publisher = "other-publisher".into();
        let report = verify_manifest(&bytes, &identity, Ok(store));
        assert_eq!(report.signature_validity, "VALID");
        assert_eq!(report.publisher_identity, "MISMATCH");
        assert_eq!(report.policy, "REJECTED");
    }

    #[test]
    fn unsupported_algorithm_and_truncated_signature_reject() {
        let (bytes, _, _) = fixture();
        let unsupported = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("algorithm=ed25519", "algorithm=other");
        assert!(parse_manifest(unsupported.as_bytes()).is_err());
        let truncated = String::from_utf8(bytes).unwrap();
        assert!(parse_manifest(&truncated.as_bytes()[..truncated.len() - 3]).is_err());
    }

    #[test]
    fn manifest_reader_rejects_symlinks_and_hard_links() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("iu-p013-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("manifest");
        let link = root.join("symlink");
        let hard = root.join("hardlink");
        std::fs::write(&target, b"fixture\n").unwrap();
        symlink(&target, &link).unwrap();
        std::fs::hard_link(&target, &hard).unwrap();
        assert!(safe_read(&link, MANIFEST_MAX, None, None).is_err());
        assert!(safe_read(&hard, MANIFEST_MAX, None, None).is_err());
        std::fs::remove_file(&hard).unwrap();
        assert_eq!(
            safe_read(&target, MANIFEST_MAX, None, None).unwrap(),
            b"fixture\n"
        );
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&target).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn trust_reader_uses_held_directories_and_rejects_unsafe_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::time::{SystemTime, UNIX_EPOCH};
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("iu-p013a-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let dir = root.join("trusted");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = dir.join("store.v1");
        std::fs::write(
            &store,
            b"ios-unsandboxed-trust-store\nschema_version=1\ngeneration=1\nkey_count=0\n",
        )
        .unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600)).unwrap();
        let meta = std::fs::metadata(&root).unwrap();
        let name = std::ffi::CString::new("trusted").unwrap();
        let read = |component: &std::ffi::CStr| {
            let rootfd = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open(&root)
                .unwrap();
            load_store_from_root(rootfd, &[component], meta.uid(), meta.gid())
        };
        assert_eq!(read(&name).unwrap().generation, 1);
        let alias = root.join("alias");
        symlink(&dir, &alias).unwrap();
        assert!(read(&std::ffi::CString::new("alias").unwrap()).is_err());
        let hard = root.join("hard");
        std::fs::hard_link(&store, &hard).unwrap();
        assert!(read(&name).is_err());
        std::fs::remove_file(hard).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&name).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(store).unwrap();
        std::fs::remove_dir(dir).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
