//! Privileged descriptor-relative persistence. The C caller owns platform,
//! installation and P007 lock checks; this boundary owns schemas and all trust IO.
use crate::builder_mutation::{self, BuilderMutationRequestV1 as Request};
use crate::builder_transaction::{
    self as tx, Journal, Marker, Observation, Pair, TransactionState as State,
};
use crate::builder_trust::{self as schema, BuilderMutationBaseV1, MAX_STORE_BYTES};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

type Result<T> = std::result::Result<T, String>;
const NAMES: [&str; 7] = [
    "roots.v1",
    "policies.v1",
    "state.v1",
    "transaction.v1",
    "roots.stage.v1",
    "policies.stage.v1",
    "state.stage.v1",
];
const ROOT: &str = "roots.v1";
const POLICY: &str = "policies.v1";
const JOURNAL: &str = "transaction.v1";
const MARKER: &str = "state.v1";
const MARKER_STAGE: &str = "state.stage.v1";

/// Pointer fields are borrowed C argv strings, never store bytes or digests.
#[repr(C)]
pub struct AdminRequest {
    abi_version: u32,
    struct_size: u32,
    datafd: i32,
    uid: u32,
    gid: u32,
    apply: u32,
    action: *const libc::c_char,
    first: *const libc::c_char,
    second: *const libc::c_char,
    identity: *const libc::c_char,
    reserved: u64,
}
const _: () = assert!(std::mem::size_of::<AdminRequest>() == 64);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Identity {
    fn of(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(err)?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            links: m.nlink(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }
    fn safe(&self, uid: u32, gid: u32, directory: bool) -> bool {
        self.uid == uid
            && self.gid == gid
            && self.mode & 0o7777 == if directory { 0o700 } else { 0o600 }
            // POSIX type bits on both supported platforms; libc mode_t is
            // u16 on Darwin and u32 on Linux, while MetadataExt::mode is u32.
            && self.mode & 0o170000 == if directory { 0o040000 } else { 0o100000 }
            && (directory || self.links == 1)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    identity: Identity,
    bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot(BTreeMap<String, Entry>);
impl Snapshot {
    fn bytes(&self, name: &str) -> Option<&[u8]> {
        self.0.get(name).map(|e| e.bytes.as_slice())
    }
    fn journal(&self) -> Result<Option<Journal>> {
        self.bytes(JOURNAL)
            .map(tx::parse_journal)
            .transpose()
            .map_err(str::to_owned)
    }
    fn store_pair(&self, name: &str) -> Result<Option<Pair>> {
        self.bytes(name)
            .map(|bytes| {
                let generation = if name.starts_with("roots") {
                    schema::parse_root_store(bytes).map(|(_, g)| g)
                } else {
                    schema::parse_policy_store(bytes).map(|(_, g)| g)
                }
                .map_err(|e| e.message)?;
                if generation == 0 {
                    return Err("zero generation is not an administrative store".into());
                }
                Ok(Pair {
                    generation,
                    digest: schema::hex(&Sha256::digest(bytes)),
                })
            })
            .transpose()
    }
    fn marker(&self, name: &str) -> Result<Option<Marker>> {
        self.bytes(name)
            .map(tx::parse_marker)
            .transpose()
            .map_err(str::to_owned)
    }
    fn state(&self) -> State {
        fn obs<T>(value: Result<Option<T>>) -> Observation<T> {
            match value {
                Ok(Some(v)) => Observation::Valid(v),
                Ok(None) => Observation::Absent,
                Err(_) => Observation::Invalid,
            }
        }
        let state = tx::classify(
            obs(self.journal()),
            obs(self.store_pair(ROOT)),
            obs(self.store_pair(POLICY)),
            obs(self.store_pair("roots.stage.v1")),
            obs(self.store_pair("policies.stage.v1")),
            obs(self.marker(MARKER)),
        );
        if self.bytes(MARKER_STAGE).is_some() {
            match (self.journal(), self.marker(MARKER_STAGE)) {
                (Ok(Some(j)), Ok(Some(m)))
                    if m.roots == j.new_roots
                        && m.policies == j.new_policies
                        && matches!(
                            state,
                            State::BothStoresReplaced
                                | State::CommittedPairMarkerPending
                                | State::CompleteCommit
                        ) =>
                {
                    state
                }
                _ => State::ConflictingState,
            }
        } else {
            state
        }
    }
    fn settled(&self) -> Result<()> {
        if self
            .0
            .keys()
            .any(|n| ![ROOT, POLICY, MARKER].contains(&n.as_str()))
        {
            return Err("builder transaction artifacts require recovery".into());
        }
        match (
            self.store_pair(ROOT)?,
            self.store_pair(POLICY)?,
            self.marker(MARKER)?,
        ) {
            (None, None, None) => Ok(()),
            (Some(r), Some(p), Some(m)) if r == m.roots && p == m.policies => Ok(()),
            _ => Err("incomplete or inconsistent builder pair/marker".into()),
        }
    }
    fn report(&self, persistence: &str) {
        let state = self.state();
        println!("Builder trust transaction: {}\nRoot generation: {}\nPolicy generation: {}\nTransaction state: {}\nRecovery required: {}\nPersistence: {}", if self.bytes(JOURNAL).is_some() { "PENDING" } else { "NONE" }, self.store_pair(ROOT).ok().flatten().map(|p| p.generation.to_string()).unwrap_or_else(|| "ABSENT/INVALID".into()), self.store_pair(POLICY).ok().flatten().map(|p| p.generation.to_string()).unwrap_or_else(|| "ABSENT/INVALID".into()), state.label(), if self.settled().is_ok() { "NO" } else { "YES" }, persistence);
        limits();
    }
}
fn limits() {
    println!("Independent trust establishment: UNVERIFIED\nRollback protection: UNVERIFIED\nBuild origin: BUILD_ORIGIN_UNVERIFIED\nProtected origin: UNKNOWN\nAmethyst runtime: UNVERIFIED\nLaunch boundary: NOT IMPLEMENTED\nExecution activation: DISABLED\nOperational authorization: FALSE");
}
fn err(e: std::io::Error) -> String {
    e.to_string()
}
fn c(s: &str) -> CString {
    CString::new(s).expect("fixed internal filename")
}
fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c(name).as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode, // openat is variadic: use the promoted unsigned-int type on Darwin too.
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn names(dir: &File) -> Result<BTreeSet<String>> {
    let scan = open_at(dir, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(err)?;
    let fd = std::os::fd::IntoRawFd::into_raw_fd(scan);
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe {
            libc::close(fd);
        }
        return Err("fdopendir failed".into());
    }
    let mut result = BTreeSet::new();
    let outcome = (|| {
        loop {
            // POSIX readdir uses errno to distinguish end-of-directory from error.
            set_errno_zero();
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err("readdir failed".into());
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| "non-UTF8 foreign entry")?;
            if name == "." || name == ".." {
                continue;
            }
            if !NAMES.contains(&name) {
                return Err(format!(
                    "foreign builder trust entry: {name}; preserve evidence"
                ));
            }
            result.insert(name.to_owned());
        }
        Ok(result)
    })();
    unsafe {
        libc::closedir(stream);
    }
    outcome
}
fn set_errno_zero() {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(target_vendor = "apple")]
    unsafe {
        *libc::__error() = 0;
    }
}
struct Directory {
    parent: File,
    dir: File,
    uid: u32,
    gid: u32,
    dev: u64,
    ino: u64,
}
impl Directory {
    fn open(datafd: i32, uid: u32, gid: u32, create: bool) -> Result<Option<Self>> {
        if datafd < 0 {
            return if create {
                Err("project data directory missing".into())
            } else {
                Ok(None)
            };
        }
        let fd = unsafe { libc::fcntl(datafd, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err("cannot duplicate project data descriptor".into());
        }
        let parent = unsafe { File::from_raw_fd(fd) };
        if !Identity::of(&parent)?.safe(uid, gid, true) {
            return Err("unsafe project data directory".into());
        }
        let dir = match open_at(
            &parent,
            "builder-trust",
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if unsafe { libc::mkdirat(parent.as_raw_fd(), c("builder-trust").as_ptr(), 0o700) }
                    != 0
                {
                    return Err("cannot create builder directory".into());
                }
                let dir = open_at(
                    &parent,
                    "builder-trust",
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )
                .map_err(err)?;
                if unsafe { libc::fchown(dir.as_raw_fd(), uid, gid) } != 0
                    || unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } != 0
                {
                    return Err("builder directory ownership failed".into());
                }
                dir.sync_all().map_err(err)?;
                parent.sync_all().map_err(err)?;
                dir
            }
            Err(e) => return Err(format!("unsafe/unavailable builder directory: {e}")),
        };
        let id = Identity::of(&dir)?;
        if !id.safe(uid, gid, true) {
            return Err("unsafe builder directory owner/mode/type".into());
        }
        Ok(Some(Self {
            parent,
            dir,
            uid,
            gid,
            dev: id.dev,
            ino: id.ino,
        }))
    }
    fn verify(&self) -> Result<()> {
        let current = open_at(
            &self.parent,
            "builder-trust",
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .map_err(err)?;
        let id = Identity::of(&current)?;
        if !id.safe(self.uid, self.gid, true) || id.dev != self.dev || id.ino != self.ino {
            return Err("builder directory identity changed".into());
        }
        Ok(())
    }
    fn load(&self, name: &str) -> Result<Entry> {
        let mut file = open_at(&self.dir, name, libc::O_RDONLY, 0).map_err(err)?;
        let before = Identity::of(&file)?;
        let bound = match name {
            JOURNAL => tx::MAX_JOURNAL_BYTES,
            MARKER | MARKER_STAGE => tx::MAX_MARKER_BYTES,
            _ => MAX_STORE_BYTES,
        };
        if !before.safe(self.uid, self.gid, false) || before.size > bound as u64 {
            return Err(format!("unsafe owner/mode/link/type/size: {name}"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(bound as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        let after = Identity::of(&file)?;
        let reopened = open_at(&self.dir, name, libc::O_RDONLY, 0).map_err(err)?;
        if before != after
            || before != Identity::of(&reopened)?
            || bytes.len() as u64 != before.size
        {
            return Err(format!("entry changed during read: {name}"));
        }
        Ok(Entry {
            identity: before,
            bytes,
        })
    }
    fn snapshot(&self) -> Result<Snapshot> {
        self.verify()?;
        let before = names(&self.dir)?;
        let mut entries = BTreeMap::new();
        for n in &before {
            entries.insert(n.clone(), self.load(n)?);
        }
        if before != names(&self.dir)? {
            return Err("directory entries changed during read".into());
        }
        for (name, value) in &entries {
            if *value != self.load(name)? {
                return Err("snapshot changed during read".into());
            }
        }
        self.verify()?;
        Ok(Snapshot(entries))
    }
    fn expect(&self, snapshot: &Snapshot) -> Result<()> {
        if self.snapshot()? != *snapshot {
            return Err("filesystem changed since validation".into());
        }
        Ok(())
    }
    fn sync(&self, fault: &Fault) -> Result<()> {
        fault.io("builder-fail-dir-fsync")?;
        self.dir.sync_all().map_err(err)
    }
    fn write_new(&self, name: &str, bytes: &[u8], fault: &Fault) -> Result<()> {
        self.verify()?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err("write exceeds bounded store limit".into());
        }
        let mut file = open_at(
            &self.dir,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .map_err(err)?;
        if unsafe { libc::fchown(file.as_raw_fd(), self.uid, self.gid) } != 0
            || unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
        {
            return Err("file ownership failed".into());
        }
        let before = Identity::of(&file)?;
        if !before.safe(self.uid, self.gid, false) {
            return Err("unsafe new file".into());
        }
        fault.io("builder-fail-write")?;
        if fault.is("builder-disk-full") {
            file.write_all(&bytes[..1]).map_err(err)?;
            return Err("simulated ENOSPC after short write".into());
        }
        // A host fixture exercises the actual bounded write loop with 1-byte writes.
        let mut rest = bytes;
        while !rest.is_empty() {
            let chunk = if fault.is("builder-short-write") {
                &rest[..1]
            } else {
                rest
            };
            match file.write(chunk) {
                Ok(0) => return Err("zero-length write".into()),
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(err(e)),
            }
        }
        fault.io("builder-fail-fsync")?;
        if name == JOURNAL {
            fault.io("builder-fail-journal-fsync")?;
        }
        if name == MARKER_STAGE {
            fault.io("builder-fail-marker-fsync")?;
        }
        file.sync_all().map_err(err)?;
        let actual = self.load(name)?;
        if actual.identity.dev != before.dev
            || actual.identity.ino != before.ino
            || actual.bytes != bytes
        {
            return Err("new file failed descriptor/content validation".into());
        }
        Ok(())
    }
    fn rename(&self, from: &str, to: &str, expected: &Snapshot, fault: &Fault) -> Result<()> {
        self.expect(expected)?;
        fault.io("builder-fail-rename")?;
        if unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                c(from).as_ptr(),
                self.dir.as_raw_fd(),
                c(to).as_ptr(),
            )
        } != 0
        {
            return Err(err(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    fn remove(&self, name: &str, expected: &Snapshot) -> Result<()> {
        self.expect(expected)?;
        if !expected.0.contains_key(name) {
            return Err("refusing to remove absent/unverified artifact".into());
        }
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), c(name).as_ptr(), 0) } != 0 {
            return Err(err(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

struct Fault {
    #[cfg(feature = "builder-admin-testing")]
    name: Option<String>,
}
impl Fault {
    fn none() -> Self {
        Self {
            #[cfg(feature = "builder-admin-testing")]
            name: None,
        }
    }
    fn is(&self, name: &str) -> bool {
        #[cfg(feature = "builder-admin-testing")]
        {
            self.name.as_deref() == Some(name)
        }
        #[cfg(not(feature = "builder-admin-testing"))]
        {
            let _ = name;
            false
        }
    }
    fn point(&self, name: &str) {
        if self.is(name) {
            unsafe {
                libc::_exit(86);
            }
        }
    }
    fn io(&self, name: &str) -> Result<()> {
        if self.is(name) {
            Err(format!("injected IO failure: {name}"))
        } else {
            Ok(())
        }
    }
}

fn request(action: &str, first: &str, second: &str, identity: &str) -> Result<Request> {
    Ok(match action {
        "add-signer" => Request::AddSigner {
            public_key: builder_mutation::read_public_key_file(Path::new(first))
                .map_err(|e| e.0)?,
            signer_identity: identity.into(),
            enrollment_reference: None,
        },
        "revoke-signer" => Request::RevokeSigner {
            key_id: first.into(),
        },
        "rotate-signer" => Request::RotateSigner {
            old_key_id: first.into(),
            new_public_key: builder_mutation::read_public_key_file(Path::new(second))
                .map_err(|e| e.0)?,
            new_signer_identity: identity.into(),
            enrollment_reference: None,
        },
        "add-policy" => Request::AddPolicy {
            policy: builder_mutation::read_policy_file(Path::new(first)).map_err(|e| e.0)?,
        },
        "revoke-policy" => Request::RevokePolicy {
            policy_id: first.into(),
        },
        _ => return Err("unknown builder mutation operation".into()),
    })
}
fn marker_bytes(j: &Journal) -> Vec<u8> {
    builder_mutation::marker_bytes(
        j.new_roots.generation,
        &j.new_roots.digest,
        j.new_policies.generation,
        &j.new_policies.digest,
    )
}
fn recoverable(state: State) -> bool {
    matches!(
        state,
        State::PreparedOldPair
            | State::FirstStoreReplaced
            | State::SecondStoreReplaced
            | State::BothStoresReplaced
            | State::CommittedPairMarkerPending
            | State::CompleteCommit
    )
}

/// Check all old records still available against the intended new stores.
/// Once a rename consumed an old store, its trusted journal digest binds the
/// previously validated transition; recovery never substitutes an older store.
fn reconcile(s: &Snapshot, j: &Journal) -> Result<()> {
    let new_roots = if s.store_pair(ROOT)?.as_ref() == Some(&j.new_roots) {
        s.bytes(ROOT)
    } else {
        s.bytes("roots.stage.v1")
    }
    .ok_or("new roots unavailable")?;
    let new_policies = if s.store_pair(POLICY)?.as_ref() == Some(&j.new_policies) {
        s.bytes(POLICY)
    } else {
        s.bytes("policies.stage.v1")
    }
    .ok_or("new policies unavailable")?;
    let (roots, _) = schema::parse_root_store(new_roots).map_err(|e| e.message)?;
    let (policies, _) = schema::parse_policy_store(new_policies).map_err(|e| e.message)?;
    if s.store_pair(ROOT)?.as_ref() == j.old_roots.as_ref() {
        if let Some(old) = s.bytes(ROOT) {
            let (old, _) = schema::parse_root_store(old).map_err(|e| e.message)?;
            for (id, record) in &old.keys {
                let next = roots
                    .keys
                    .get(id)
                    .ok_or("recovery would remove key history")?;
                let mut expected = record.clone();
                if expected.state == "active" {
                    expected.state = next.state.clone();
                }
                if next != &expected {
                    return Err("recovery would rewrite or reactivate signer history".into());
                }
            }
        }
    }
    if j.old_policies.is_none() {
        for policy in policies.policies.values().filter(|p| p.state == "active") {
            if !roots
                .keys
                .values()
                .any(|key| key.signer_identity == policy.signer_identity && key.state == "active")
            {
                return Err("initial policy has no active signer".into());
            }
        }
    }
    if s.store_pair(POLICY)?.as_ref() == j.old_policies.as_ref() {
        if let Some(old) = s.bytes(POLICY) {
            let (old, _) = schema::parse_policy_store(old).map_err(|e| e.message)?;
            for (id, record) in &old.policies {
                if policies.policies.get(id) == Some(record) {
                    continue;
                }
                if record.state != "active" {
                    return Err("recovery would remove revoked policy history".into());
                }
                let mut revoked = record.clone();
                revoked.state = "revoked".into();
                revoked.policy_id = schema::derive_policy_id(&revoked).map_err(|e| e.message)?;
                if policies.policies.get(&revoked.policy_id) != Some(&revoked) {
                    return Err("recovery would alter policy scope/history".into());
                }
            }
            for (id, policy) in &policies.policies {
                if old.policies.contains_key(id) || policy.state == "revoked" {
                    continue;
                }
                if !roots.keys.values().any(|key| {
                    key.signer_identity == policy.signer_identity && key.state == "active"
                }) {
                    return Err("new policy has no active signer".into());
                }
            }
        }
    }
    Ok(())
}

/// No rollback exists: every live replacement consumes only a verified new stage.
fn forward(dir: &Directory, journal: &[u8], fault: &Fault) -> Result<()> {
    let j = tx::parse_journal(journal).map_err(str::to_owned)?;
    let initial = dir.snapshot()?;
    if initial.bytes(JOURNAL) != Some(journal) || !recoverable(initial.state()) {
        return Err("journal is not a verified recoverable transaction".into());
    }
    reconcile(&initial, &j)?;
    // Recovery may observe complete bytes left by an unsuccessful journal
    // fsync. Establish durability again before allowing any live replacement.
    let journal_file = open_at(&dir.dir, JOURNAL, libc::O_RDWR, 0).map_err(err)?;
    fault.io("builder-fail-recovery-journal-fsync")?;
    journal_file.sync_all().map_err(err)?;
    dir.sync(fault)?;
    dir.expect(&initial)?;
    for (index, (live, stage, new)) in [
        (ROOT, "roots.stage.v1", &j.new_roots),
        (POLICY, "policies.stage.v1", &j.new_policies),
    ]
    .into_iter()
    .enumerate()
    {
        let s = dir.snapshot()?;
        if s.bytes(JOURNAL) != Some(journal) || !recoverable(s.state()) {
            return Err("transaction evidence changed or missing; preserving files".into());
        }
        if s.store_pair(live)?.as_ref() == Some(new) {
            continue;
        }
        if s.store_pair(stage)?.as_ref() != Some(new) {
            return Err("missing or incorrect necessary stage".into());
        }
        fault.point(if index == 0 {
            "builder-before-first-rename"
        } else {
            "builder-before-second-rename"
        });
        // Complete staged evidence found by recovery is flushed again before
        // consumption, even if an earlier process returned a sync error.
        open_at(&dir.dir, stage, libc::O_RDWR, 0)
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        dir.sync(fault)?;
        dir.rename(stage, live, &s, fault)?;
        fault.point(if index == 0 {
            "builder-after-first-rename"
        } else {
            "builder-after-second-rename"
        });
        // Failure after a rename never proceeds to marker or cleanup.
        fault.io("builder-fail-post-rename-fsync")?;
        dir.sync(fault)?;
        fault.point(if index == 0 {
            "builder-after-first-dir-fsync"
        } else {
            "builder-after-second-dir-fsync"
        });
    }
    // Repeat fsync even when a prior process renamed but died before directory sync.
    dir.sync(fault)?;
    let s = dir.snapshot()?;
    if s.bytes(JOURNAL) != Some(journal)
        || !recoverable(s.state())
        || s.store_pair(ROOT)?.as_ref() != Some(&j.new_roots)
        || s.store_pair(POLICY)?.as_ref() != Some(&j.new_policies)
    {
        return Err("new pair failed final verification".into());
    }
    let marker = marker_bytes(&j);
    fault.point("builder-before-marker");
    if s.bytes(MARKER) != Some(marker.as_slice()) {
        if s.bytes(MARKER_STAGE).is_none() {
            dir.write_new(MARKER_STAGE, &marker, fault)?;
            dir.sync(fault)?;
        } else if s.bytes(MARKER_STAGE) != Some(marker.as_slice()) {
            return Err("conflicting marker stage".into());
        }
        // An earlier process may have stopped during this stage's fsync.
        // Validate and flush its complete bytes again before publication.
        open_at(&dir.dir, MARKER_STAGE, libc::O_RDWR, 0)
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        dir.sync(fault)?;
        fault.point("builder-after-marker-fsync");
        let s = dir.snapshot()?;
        if s.bytes(JOURNAL) != Some(journal) || !recoverable(s.state()) {
            return Err("journal changed before marker publication".into());
        }
        dir.rename(MARKER_STAGE, MARKER, &s, fault)?;
        fault.point("builder-after-marker-rename");
        dir.sync(fault)?;
    }
    let s = dir.snapshot()?;
    if s.bytes(JOURNAL) != Some(journal) || s.state() != State::CompleteCommit {
        return Err("complete pair and marker not verified; evidence retained".into());
    }
    // Persist marker on retries even if it was renamed before an earlier failure.
    open_at(&dir.dir, MARKER, libc::O_RDONLY, 0)
        .map_err(err)?
        .sync_all()
        .map_err(err)?;
    dir.sync(fault)?;
    fault.point("builder-before-cleanup");
    if s.bytes(MARKER_STAGE).is_some() {
        dir.remove(MARKER_STAGE, &s)?;
        dir.sync(fault)?;
    }
    fault.point("builder-during-cleanup");
    let s = dir.snapshot()?;
    if s.bytes(JOURNAL) != Some(journal) || s.state() != State::CompleteCommit {
        return Err("cleanup evidence changed".into());
    }
    dir.remove(JOURNAL, &s)?;
    dir.sync(fault)?;
    fault.point("builder-after-cleanup");
    dir.snapshot()?.settled()?;
    Ok(())
}

fn orphan_cleanup(dir: &Directory, s: &Snapshot, apply: bool, fault: &Fault) -> Result<()> {
    // With no journal, do not promote any stage. Cleanup is allowed only for
    // canonical next-generation stages and an intact settled old pair (or the
    // wholly absent initial pair). Half commits/missing markers preserve evidence.
    if s.bytes(MARKER_STAGE).is_some() {
        return Err("orphan marker stage; preserve evidence".into());
    }
    let mut live = s.clone();
    live.0.remove("roots.stage.v1");
    live.0.remove("policies.stage.v1");
    live.settled()?;
    for (name, old) in [("roots.stage.v1", ROOT), ("policies.stage.v1", POLICY)] {
        if let Some(stage) = s.store_pair(name)? {
            let expected = s
                .store_pair(old)?
                .map(|p| p.generation.checked_add(1))
                .unwrap_or(Some(1));
            if Some(stage.generation) != expected {
                return Err("orphan stage is not a canonical next generation".into());
            }
        }
    }
    println!("Orphan stages: verified uncommitted evidence; unchanged live pair; cleanup only");
    if apply {
        for name in ["roots.stage.v1", "policies.stage.v1"] {
            let now = dir.snapshot()?;
            if now.bytes(name).is_some() {
                // Other entries must still be the exact originally observed bytes and identities.
                let expected = Snapshot(
                    s.0.iter()
                        .filter(|(n, _)| now.0.contains_key(*n))
                        .map(|(n, e)| (n.clone(), e.clone()))
                        .collect(),
                );
                if now != expected {
                    return Err("orphan evidence changed".into());
                }
                dir.remove(name, &now)?;
                dir.sync(fault)?;
            }
        }
        dir.snapshot()?.settled()?;
    }
    Ok(())
}

fn run(r: &AdminRequest, fault: &Fault) -> Result<()> {
    if r.abi_version != 1
        || r.struct_size as usize != std::mem::size_of::<AdminRequest>()
        || r.apply > 1
        || r.reserved != 0
    {
        return Err("invalid privileged ABI request".into());
    }
    let action = argument(r.action)?;
    let first = argument(r.first)?;
    let second = argument(r.second)?;
    let identity = argument(r.identity)?;
    let apply = r.apply == 1;
    let dir = Directory::open(r.datafd, r.uid, r.gid, false)?;
    let s = dir
        .as_ref()
        .map(Directory::snapshot)
        .transpose()?
        .unwrap_or_else(|| Snapshot(BTreeMap::new()));
    s.report("NOT_APPLIED");
    if action == "recover" {
        if s.settled().is_ok() {
            println!("Recovery: no-op; settled state");
            return Ok(());
        }
        let dir = dir.as_ref().ok_or("missing builder directory")?;
        if s.bytes(JOURNAL).is_none() {
            orphan_cleanup(dir, &s, apply, fault)?;
        } else {
            if !recoverable(s.state()) {
                return Err("forward recovery cannot be proven safe; evidence preserved".into());
            }
            if apply {
                forward(dir, s.bytes(JOURNAL).ok_or("journal missing")?, fault)?;
            }
        }
        if apply {
            dir.snapshot()?.report("COMMITTED");
        }
        return Ok(());
    }
    if matches!(action.as_str(), "status" | "list" | "inspect") {
        s.settled()?;
        let base = BuilderMutationBaseV1::from_admin_bytes(s.bytes(ROOT), s.bytes(POLICY))
            .map_err(|e| e.message)?;
        if action != "status" {
            if let Some(roots) = base.roots {
                for key in roots
                    .keys
                    .values()
                    .filter(|k| action == "list" || k.signer_identity == first)
                {
                    println!(
                        "Signer: {} keyId={} state={}",
                        key.signer_identity, key.key_id, key.state
                    );
                    if let Some(policies) = &base.policies {
                        for policy in policies
                            .policies
                            .values()
                            .filter(|p| p.signer_identity == key.signer_identity)
                        {
                            println!(
                                "Policy: {} builder={} state={}",
                                policy.policy_id, policy.builder_id, policy.state
                            );
                        }
                    }
                }
            }
        }
        return Ok(());
    }
    s.settled()?;
    let base = BuilderMutationBaseV1::from_admin_bytes(s.bytes(ROOT), s.bytes(POLICY))
        .map_err(|e| e.message)?;
    let plan =
        builder_mutation::plan_from_base(&base, request(&action, &first, &second, &identity)?)
            .map_err(|e| e.0)?;
    println!("{}", plan.render());
    if !apply || !plan.changed {
        return Ok(());
    }
    // No filesystem creation on dry runs or no-op mutations.
    let dir = match dir {
        Some(d) => d,
        None => {
            Directory::open(r.datafd, r.uid, r.gid, true)?.ok_or("directory creation failed")?
        }
    };
    dir.expect(&s)?;
    let journal = plan
        .expected_transaction
        .as_ref()
        .ok_or("missing reconstructed journal")?;
    let j = tx::parse_journal(journal).map_err(str::to_owned)?;
    fault.point("builder-before-stage");
    let mut expected = s.clone();
    for (index, (stage, proposed, old, new)) in [
        (
            "roots.stage.v1",
            plan.proposed_roots_bytes.as_ref(),
            j.old_roots.as_ref(),
            &j.new_roots,
        ),
        (
            "policies.stage.v1",
            plan.proposed_policies_bytes.as_ref(),
            j.old_policies.as_ref(),
            &j.new_policies,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if old == Some(new) {
            continue;
        }
        dir.expect(&expected)?;
        dir.write_new(stage, proposed.ok_or("missing proposed store")?, fault)?;
        expected.0.insert(stage.into(), dir.load(stage)?);
        dir.expect(&expected)?;
        fault.point(if index == 0 {
            "builder-after-first-stage-fsync"
        } else {
            "builder-after-second-stage-fsync"
        });
    }
    dir.sync(fault)?;
    fault.point("builder-before-journal");
    dir.expect(&expected)?;
    dir.write_new(JOURNAL, journal, fault)?;
    dir.sync(fault)?;
    expected.0.insert(JOURNAL.into(), dir.load(JOURNAL)?);
    dir.expect(&expected)?;
    if expected.state() != State::PreparedOldPair {
        return Err("prepared transaction failed independent classification".into());
    }
    fault.point("builder-after-journal-fsync");
    forward(&dir, journal, fault)?;
    dir.snapshot()?.report("COMMITTED");
    Ok(())
}
fn argument(ptr: *const libc::c_char) -> Result<String> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    // Pointers are valid borrowed argv strings supplied by the C helper, never
    // dereferenced as authority-bearing store objects.
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| "argument is not UTF-8")?;
    if value.len() > 4096 {
        return Err("argument exceeds bound".into());
    }
    Ok(value.into())
}
fn boundary(request: *const AdminRequest, fault: Fault) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if request.is_null() {
            return Err("null privileged request".into());
        }
        run(unsafe { &*request }, &fault)
    });
    match result {
        Ok(Ok(())) => 0,
        other => {
            let message = match other {
                Ok(Err(e)) => e,
                _ => "privileged Rust boundary panic".into(),
            };
            eprintln!("Builder administration stopped: {message}; preserve transaction evidence");
            println!("Persistence: RECOVERY_REQUIRED\nRecovery required: YES");
            limits();
            3
        }
    }
}
#[no_mangle]
pub extern "C" fn iu_builder_admin_v1(request: *const AdminRequest) -> i32 {
    boundary(request, Fault::none())
}
#[no_mangle]
pub extern "C" fn iu_builder_admin_settled_v1(datafd: i32, uid: u32, gid: u32) -> i32 {
    match std::panic::catch_unwind(|| {
        Directory::open(datafd, uid, gid, false)
            .and_then(|d| d.map(|d| d.snapshot()?.settled()).unwrap_or(Ok(())))
    }) {
        Ok(Ok(())) => 0,
        _ => 3,
    }
}
#[cfg(feature = "builder-admin-testing")]
#[no_mangle]
pub extern "C" fn iu_builder_admin_test_v1(
    request: *const AdminRequest,
    fault: *const libc::c_char,
) -> i32 {
    match argument(fault) {
        Ok(name) => boundary(request, Fault { name: Some(name) }),
        Err(_) => 3,
    }
}
