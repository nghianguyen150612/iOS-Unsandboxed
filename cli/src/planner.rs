use std::ffi::{c_char, CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;

const PATH_CAPACITY: usize = 1024;
const MACHO_UNSUPPORTED_FORMAT: u32 = 6;
const MACHO_TRUNCATED_OR_CORRUPT: u32 = 7;
const MACHO_IO_ERROR: u32 = 8;
const PREPARATION_UNSUPPORTED_TARGET: u32 = 5;

#[repr(C)]
#[allow(dead_code)]
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

const _: [(); 1232] = [(); std::mem::size_of::<PlanV1>()];

#[repr(C)]
struct LaunchSummaryV1 {
    abi_version: u32,
    struct_size: u32,
    scope_state: u32,
    store_state: u32,
    provenance_state: u32,
    decision: u32,
    boundary_status: u32,
    operational_authorization: u32,
    device: u64,
    inode: u64,
    sha256: [u8; 32],
}

extern "C" {
    fn iu_launch_binding_path_summary_v1(path: *const c_char, summary: *mut LaunchSummaryV1)
        -> i32;
    fn iu_execution_plan_create_v1(path: *const c_char, result: *mut PlanV1) -> i32;
    fn iu_execution_plan_preparation_name_v1(state: u32) -> *const c_char;
    fn iu_execution_plan_preview_name_v1(status: u32) -> *const c_char;
    fn iu_ame_macho_state_name_v1(state: u32) -> *const c_char;
    fn iu_ame_compatibility_name_v1(state: u32) -> *const c_char;
}

fn c_name(value: *const c_char) -> &'static str {
    if value.is_null() {
        return "UNKNOWN";
    }
    // These functions return process-lifetime static C strings.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .unwrap_or("UNKNOWN")
}

pub fn inspect(path: &OsStr) -> Result<(String, bool), String> {
    inspect_inner(path, false)
}

pub fn plan(path: &OsStr) -> Result<(String, bool), String> {
    inspect_inner(path, true)
}

pub fn artifact_identity(path: &OsStr) -> Result<crate::provenance::ArtifactIdentity, String> {
    let path_c = CString::new(path.as_bytes())
        .map_err(|_| "path contains an embedded NUL byte".to_owned())?;
    let mut out = std::mem::MaybeUninit::<PlanV1>::zeroed();
    let rc = unsafe { iu_execution_plan_create_v1(path_c.as_ptr(), out.as_mut_ptr()) };
    if rc != 0 {
        return Err(format!("artifact inspection failed ({})", -rc));
    }
    let out = unsafe { out.assume_init() };
    if out.abi_version != 1
        || out.struct_size as usize != std::mem::size_of::<PlanV1>()
        || out.inspection_status != 1
    {
        return Err("artifact identity is incomplete".into());
    }
    Ok(crate::provenance::ArtifactIdentity {
        sha256: out.sha256,
        size: out.file_size,
        architecture: out.architecture,
        filetype: out.macho_filetype,
    })
}

fn inspect_inner(path: &OsStr, binding: bool) -> Result<(String, bool), String> {
    let path_c = CString::new(path.as_bytes())
        .map_err(|_| "path contains an embedded NUL byte".to_owned())?;
    let mut plan = std::mem::MaybeUninit::<PlanV1>::zeroed();
    // `path_c` remains live through the synchronous call and the output is a
    // fixed-size C ABI record with no pointers.
    let rc = unsafe { iu_execution_plan_create_v1(path_c.as_ptr(), plan.as_mut_ptr()) };
    if rc != 0 {
        let code = -rc;
        return Err(match code {
            1 => "invalid argument".to_owned(),
            2 => "invalid planner ABI".to_owned(),
            3 => "unsafe or invalid path (empty, traversal, symlink, or too long)".to_owned(),
            4 => "unsafe target (non-regular file, hard link, or oversized file)".to_owned(),
            5 => "target could not be read".to_owned(),
            6 => "file identity changed during inspection".to_owned(),
            _ => "planner inspection failed".to_owned(),
        });
    }
    let plan = unsafe { plan.assume_init() };
    if plan.abi_version != 1 || plan.struct_size as usize != std::mem::size_of::<PlanV1>() {
        return Err("planner returned an incompatible ABI record".to_owned());
    }
    if plan.inspection_status != 1 || plan.canonical_path_length as usize >= PATH_CAPACITY {
        return Err("planner returned an incomplete identity record".to_owned());
    }
    let path = unsafe { CStr::from_ptr(plan.canonical_path.as_ptr()) }.to_string_lossy();
    let architecture = match plan.architecture {
        1 => "ARM64",
        _ => "UNSUPPORTED",
    };
    let filetype = match plan.macho_filetype {
        2 => "MH_EXECUTE",
        6 => "MH_DYLIB",
        8 => "MH_BUNDLE",
        1 => "MH_OBJECT",
        _ => "UNKNOWN",
    };
    let mut digest = String::with_capacity(64);
    for byte in plan.sha256 {
        use std::fmt::Write;
        let _ = write!(digest, "{byte:02x}");
    }
    let prep = c_name(unsafe { iu_execution_plan_preparation_name_v1(plan.signature_preparation) });
    let macho = c_name(unsafe { iu_ame_macho_state_name_v1(plan.macho_state) });
    let preview = c_name(unsafe { iu_execution_plan_preview_name_v1(plan.preview_status) });
    let adapter = c_name(unsafe { iu_ame_compatibility_name_v1(plan.adapter_compatibility) });
    let missing_prerequisites = missing_prerequisite_names(plan.missing_prerequisites);
    let (inspection, valid) = match plan.macho_state {
        MACHO_TRUNCATED_OR_CORRUPT => ("INVALID_BINARY".to_owned(), false),
        MACHO_UNSUPPORTED_FORMAT => ("UNSUPPORTED_BINARY".to_owned(), false),
        MACHO_IO_ERROR => ("INSPECTION_FAILED".to_owned(), false),
        _ if plan.signature_preparation == PREPARATION_UNSUPPORTED_TARGET => {
            ("UNSUPPORTED_BINARY".to_owned(), false)
        }
        _ => ("COMPLETE".to_owned(), true),
    };
    let mut report = format!(
        "iOS-Unsandboxed v0.1.0\n\nFile: {path}\nFile type: REGULAR\nArchitecture: {architecture}\nMach-O: {filetype}\nSignature: {macho}\nPreparation: {}\nSHA-256: {digest}\nIdentity: RECORDED (device={}, inode={}, size={}, mode={:04o}, uid={}, gid={}, links={}, mtime={}.{:09}, ctime={}.{:09})\nRevalidation: REQUIRED BEFORE ANY FUTURE OPERATION\nInspection: {inspection}\nPlanner preview: {preview}\nP003 policy outcome: {} (reason={})\nRequired capabilities: ARM64_MACHO_INSPECTION, FUTURE_EXECUTION_ADAPTER (0x{:08x})\nMissing prerequisites: {missing_prerequisites} (0x{:08x})\nAmethyst compatibility: {adapter}\nRuntime hook state: UNVERIFIED\nSSH interception coverage: BLOCKED / UNVERIFIED\nAmethyst trust-cache support: UNVERIFIED\nSigning preparation: NOT IMPLEMENTED\nProcess unsandbox: BLOCKED\nCryptographic signature validity: NOT VERIFIED\nKernel acceptance: NOT VERIFIED\nSandbox policy: NOT VERIFIED\nDynamic-loader startup: NOT VERIFIED\nDevice runtime verified: NO\nExecution activation: DISABLED\nLaunch permission: NOT GRANTED\n",
        prep, plan.device_number, plan.inode, plan.file_size, plan.mode,
        plan.owner_uid, plan.owner_gid, plan.link_count,
        plan.modification_seconds, plan.modification_nanoseconds,
        plan.change_seconds, plan.change_nanoseconds,
        policy_name(plan.policy_outcome),
        plan.policy_reason, plan.required_capabilities, plan.missing_prerequisites,
    );
    if binding {
        let mut summary = std::mem::MaybeUninit::<LaunchSummaryV1>::zeroed();
        let rc =
            unsafe { iu_launch_binding_path_summary_v1(path_c.as_ptr(), summary.as_mut_ptr()) };
        if rc != 0 {
            return Err("launch binding could not verify the same open object".to_owned());
        }
        let summary = unsafe { summary.assume_init() };
        if summary.abi_version != 1
            || summary.struct_size as usize != std::mem::size_of::<LaunchSummaryV1>()
            || summary.device != plan.device_number
            || summary.inode != plan.inode
            || summary.sha256 != plan.sha256
            || summary.operational_authorization != 0
            || summary.boundary_status != 1
        {
            return Err("launch binding identity or ABI mismatch".to_owned());
        }
        let scope = match summary.scope_state {
            1 => "NOT CONFIGURED",
            2 => "MATCH (directory only)",
            _ => "UNVERIFIED",
        };
        let provenance = match summary.provenance_state {
            1 => "EVIDENCE ABSENT",
            2 => "LOCAL DECLARATION ONLY",
            3 => "MALFORMED",
            4 => "IDENTITY MISMATCH",
            5 => "UNTRUSTED",
            6 => "VERIFIED",
            7 => "KNOWN PROTECTED",
            _ => "UNVERIFIED",
        };
        let reason = match summary.decision {
            1 => "POLICY_DISABLED",
            2 => "KNOWN_PROTECTED",
            3 => "PROVENANCE_UNKNOWN",
            4 => "ORIGIN_NOT_AUTHENTICATED",
            5 => "PROVENANCE_IDENTITY_MISMATCH",
            6 => "SCOPE_NOT_CONFIGURED_OR_UNVERIFIED",
            7 => "UNSUPPORTED_ARTIFACT",
            _ => "UNKNOWN",
        };
        use std::fmt::Write;
        let _ = writeln!(report, "Scope match: {scope} (store state={})\nArtifact provenance: {provenance}\nLaunch binding: PREVIEW ONLY; future launch boundary NOT IMPLEMENTED\nLaunch decision: BLOCKED ({reason})\nOperational authorization: FALSE", summary.store_state);
    }
    Ok((report, valid))
}

fn missing_prerequisite_names(mask: u32) -> String {
    const FLAGS: [(u32, &str); 10] = [
        (1, "TRUSTED_BUILD_IDENTITY"),
        (2, "HOOK_RUNTIME_EVIDENCE"),
        (4, "SSH_INTERCEPTION_COVERAGE"),
        (8, "SIGNATURE_PREPARATION"),
        (16, "EXECUTION_ADAPTER"),
        (32, "TRUST_CACHE_VERIFICATION"),
        (64, "KERNEL_ACCEPTANCE"),
        (128, "SANDBOX_OUTCOME"),
        (256, "DYNAMIC_LOADER_STARTUP"),
        (512, "LAUNCH_BOUNDARY_IDENTITY"),
    ];
    FLAGS
        .iter()
        .filter_map(|(flag, name)| (mask & flag != 0).then_some(*name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn policy_name(value: u32) -> &'static str {
    match value {
        0 => "ALLOW_ELIGIBLE (hypothetical P003 outcome)",
        1 => "SKIP_NOT_TARGETED",
        2 => "DENY_DISABLED",
        3 => "DENY_UNVERIFIED_BACKEND",
        4 => "DENY_PROTECTED_PATH",
        5 => "DENY_UNSAFE_FILE",
        6 => "DENY_IDENTITY_MISMATCH",
        7 => "DENY_UNSUPPORTED_TARGET",
        _ => "DENY_INTERNAL_ERROR",
    }
}
