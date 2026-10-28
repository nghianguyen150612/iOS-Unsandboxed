use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::process::ExitCode;

mod ipc;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "Usage: ios-unsandboxed <command> [arguments]\n\
\n\
Commands:\n\
  doctor                         Run read-only compatibility diagnostics\n\
  doctor --amethyst               Inspect the read-only Amethyst adapter contract\n\
  status                         Show daemon lifecycle and activation status\n\
  inspect <binary>               Inspect a Mach-O binary (not implemented)\n\
  sign <binary> [--entitlements <file>]\n\
                                 Prepare a binary for execution (not implemented)\n\
  install <binary>               Install a binary (not implemented)\n\
  enable                         Enable the service (not implemented)\n\
  disable                        Disable the service (not implemented)\n\
  logs                           Show service logs (not implemented)\n\
\n\
Options:\n\
  -h, --help                     Show this help\n\
  -V, --version                  Show version\n\
      --test-socket <path> status  Query an explicitly selected development socket\n\
      --test-socket <path> check   Exercise read-only IPC diagnostics\n";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Help,
    Version,
    Doctor,
    DoctorAmethyst(Option<OsString>),
    Status(Option<OsString>),
    TestCheck(OsString),
    ReservedCommand(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
struct UsageError(&'static str);

fn parse_args(args: &[OsString]) -> Result<Invocation, UsageError> {
    if args.is_empty() {
        return Ok(Invocation::Help);
    }

    if args.len() == 1 {
        match args[0].to_str() {
            Some("--help" | "-h") => return Ok(Invocation::Help),
            Some("--version" | "-V") => return Ok(Invocation::Version),
            _ => {}
        }
    }

    let command = args[0]
        .to_str()
        .ok_or(UsageError("command name must be valid UTF-8"))?;

    match command {
        "doctor" if args.len() == 1 => Ok(Invocation::Doctor),
        "doctor" if args.len() == 2 && args[1] == OsStr::new("--amethyst") => {
            Ok(Invocation::DoctorAmethyst(None))
        }
        "--test-socket"
            if args.len() == 4
                && !args[1].is_empty()
                && args[2] == OsStr::new("doctor")
                && args[3] == OsStr::new("--amethyst") =>
        {
            Ok(Invocation::DoctorAmethyst(Some(args[1].clone())))
        }
        "status" if args.len() == 1 => Ok(Invocation::Status(None)),
        "--test-socket"
            if args.len() == 3 && !args[1].is_empty() && args[2] == OsStr::new("status") =>
        {
            Ok(Invocation::Status(Some(args[1].clone())))
        }
        "--test-socket"
            if args.len() == 3 && !args[1].is_empty() && args[2] == OsStr::new("check") =>
        {
            Ok(Invocation::TestCheck(args[1].clone()))
        }
        "enable" if args.len() == 1 => Ok(Invocation::ReservedCommand("enable")),
        "disable" if args.len() == 1 => Ok(Invocation::ReservedCommand("disable")),
        "logs" if args.len() == 1 => Ok(Invocation::ReservedCommand("logs")),
        "inspect" if args.len() == 2 && !args[1].is_empty() => {
            Ok(Invocation::ReservedCommand("inspect"))
        }
        "install" if args.len() == 2 && !args[1].is_empty() => {
            Ok(Invocation::ReservedCommand("install"))
        }
        "sign" if args.len() == 2 && !args[1].is_empty() => Ok(Invocation::ReservedCommand("sign")),
        "sign"
            if args.len() == 4
                && !args[1].is_empty()
                && args[2] == OsStr::new("--entitlements")
                && !args[3].is_empty() =>
        {
            Ok(Invocation::ReservedCommand("sign"))
        }
        "doctor" | "status" | "inspect" | "sign" | "install" | "enable" | "disable" | "logs" => {
            Err(UsageError("invalid command arguments"))
        }
        _ => Err(UsageError("unknown command or option")),
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();

    match parse_args(&args) {
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("ios-unsandboxed {VERSION}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Doctor) => print_doctor(),
        Ok(Invocation::DoctorAmethyst(socket)) => print_amethyst_doctor(socket.as_deref()),
        Ok(Invocation::Status(test_socket)) => print_status(test_socket.as_deref()),
        Ok(Invocation::TestCheck(path)) => print_test_check(std::path::Path::new(&path)),
        Ok(Invocation::ReservedCommand(command)) => {
            eprintln!(
                "ios-unsandboxed: '{command}' is not implemented in v{VERSION}; no system state was changed."
            );
            ExitCode::from(3)
        }
        Err(error) => {
            eprintln!("ios-unsandboxed: {}", error.0);
            eprintln!("Try 'ios-unsandboxed --help' for usage.");
            ExitCode::from(2)
        }
    }
}

fn print_test_check(path: &std::path::Path) -> ExitCode {
    match ipc::test_socket_check(path) {
        Ok(check) => {
            println!("PING: PASS");
            println!(
                "GET_STATUS: PASS (activation={}, interception={}, device_acceptance={})",
                if check.status.activation {
                    "enabled"
                } else {
                    "disabled"
                },
                if check.status.interception {
                    "implemented"
                } else {
                    "not_implemented"
                },
                if check.status.device_verified {
                    "verified"
                } else {
                    "not_tested"
                }
            );
            println!(
                "GET_PREFLIGHT: PASS (compatibility={} family={} architecture={})",
                check.preflight.compatibility, check.preflight.family, check.preflight.architecture
            );
            if let Some(lifecycle) = check.status.lifecycle {
                println!(
                    "GET_LIFECYCLE_STATUS: PASS (state={}; schema={}; peer_uid={}; peer_gid={})",
                    state_file_status_name(lifecycle.state_file),
                    if lifecycle.schema_supported {
                        lifecycle.schema_version.to_string()
                    } else {
                        "unsupported_or_unknown".to_owned()
                    },
                    lifecycle.peer_uid,
                    lifecycle.peer_gid
                );
            } else {
                println!("GET_LIFECYCLE_STATUS: NOT IMPLEMENTED (P004 daemon)");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ios-unsandboxed: test socket diagnostic failed ({error})");
            ExitCode::from(4)
        }
    }
}

fn print_status(test_socket: Option<&OsStr>) -> ExitCode {
    println!("iOS-Unsandboxed v{VERSION}");
    let result = match test_socket {
        Some(path) => ipc::get_status_test_socket(std::path::Path::new(path)),
        None => ipc::get_status(),
    };
    match result {
        Ok(status) => {
            println!(
                "\nDaemon: {}",
                if status.daemon_running {
                    "RUNNING"
                } else {
                    "UNAVAILABLE"
                }
            );
            println!("IPC: CONNECTED\nIPC protocol: v1");
            println!("LaunchDaemon job state: UNKNOWN (launchd state is not queried)");
            if test_socket.is_some() {
                println!("Daemon executable: NOT CHECKED (test socket)");
                println!("LaunchDaemon plist: NOT CHECKED (test socket)");
            } else {
                println!(
                    "Daemon executable: {}",
                    local_file_presence("/usr/local/bin/ios-unsandboxedd")
                );
                println!(
                    "LaunchDaemon plist: {}",
                    local_file_presence("/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist")
                );
            }
            if let Some(lifecycle) = status.lifecycle {
                println!(
                    "Authenticated peer: uid={} gid={}",
                    lifecycle.peer_uid, lifecycle.peer_gid
                );
                println!(
                    "Installation record: {}",
                    if lifecycle.service_installed {
                        "INSTALLED (root-owned state record)"
                    } else {
                        "NOT RECORDED"
                    }
                );
                println!(
                    "State file: {}",
                    state_file_status_name(lifecycle.state_file)
                );
                println!(
                    "State schema: {}{}",
                    if lifecycle.schema_supported {
                        "SUPPORTED"
                    } else if lifecycle.state_file == ipc::StateFileStatus::UnsupportedSchema {
                        "UNSUPPORTED"
                    } else {
                        "UNKNOWN"
                    },
                    if lifecycle.schema_version != 0 {
                        format!(" (version {})", lifecycle.schema_version)
                    } else {
                        String::new()
                    }
                );
                println!("Activation: DISABLED (P005 has no activation operation)");
            } else {
                println!("Installation record: UNKNOWN (not reported by this daemon)");
                println!("State file: UNKNOWN (not reported by this daemon)");
                println!("State schema: UNKNOWN (not reported by this daemon)");
                println!(
                    "Activation: {} (reported by daemon)",
                    if status.activation {
                        "ENABLED"
                    } else {
                        "DISABLED"
                    }
                );
            }
            println!(
                "Amethyst compatibility: {}",
                match status.compatibility {
                    0 => "SUPPORTED AND VERIFIED",
                    1 => "UNVERIFIED",
                    2 => "COMPONENT MISSING",
                    3 => "VERSION MISMATCH",
                    4 => "UNSUPPORTED PLATFORM",
                    _ => "INTERNAL ERROR",
                }
            );
            println!(
                "Execution interception: {}",
                if status.interception {
                    "IMPLEMENTED"
                } else {
                    "NOT IMPLEMENTED"
                }
            );
            println!(
                "Device acceptance: {}",
                if status.device_verified {
                    "VERIFIED"
                } else {
                    "NOT TESTED"
                }
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("\nDaemon: UNAVAILABLE\nIPC: CONNECTION FAILED");
            println!("LaunchDaemon job state: UNKNOWN (launchd state is not queried)");
            if test_socket.is_some() {
                println!("Daemon executable: NOT CHECKED (test socket)");
                println!("LaunchDaemon plist: NOT CHECKED (test socket)");
            } else {
                println!(
                    "Daemon executable: {}",
                    local_file_presence("/usr/local/bin/ios-unsandboxedd")
                );
                println!(
                    "LaunchDaemon plist: {}",
                    local_file_presence("/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist")
                );
            }
            println!("Installation record: UNKNOWN (IPC unavailable)");
            println!("State file: UNKNOWN (IPC unavailable)");
            println!("State schema: UNKNOWN (IPC unavailable)");
            println!("Activation: UNKNOWN (IPC unavailable)");
            eprintln!("\nError: cannot connect to ios-unsandboxedd ({error}).");
            ExitCode::from(4)
        }
    }
}

fn local_file_presence(path: &str) -> &'static str {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => "PRESENT",
        Ok(_) => "UNSAFE FILE TYPE",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "ABSENT",
        Err(_) => "UNKNOWN",
    }
}

fn state_file_status_name(status: ipc::StateFileStatus) -> &'static str {
    match status {
        ipc::StateFileStatus::DirectoryMissing => "DIRECTORY MISSING",
        ipc::StateFileStatus::FileMissing => "FILE MISSING",
        ipc::StateFileStatus::Valid => "AVAILABLE AND VALID",
        ipc::StateFileStatus::Unsafe => "UNSAFE (not trusted)",
        ipc::StateFileStatus::UnsupportedSchema => "AVAILABLE WITH UNSUPPORTED SCHEMA",
        ipc::StateFileStatus::Corrupt => "CORRUPT (not trusted)",
        ipc::StateFileStatus::IoError => "UNAVAILABLE (I/O error)",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComponentState {
    Missing,
    Regular,
    WrongType,
    MetadataUnavailable,
}

const OS: &str = env::consts::OS;
const ARCH: &str = env::consts::ARCH;

fn inspect_component(path: &str) -> ComponentState {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ComponentState::Missing;
        }
        Err(_) => return ComponentState::MetadataUnavailable,
    };

    if !metadata.file_type().is_file() {
        return ComponentState::WrongType;
    }
    ComponentState::Regular
}

fn compatibility_state(components_ok: bool) -> &'static str {
    if OS != "ios" || ARCH != "aarch64" {
        "UNSUPPORTED_PLATFORM"
    } else if !components_ok {
        "COMPONENT_MISSING"
    } else {
        // std cannot establish the hardware model, exact iOS build, installed
        // Amethyst provenance, or live hook state.
        "UNVERIFIED"
    }
}

fn print_doctor() -> ExitCode {
    let components = [
        (
            "/amethyst/launchd_hook.dylib",
            inspect_component("/amethyst/launchd_hook.dylib"),
        ),
        (
            "/usr/lib/base_hook.dylib",
            inspect_component("/usr/lib/base_hook.dylib"),
        ),
    ];
    let components_ok = components
        .iter()
        .all(|(_, state)| *state == ComponentState::Regular);
    let compatibility = compatibility_state(components_ok);

    println!("iOS-Unsandboxed read-only preflight");
    println!("Project version: {VERSION}");
    println!("Detected platform: {OS}");
    println!("Architecture: {ARCH}");
    println!("Machine: UNKNOWN (requires native device probe)");
    println!("Product version: UNKNOWN (requires native device probe)");
    println!("System build: UNKNOWN (requires native device probe)");

    let layout_paths = [
        "/usr/local/bin",
        "/usr/local/lib",
        "/var/lib",
        "/var/run",
        "/var/log",
        "/Library/LaunchDaemons",
    ];
    if OS == "ios" {
        let available = layout_paths
            .iter()
            .filter(|path| fs::metadata(path).is_ok_and(|metadata| metadata.is_dir()))
            .count();
        println!("Rootful layout assessment: WARN — {available}/{} contract directories available; rootful status is not proven", layout_paths.len());
    } else {
        println!("Rootful layout assessment: UNKNOWN — diagnostics are running outside iOS");
    }

    println!("Amethyst component detection:");
    for (path, state) in components {
        let status = match state {
            ComponentState::Missing => "FAIL: missing",
            ComponentState::Regular => "WARN: regular file; read access not checked by Rust probe",
            ComponentState::WrongType => "FAIL: unexpected file type",
            ComponentState::MetadataUnavailable => "UNKNOWN: metadata access unavailable",
        };
        println!("  {path}: {status}");
    }
    println!("Amethyst compatibility verification: {compatibility}");
    if compatibility == "UNVERIFIED" {
        println!("  WARN: exact device/version, installed Amethyst build, and live hook state are unknown");
    }

    println!("Daemon IPC connectivity:");
    match ipc::ping() {
        Ok(()) => {
            println!("  connection: PASS — compatible daemon responded to PING");
            match ipc::get_preflight() {
                Ok(result) => println!("  daemon preflight: compatibility={} family={} architecture={} device_match={} os_match={}", result.compatibility, result.family, result.architecture, result.device_match, result.os_match),
                Err(error) => println!("  daemon preflight: unavailable ({error})"),
            }
        }
        Err(_) => println!(
            "  connection: UNAVAILABLE — local diagnostics remain independent of daemon IPC"
        ),
    }

    let project_paths = [
        "/usr/local/bin/ios-unsandboxed",
        "/usr/local/bin/ios-unsandboxedd",
        "/usr/local/bin/iu",
        "/var/lib/ios-unsandboxed",
        "/var/lib/ios-unsandboxed/manager.sh",
        "/var/lib/ios-unsandboxed/install-state",
        "/usr/local/lib/ios-unsandboxed",
        "/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist",
        "/var/run/ios-unsandboxedd.sock",
        "/var/log/ios-unsandboxed",
    ];
    let project_paths_present = project_paths
        .iter()
        .filter(|path| fs::symlink_metadata(path).is_ok())
        .count();
    println!(
        "Project rootful paths: {project_paths_present}/{} present (metadata only)",
        project_paths.len()
    );

    println!("Current preflight capability: PASS — read-only diagnostics only");
    println!("Activation eligibility: FAIL — preflight is not verified and activation is not implemented");
    println!(
        "Remaining requirements: exact installed Amethyst provenance, authenticated daemon policy,"
    );
    println!("  live hook checks, and file identity preservation through the final launch gate.");
    println!("Device acceptance: NOT TESTED");
    println!("Diagnostic collection: PASS");

    if compatibility == "SUPPORTED_AND_VERIFIED" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

fn print_amethyst_doctor(test_socket: Option<&OsStr>) -> ExitCode {
    const PIN: &str = "61ce86d7d3f00e5395f4d42bebda0e5dce04946a";
    let adapter = match test_socket {
        Some(path) => ipc::get_amethyst_adapter_test_socket(std::path::Path::new(path)),
        None => ipc::get_amethyst_adapter(),
    };
    println!("iOS-Unsandboxed Amethyst Adapter v1");
    println!("Source revision: {PIN} (audited source provenance)");
    println!("Installed Amethyst build: UNVERIFIED");
    println!("Launchd hook: UNVERIFIED");
    println!("Base hook: UNVERIFIED");
    println!("SSH exec interception: NOT TESTED");
    println!("Fully unsigned Mach-O support: BLOCKED");
    println!("Execution activation: DISABLED");
    match adapter {
        Ok(status) => {
            println!(
                "Adapter compatibility: {}",
                match status.compatibility {
                    0 => "SUPPORTED_AND_VERIFIED",
                    1 => "SOURCE_REVISION_KNOWN",
                    2 => "INSTALLED_BUILD_UNVERIFIED",
                    3 => "COMPONENT_MISSING",
                    4 => "VERSION_MISMATCH",
                    5 => "UNSUPPORTED_PLATFORM",
                    6 => "HOOK_STATE_UNVERIFIED",
                    7 => "ABI_INCOMPATIBLE",
                    _ => "INTERNAL_ERROR",
                }
            );
            println!(
                "Launchd component: {}",
                component_status_name(status.launchd_component)
            );
            println!(
                "Base component: {}",
                component_status_name(status.base_component)
            );
            println!(
                "Build evidence: {}",
                build_evidence_name(status.build_evidence)
            );
            println!(
                "Launchd hook evidence: {}",
                hook_evidence_name(status.launchd_hook_evidence)
            );
            println!(
                "Base hook evidence: {}",
                hook_evidence_name(status.base_hook_evidence)
            );
            println!("Daemon probe: AVAILABLE (read-only IPC v1)");
            println!("Source pin returned by daemon: {}", status.source_revision);
        }
        Err(_) => {
            println!("Adapter compatibility: UNKNOWN (daemon unavailable)");
            println!("Launchd component: UNKNOWN (daemon unavailable)");
            println!("Base component: UNKNOWN (daemon unavailable)");
            println!("Daemon probe: UNAVAILABLE; local diagnostics remain usable");
        }
    }
    println!("Device runtime validation: NOT RUN");
    ExitCode::SUCCESS
}

fn component_status_name(state: u32) -> &'static str {
    match state {
        0 => "MISSING",
        1 => "REGULAR FILE (presence only)",
        2 => "SYMLINK REJECTED",
        3 => "UNEXPECTED FILE TYPE",
        4 => "UNREADABLE",
        5 => "UNSAFE OR UNTRUSTED",
        _ => "UNKNOWN",
    }
}

fn build_evidence_name(state: u32) -> &'static str {
    match state {
        0 => "UNKNOWN",
        1 => "PACKAGE VERSION REPORTED (binary build unverified)",
        2 => "TRUSTED HASH MATCH (source/build compatibility still unverified)",
        3 => "BUILD VERSION MISMATCH",
        _ => "INVALID",
    }
}

fn hook_evidence_name(state: u32) -> &'static str {
    match state {
        0 => "UNKNOWN",
        1 => "REPORTED PRESENT (runtime activation unverified)",
        2 => "INDEPENDENT DEVICE EVIDENCE",
        _ => "INVALID",
    }
}

#[cfg(test)]
mod tests {
    use super::{compatibility_state, parse_args, Invocation, UsageError};
    use std::ffi::OsString;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn help_and_version_are_recognized() {
        assert_eq!(parse_args(&args(&[])), Ok(Invocation::Help));
        assert_eq!(parse_args(&args(&["--help"])), Ok(Invocation::Help));
        assert_eq!(parse_args(&args(&["-h"])), Ok(Invocation::Help));
        assert_eq!(parse_args(&args(&["--version"])), Ok(Invocation::Version));
        assert_eq!(parse_args(&args(&["-V"])), Ok(Invocation::Version));
    }

    #[test]
    fn reserved_commands_accept_the_documented_shapes() {
        assert_eq!(parse_args(&args(&["status"])), Ok(Invocation::Status(None)));
        assert_eq!(
            parse_args(&args(&["--test-socket", "/tmp/iu.sock", "status"])),
            Ok(Invocation::Status(Some(OsString::from("/tmp/iu.sock"))))
        );
        assert_eq!(
            parse_args(&args(&["--test-socket", "/tmp/iu.sock", "check"])),
            Ok(Invocation::TestCheck(OsString::from("/tmp/iu.sock")))
        );
        for command in ["enable", "disable", "logs"] {
            assert_eq!(
                parse_args(&args(&[command])),
                Ok(Invocation::ReservedCommand(command))
            );
        }
        assert_eq!(
            parse_args(&args(&["inspect", "./binary"])),
            Ok(Invocation::ReservedCommand("inspect"))
        );
        assert_eq!(
            parse_args(&args(&["install", "./binary"])),
            Ok(Invocation::ReservedCommand("install"))
        );
        assert_eq!(
            parse_args(&args(&["sign", "./binary"])),
            Ok(Invocation::ReservedCommand("sign"))
        );
        assert_eq!(
            parse_args(&args(&[
                "sign",
                "./binary",
                "--entitlements",
                "./entitlements.plist"
            ])),
            Ok(Invocation::ReservedCommand("sign"))
        );
    }

    #[test]
    fn doctor_is_diagnostic_and_never_claims_unverified_compatibility() {
        assert_eq!(parse_args(&args(&["doctor"])), Ok(Invocation::Doctor));
        assert_eq!(
            parse_args(&args(&["doctor", "--amethyst"])),
            Ok(Invocation::DoctorAmethyst(None))
        );
        assert_eq!(
            parse_args(&args(&[
                "--test-socket",
                "/tmp/iu.sock",
                "doctor",
                "--amethyst"
            ])),
            Ok(Invocation::DoctorAmethyst(Some(OsString::from(
                "/tmp/iu.sock"
            ))))
        );
        assert_ne!(compatibility_state(true), "SUPPORTED_AND_VERIFIED");
    }

    #[test]
    fn malformed_or_unknown_commands_are_rejected() {
        assert_eq!(
            parse_args(&args(&["doctor", "--activate"])),
            Err(UsageError("invalid command arguments"))
        );
        assert_eq!(
            parse_args(&args(&["enable", "now"])),
            Err(UsageError("invalid command arguments"))
        );
        assert_eq!(
            parse_args(&args(&["sign", "./binary", "--entitlements"])),
            Err(UsageError("invalid command arguments"))
        );
        assert_eq!(
            parse_args(&args(&["unknown"])),
            Err(UsageError("unknown command or option"))
        );
    }
}
