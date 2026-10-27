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
  status                         Show daemon and activation status\n\
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
      --test-socket <path> status  Query an explicitly selected development socket\n";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Help,
    Version,
    Doctor,
    Status(Option<OsString>),
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
        "status" if args.len() == 1 => Ok(Invocation::Status(None)),
        "--test-socket"
            if args.len() == 3 && !args[1].is_empty() && args[2] == OsStr::new("status") =>
        {
            Ok(Invocation::Status(Some(args[1].clone())))
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
        Ok(Invocation::Status(test_socket)) => print_status(test_socket.as_deref()),
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
            println!(
                "IPC: CONNECTED\nIPC protocol: v1\nActivation: {}",
                if status.activation {
                    "ENABLED"
                } else {
                    "DISABLED"
                }
            );
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
            println!("\nDaemon: UNAVAILABLE\nIPC: CONNECTION FAILED\nActivation: UNKNOWN");
            eprintln!("\nError: cannot connect to ios-unsandboxedd ({error}).");
            ExitCode::from(4)
        }
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
