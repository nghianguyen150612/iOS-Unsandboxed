use std::env;
use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "Usage: ios-unsandboxed <command> [arguments]\n\
\n\
Commands:\n\
  doctor                         Check the environment (not implemented)\n\
  status                         Show service status (not implemented)\n\
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
  -V, --version                  Show version\n";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Help,
    Version,
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
        "doctor" if args.len() == 1 => Ok(Invocation::ReservedCommand("doctor")),
        "status" if args.len() == 1 => Ok(Invocation::ReservedCommand("status")),
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

#[cfg(test)]
mod tests {
    use super::{parse_args, Invocation, UsageError};
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
        for command in ["doctor", "status", "enable", "disable", "logs"] {
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
    fn malformed_or_unknown_commands_are_rejected() {
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
