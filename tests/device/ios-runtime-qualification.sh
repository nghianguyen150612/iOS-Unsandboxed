#!/bin/sh
# P006 read-only device inventory and explicit temporary IPC qualification.
# This script never invokes production --serve or changes Amethyst/system paths.

set -u

PROGRAM=${0##*/}
ROOT_PREFIX=/
RUNTIME_TEST=0
CLI_BINARY=
DAEMON_BINARY=
OBS_VALUE=
OBS_STATUS=1
RUNTIME_DIR=
RUNTIME_SOCKET=
DAEMON_PID=
RUNTIME_RESULT=PASS
UNAME_SYSTEM=unknown

usage() {
    printf '%s\n' \
        "Usage: $PROGRAM [--root FIXTURE_ROOT] [--runtime-test --cli PATH --daemon PATH]" \
        '' \
        'Default mode performs read-only device and path inventory.' \
        '--runtime-test explicitly runs the supplied binaries on a private test socket.' \
        '--root is for isolated host fixtures only; it disables runtime testing.'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --root)
            if [ "$#" -lt 2 ]; then
                printf '%s: --root requires a directory\n' "$PROGRAM" >&2
                exit 2
            fi
            ROOT_PREFIX=$2
            shift 2
            ;;
        --runtime-test)
            RUNTIME_TEST=1
            shift
            ;;
        --cli)
            if [ "$#" -lt 2 ]; then
                printf '%s: --cli requires an explicit binary path\n' "$PROGRAM" >&2
                exit 2
            fi
            CLI_BINARY=$2
            shift 2
            ;;
        --daemon)
            if [ "$#" -lt 2 ]; then
                printf '%s: --daemon requires an explicit binary path\n' "$PROGRAM" >&2
                exit 2
            fi
            DAEMON_BINARY=$2
            shift 2
            ;;
        *)
            printf '%s: unknown option: %s\n' "$PROGRAM" "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$ROOT_PREFIX" in
    /*) ;;
    *) printf '%s: --root must be an absolute directory path\n' "$PROGRAM" >&2; exit 2 ;;
esac

if [ "$RUNTIME_TEST" -eq 1 ]; then
    if [ "$ROOT_PREFIX" != / ]; then
        printf '%s: --runtime-test cannot be combined with --root\n' "$PROGRAM" >&2
        exit 2
    fi
    if [ -z "$CLI_BINARY" ] || [ -z "$DAEMON_BINARY" ]; then
        printf '%s: --runtime-test requires explicit --cli and --daemon paths\n' "$PROGRAM" >&2
        exit 2
    fi
elif [ -n "$CLI_BINARY" ] || [ -n "$DAEMON_BINARY" ]; then
    printf '%s: --cli and --daemon are accepted only with --runtime-test\n' "$PROGRAM" >&2
    exit 2
fi

if [ ! -d "$ROOT_PREFIX" ]; then
    printf '%s: root directory does not exist: %s\n' "$PROGRAM" "$ROOT_PREFIX" >&2
    exit 2
fi

if [ "$ROOT_PREFIX" = / ]; then
    FIXTURE_MODE=0
else
    FIXTURE_MODE=1
fi

root_path() {
    case "$ROOT_PREFIX" in
        /) printf '/%s' "$1" ;;
        *) printf '%s/%s' "${ROOT_PREFIX%/}" "$1" ;;
    esac
}

command_available() {
    command -v "$1" >/dev/null 2>&1
}

observe() {
    OBS_LABEL=$1
    shift
    OBS_VALUE=
    OBS_STATUS=127
    if ! command_available "$1"; then
        printf 'MISSING_COMMAND: %s (needed for %s)\n' "$1" "$OBS_LABEL"
        return 127
    fi
    OBS_VALUE=$("$@" 2>&1)
    OBS_STATUS=$?
    if [ "$OBS_STATUS" -eq 0 ]; then
        printf 'OBSERVED %s: %s\n' "$OBS_LABEL" "$OBS_VALUE"
    else
        printf 'OBSERVED %s: unavailable (exit=%s; output=%s)\n' \
            "$OBS_LABEL" "$OBS_STATUS" "$OBS_VALUE"
    fi
    return "$OBS_STATUS"
}

print_file_lines() {
    while IFS= read -r PRINT_LINE || [ -n "$PRINT_LINE" ]; do
        printf '  %s\n' "$PRINT_LINE"
    done < "$1"
}

stat_line() {
    STAT_OUTPUT=
    STAT_STATUS=127
    if ! command_available stat; then
        printf 'MISSING_COMMAND: stat (numeric ownership and mode metadata)\n'
        return 127
    fi
    case "$UNAME_SYSTEM" in
        Darwin|FreeBSD|OpenBSD|NetBSD|DragonFly)
            STAT_OUTPUT=$(stat -f 'uid=%u gid=%g mode=%Lp type=%HT size=%z links=%l' "$1" 2>/dev/null)
            STAT_STATUS=$?
            ;;
        *)
            STAT_OUTPUT=$(stat -c 'uid=%u gid=%g mode=%a type=%F size=%s links=%h' "$1" 2>/dev/null)
            STAT_STATUS=$?
            ;;
    esac
    if [ "$STAT_STATUS" -eq 0 ] && [ -n "$STAT_OUTPUT" ]; then
        printf 'STAT_METADATA: %s\n' "$STAT_OUTPUT"
    else
        printf 'STAT_METADATA: unavailable (stat syntax unsupported on this system)\n'
    fi
    return "$STAT_STATUS"
}

hash_file() {
    HASH_PATH=$1
    if command_available shasum; then
        printf 'SHA256_COMMAND: shasum -a 256 %s\n' "$HASH_PATH"
        shasum -a 256 "$HASH_PATH" 2>&1
    elif command_available sha256sum; then
        printf 'SHA256_COMMAND: sha256sum %s\n' "$HASH_PATH"
        sha256sum "$HASH_PATH" 2>&1
    elif command_available openssl; then
        printf 'SHA256_COMMAND: openssl dgst -sha256 %s\n' "$HASH_PATH"
        openssl dgst -sha256 "$HASH_PATH" 2>&1
    else
        printf 'MISSING_COMMAND: shasum, sha256sum, or openssl (no SHA-256 tool available)\n'
        return 127
    fi
}

report_tool() {
    TOOL_LABEL=$1
    shift
    if command_available "$1"; then
        printf '%s\n' "$TOOL_LABEL"
        printf 'COMMAND:'
        for TOOL_ARG do printf ' <%s>' "$TOOL_ARG"; done
        printf '\n'
        "$@" 2>&1
        TOOL_STATUS=$?
        printf 'COMMAND_EXIT_STATUS: %s\n' "$TOOL_STATUS"
        return 0
    fi
    printf 'MISSING_COMMAND: %s (needed for %s)\n' "$1" "$TOOL_LABEL"
    return 127
}

inspect_binary_metadata() {
    META_PATH=$1
    if command_available file; then
        report_tool 'FILE_FORMAT (classification only)' file "$META_PATH"
    else
        printf 'MISSING_COMMAND: file (Mach-O/architecture classification)\n'
    fi

    if command_available otool; then
        report_tool 'MACH_O_HEADER (architecture and file type)' otool -hv "$META_PATH"
        report_tool 'MACH_O_DEPENDENCIES (dynamic loader dependencies)' otool -L "$META_PATH"
        report_tool 'MACH_O_LOAD_COMMANDS (deployment target, UUID, signature command)' \
            otool -l "$META_PATH"
    else
        printf 'MISSING_COMMAND: otool (Mach-O headers, load commands, and dependencies)\n'
    fi

    if command_available codesign; then
        printf '%s\n' 'CODESIGN_DISPLAY (metadata only; does not establish trust or startup):'
        report_tool 'CODESIGN_METADATA' codesign -dv --verbose=4 "$META_PATH"
        printf '%s\n' 'CODESIGN_VERIFY (host signature validity only; does not establish Amethyst trust):'
        report_tool 'CODESIGN_VALIDATION' codesign --verify --strict --verbose=2 "$META_PATH"
    else
        printf 'MISSING_COMMAND: codesign (signature metadata/host validation)\n'
    fi
}

inspect_path() {
    PATH_LABEL=$1
    PATH_RELATIVE=$2
    PATH_HASH=${3:-no}
    PATH_BINARY=${4:-no}
    PATH_VALUE=$(root_path "$PATH_RELATIVE")
    PATH_KIND=missing

    if [ -L "$PATH_VALUE" ]; then
        PATH_KIND=symlink
    elif [ -f "$PATH_VALUE" ]; then
        PATH_KIND=regular-file
    elif [ -d "$PATH_VALUE" ]; then
        PATH_KIND=directory
    elif [ -e "$PATH_VALUE" ]; then
        PATH_KIND=other
    fi

    printf '\nPATH: %s\n' "$PATH_LABEL"
    printf 'PATH_VALUE: %s\n' "$PATH_VALUE"
    printf 'OBSERVED_FILE_TYPE: %s\n' "$PATH_KIND"

    if command_available ls; then
        ls -ld "$PATH_VALUE" 2>&1
    else
        printf 'MISSING_COMMAND: ls (path ownership, mode, and type listing)\n'
    fi
    if [ "$PATH_KIND" != missing ]; then
        stat_line "$PATH_VALUE" || :
    fi

    case "$PATH_KIND" in
        regular-file)
            if [ "$PATH_HASH" = yes ]; then hash_file "$PATH_VALUE" || :; fi
            if [ "$PATH_BINARY" = yes ]; then inspect_binary_metadata "$PATH_VALUE"; fi
            ;;
        missing)
            printf 'PATH_RESULT: absent (future installation target unless independently present)\n'
            ;;
        symlink)
            printf '%s\n' 'HASH_RESULT: not hashed as a binary; path is a symlink.'
            ;;
        *)
            printf '%s\n' 'HASH_RESULT: not applicable; path is not a regular file.'
            ;;
    esac

    case "$PATH_RELATIVE" in
        Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist)
            if [ "$PATH_KIND" = regular-file ]; then
                if command_available plutil; then
                    report_tool 'PLIST_PARSE (syntax only; not launchd runtime evidence)' \
                        plutil -lint "$PATH_VALUE"
                else
                    printf 'MISSING_COMMAND: plutil (plist syntax inspection)\n'
                fi
            fi
            ;;
    esac
}

query_amethyst_package() {
    printf '\nAMETHYST_PACKAGE_EVIDENCE (audited source identifier only; absence is not device failure proof):\n'
    if command_available dpkg-query; then
        report_tool 'PACKAGE_VERSION com.staturnz.tnsv2-updater' \
            dpkg-query -W '-f=${Package} ${Version} ${Architecture}\n' com.staturnz.tnsv2-updater
        report_tool 'PACKAGE_OWNER /amethyst/launchd_hook.dylib' \
            dpkg-query -S /amethyst/launchd_hook.dylib
        report_tool 'PACKAGE_OWNER /usr/lib/base_hook.dylib' \
            dpkg-query -S /usr/lib/base_hook.dylib
    elif command_available dpkg; then
        report_tool 'PACKAGE_VERSION com.staturnz.tnsv2-updater' \
            dpkg -s com.staturnz.tnsv2-updater
        report_tool 'PACKAGE_OWNER /amethyst/launchd_hook.dylib' \
            dpkg -S /amethyst/launchd_hook.dylib
        report_tool 'PACKAGE_OWNER /usr/lib/base_hook.dylib' \
            dpkg -S /usr/lib/base_hook.dylib
    else
        printf 'MISSING_COMMAND: dpkg-query or dpkg (narrow Amethyst package evidence)\n'
    fi
    printf '%s\n' 'PACKAGE_PROVENANCE_LIMIT: a package name/version or file ownership record does not identify installed binary bytes.'
}

report_launchd() {
    printf '\nLAUNCHD_READ_ONLY_INSPECTION:\n'
    if command_available launchctl; then
        report_tool 'LAUNCHD_JOB_QUERY (read-only; no load/bootstrap/kickstart)' \
            launchctl list com.ios-unsandboxed.daemon
    else
        printf 'MISSING_COMMAND: launchctl (read-only project job query)\n'
    fi
    printf '%s\n' 'LAUNCHD_ACTIVATION: not attempted.'
}

report_environment_facts() {
    printf '\nENVIRONMENT_FACTS (values that can contain user data are omitted):\n'
    if [ -n "${PATH-}" ]; then
        case ":$PATH:" in
            *:/usr/local/bin:*) printf '%s\n' 'PATH: set; contains /usr/local/bin' ;;
            *) printf '%s\n' 'PATH: set; does not contain /usr/local/bin' ;;
        esac
    else
        printf '%s\n' 'PATH: unset'
    fi
    for ENV_NAME in TMPDIR SHELL LANG SSH_CONNECTION SSH_CLIENT; do
        eval 'ENV_SET=${'"$ENV_NAME"'+set}'
        if [ "${ENV_SET-}" = set ]; then
            printf 'ENVIRONMENT_VARIABLE: %s=set (value omitted)\n' "$ENV_NAME"
        else
            printf 'ENVIRONMENT_VARIABLE: %s=unset\n' "$ENV_NAME"
        fi
    done
}

report_host_facts() {
    printf '%s\n' 'DEVICE_AND_PROCESS_FACTS (observed command output):'
    observe 'kernel name' uname -s || :
    if [ "$OBS_STATUS" -eq 0 ]; then UNAME_SYSTEM=$OBS_VALUE; else UNAME_SYSTEM=unknown; fi
    observe 'kernel release' uname -r || :
    observe 'kernel build string' uname -v || :
    observe 'kernel architecture' uname -m || :
    if [ "$OBS_STATUS" -eq 0 ]; then KERNEL_ARCH=$OBS_VALUE; else KERNEL_ARCH=; fi

    observe 'effective UID' id -u || :
    if [ "$OBS_STATUS" -eq 0 ]; then EFFECTIVE_UID=$OBS_VALUE; else EFFECTIVE_UID=; fi
    observe 'effective GID' id -g || :
    if [ "$OBS_STATUS" -eq 0 ]; then EFFECTIVE_GID=$OBS_VALUE; else EFFECTIVE_GID=; fi
    observe 'root account UID' id -u root || :
    if [ "$OBS_STATUS" -eq 0 ]; then ROOT_UID=$OBS_VALUE; else ROOT_UID=; fi
    observe 'wheel group GID' id -g wheel || :
    if [ "$OBS_STATUS" -eq 0 ]; then WHEEL_GID=$OBS_VALUE; else WHEEL_GID=; fi

    observe 'hardware machine identifier' sysctl -n hw.machine || :
    if [ "$OBS_STATUS" -eq 0 ]; then HW_MACHINE=$OBS_VALUE; else HW_MACHINE=; fi
    observe 'hardware model identifier' sysctl -n hw.model || :
    if [ "$OBS_STATUS" -eq 0 ]; then HW_MODEL=$OBS_VALUE; else HW_MODEL=; fi
    observe 'OS product version' sw_vers -productVersion || :
    if [ "$OBS_STATUS" -eq 0 ]; then PRODUCT_VERSION=$OBS_VALUE; else PRODUCT_VERSION=; fi
    observe 'OS build identifier' sysctl -n kern.osversion || :
    SYSTEM_BUILD=$OBS_VALUE
    observe 'kernel release sysctl' sysctl -n kern.osrelease || :

    observe 'device clock UTC (device clock is not externally validated)' date -u '+%Y-%m-%dT%H:%M:%SZ' || :
    report_environment_facts

    if [ "$FIXTURE_MODE" -eq 1 ]; then
        printf '%s\n' 'FIXTURE_MODE: host filesystem fixture; host identity facts above are not device evidence.'
        return
    fi

    if [ "$HW_MACHINE" = iPad4,4 ] && [ "$KERNEL_ARCH" = arm64 ] &&
        [ "$PRODUCT_VERSION" = 12.5.7 ]; then
        printf '%s\n' 'REFERENCE_DEVICE_AND_OS_MATCH: PASS (observed identifiers match the declared target profile).'
    elif [ -n "$HW_MACHINE" ] && [ -n "$KERNEL_ARCH" ] && [ -n "$PRODUCT_VERSION" ]; then
        printf '%s\n' 'REFERENCE_DEVICE_AND_OS_MATCH: FAIL (one or more observed identifiers differ from the declared target profile).'
    else
        printf '%s\n' 'REFERENCE_DEVICE_AND_OS_MATCH: BLOCKED (required identifiers were unavailable).'
    fi

    if [ "$ROOT_UID" = 0 ] && [ "$WHEEL_GID" = 0 ]; then
        printf '%s\n' 'ROOT_AND_WHEEL_ID_ASSUMPTIONS: PASS (root UID and wheel GID are both 0).'
    elif [ -n "$ROOT_UID" ] && [ -n "$WHEEL_GID" ]; then
        printf '%s\n' 'ROOT_AND_WHEEL_ID_ASSUMPTIONS: FAIL (observed numeric IDs differ from 0).'
    else
        printf '%s\n' 'ROOT_AND_WHEEL_ID_ASSUMPTIONS: BLOCKED (account/group identifiers unavailable).'
    fi

    if [ "$EFFECTIVE_UID" = 0 ]; then
        printf '%s\n' 'SOCKET_ACCESS_MODEL: current session is root; mode 0600 on a root-owned socket permits this identity.'
    elif [ -n "$EFFECTIVE_UID" ]; then
        printf '%s\n' 'SOCKET_ACCESS_MODEL: current session is non-root; production mode 0600 is expected to deny pathname access.'
    else
        printf '%s\n' 'SOCKET_ACCESS_MODEL: BLOCKED (effective UID unavailable).'
    fi
}

report_runtime_path_inventory() {
    printf '\nROOTFUL_PATH_INVENTORY (missing paths are reported; none are created):\n'
    inspect_path 'canonical CLI' usr/local/bin/ios-unsandboxed yes yes
    inspect_path 'canonical daemon' usr/local/bin/ios-unsandboxedd yes yes
    inspect_path 'canonical iu alias' usr/local/bin/iu
    inspect_path 'project data directory' var/lib/ios-unsandboxed
    inspect_path 'persistent install-state' var/lib/ios-unsandboxed/install-state
    inspect_path 'manager script' var/lib/ios-unsandboxed/manager.sh
    inspect_path 'project native library directory' usr/local/lib/ios-unsandboxed
    inspect_path 'passive LaunchDaemon plist' Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist
    inspect_path 'production socket' var/run/ios-unsandboxedd.sock
    inspect_path 'project log directory' var/log/ios-unsandboxed
    inspect_path 'Amethyst launchd hook candidate' amethyst/launchd_hook.dylib yes yes
    inspect_path 'Amethyst base hook candidate' usr/lib/base_hook.dylib yes yes
    inspect_path 'Amethyst version marker' amethyst/.version
}

contains_text() {
    NEEDLE=$1
    SEARCH_FILE=$2
    while IFS= read -r SEARCH_LINE || [ -n "$SEARCH_LINE" ]; do
        case "$SEARCH_LINE" in
            *"$NEEDLE"*) return 0 ;;
        esac
    done < "$SEARCH_FILE"
    return 1
}

runtime_cleanup() {
    trap - 0 HUP INT TERM
    if [ -n "$DAEMON_PID" ]; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || :
        wait "$DAEMON_PID" 2>/dev/null || :
        DAEMON_PID=
    fi
    if [ -n "$RUNTIME_DIR" ] && [ -d "$RUNTIME_DIR" ]; then
        if [ -n "$RUNTIME_SOCKET" ]; then
            rm -f "$RUNTIME_SOCKET"
        fi
        rm -f "$RUNTIME_DIR/daemon.stdout" "$RUNTIME_DIR/daemon.stderr" \
            "$RUNTIME_DIR/cli.version" "$RUNTIME_DIR/daemon.version" \
            "$RUNTIME_DIR/daemon.probe" "$RUNTIME_DIR/cli.check" \
            "$RUNTIME_DIR/cli.status"
        if rmdir "$RUNTIME_DIR" 2>/dev/null; then
            printf '%s\n' 'TEMP_DIRECTORY_CLEANUP: PASS (only the isolated P006 directory was removed).'
        else
            printf 'TEMP_DIRECTORY_CLEANUP: FAIL (isolated directory remains for inspection: %s)\n' "$RUNTIME_DIR"
            RUNTIME_RESULT=FAIL
        fi
        RUNTIME_DIR=
    fi
}

on_runtime_signal() {
    SIGNAL_STATUS=$1
    printf 'RUNTIME_SIGNAL: received %s; requesting daemon SIGTERM before cleanup.\n' "$SIGNAL_STATUS"
    exit "$SIGNAL_STATUS"
}

record_run() {
    RUN_LABEL=$1
    RUN_LOG=$2
    shift 2
    printf 'COMMAND: '
    for RUN_ARG do printf ' <%s>' "$RUN_ARG"; done
    printf '\n'
    "$@" > "$RUN_LOG" 2>&1
    RUN_STATUS=$?
    printf 'EXIT_STATUS: %s\n' "$RUN_STATUS"
    if [ "$RUN_STATUS" -ge 128 ]; then
        RUN_SIGNAL=$((RUN_STATUS - 128))
        printf 'SIGNAL_HINT: shell exit status convention suggests signal %s; verify output and do not infer cause.\n' "$RUN_SIGNAL"
    fi
    print_file_lines "$RUN_LOG"
    return "$RUN_STATUS"
}

run_runtime_test() {
    printf '\nTEMPORARY_IPC_TEST: explicitly enabled; project binaries are used only from the supplied paths.\n'
    printf '%s\n' 'PRODUCTION_PATHS: not used; launchd and management operations are not invoked.'

    for REQUIRED_COMMAND in mktemp chmod rm rmdir sleep; do
        if ! command_available "$REQUIRED_COMMAND"; then
            printf 'MISSING_COMMAND: %s (temporary IPC test cannot run safely)\n' "$REQUIRED_COMMAND"
            printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED'
            return 0
        fi
    done
    if [ ! -f "$CLI_BINARY" ] || [ ! -x "$CLI_BINARY" ]; then
        printf 'CLI_BINARY: BLOCKED (not a regular executable at the explicit path %s)\n' "$CLI_BINARY"
        printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED'
        return 0
    fi
    if [ ! -f "$DAEMON_BINARY" ] || [ ! -x "$DAEMON_BINARY" ]; then
        printf 'DAEMON_BINARY: BLOCKED (not a regular executable at the explicit path %s)\n' "$DAEMON_BINARY"
        printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED'
        return 0
    fi

    RUNTIME_DIR=$(mktemp -d /tmp/ios-unsandboxed-p006.XXXXXX 2>/dev/null)
    case "$RUNTIME_DIR" in
        /tmp/ios-unsandboxed-p006.*) ;;
        *) printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED (mktemp returned a path outside the P006-owned prefix).'; RUNTIME_DIR=; return 0 ;;
    esac
    if [ -z "$RUNTIME_DIR" ] || [ ! -d "$RUNTIME_DIR" ] || [ -L "$RUNTIME_DIR" ]; then
        printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED (mktemp did not produce a new isolated directory).'
        RUNTIME_DIR=
        return 0
    fi
    RUNTIME_SOCKET=$RUNTIME_DIR/daemon.sock
    trap 'runtime_cleanup' 0
    trap 'on_runtime_signal 129' HUP
    trap 'on_runtime_signal 130' INT
    trap 'on_runtime_signal 143' TERM
    if ! chmod 700 "$RUNTIME_DIR"; then
        printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED (could not set temporary directory mode 0700).'
        runtime_cleanup
        return 0
    fi

    observe 'runtime test UID' id -u || :
    if [ "$OBS_STATUS" -eq 0 ]; then RUNTIME_UID=$OBS_VALUE; else RUNTIME_UID=; fi
    observe 'runtime test GID' id -g || :
    if [ "$OBS_STATUS" -eq 0 ]; then RUNTIME_GID=$OBS_VALUE; else RUNTIME_GID=; fi

    if hash_file "$CLI_BINARY"; then :; else printf '%s\n' 'CLI_BINARY_SHA256: unavailable'; fi
    if hash_file "$DAEMON_BINARY"; then :; else printf '%s\n' 'DAEMON_BINARY_SHA256: unavailable'; fi
    inspect_binary_metadata "$CLI_BINARY"
    inspect_binary_metadata "$DAEMON_BINARY"

    if record_run 'CLI version' "$RUNTIME_DIR/cli.version" "$CLI_BINARY" --version; then
        CLI_VERSION_STATUS=0
    else
        CLI_VERSION_STATUS=$?
    fi
    if contains_text 'ios-unsandboxed 0.1.0' "$RUNTIME_DIR/cli.version"; then
        if [ "$CLI_VERSION_STATUS" -eq 0 ]; then
            printf '%s\n' 'CLI_STARTUP: PASS (version output proves normal program entry).'
        else
            printf 'CLI_STARTUP: FAIL (normal program entry observed, but exit status was %s).\n' "$CLI_VERSION_STATUS"
            RUNTIME_RESULT=FAIL
        fi
    else
        printf 'CLI_STARTUP: FAIL (normal program entry was not observed; exit status was %s; cause is unclassified).\n' "$CLI_VERSION_STATUS"
        RUNTIME_RESULT=FAIL
    fi

    if record_run 'daemon version' "$RUNTIME_DIR/daemon.version" "$DAEMON_BINARY" --version; then
        DAEMON_VERSION_STATUS=0
    else
        DAEMON_VERSION_STATUS=$?
    fi
    if contains_text 'ios-unsandboxedd 0.1.0' "$RUNTIME_DIR/daemon.version"; then
        if [ "$DAEMON_VERSION_STATUS" -eq 0 ]; then
            printf '%s\n' 'DAEMON_STARTUP: PASS (version output proves normal program entry).'
        else
            printf 'DAEMON_STARTUP: FAIL (normal program entry observed, but exit status was %s).\n' "$DAEMON_VERSION_STATUS"
            RUNTIME_RESULT=FAIL
        fi
    else
        printf 'DAEMON_STARTUP: FAIL (normal program entry was not observed; exit status was %s; cause is unclassified).\n' "$DAEMON_VERSION_STATUS"
        RUNTIME_RESULT=FAIL
    fi

    if [ "$RUNTIME_RESULT" != PASS ]; then
        runtime_cleanup
        printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED (one or both diagnostic executables did not start normally).'
        return 0
    fi

    if record_run 'daemon read-only preflight' "$RUNTIME_DIR/daemon.probe" \
        "$DAEMON_BINARY" --probe; then
        PROBE_STATUS=0
    else
        PROBE_STATUS=$?
    fi
    if contains_text 'iOS-Unsandboxed read-only preflight' "$RUNTIME_DIR/daemon.probe"; then
        printf 'PREFLIGHT_PROGRAM_ENTRY: PASS (diagnostic banner observed; exit=%s; compatibility may remain blocked).\n' "$PROBE_STATUS"
    else
        printf 'PREFLIGHT_PROGRAM_ENTRY: FAIL (no diagnostic banner; exit=%s; cause is unclassified).\n' "$PROBE_STATUS"
        RUNTIME_RESULT=FAIL
        printf '%s\n' 'TEMPORARY_IPC_RESULT: BLOCKED (daemon preflight did not reach its diagnostic banner).'
        runtime_cleanup
        return 0
    fi

    printf 'COMMAND: <%s> <--test-socket> <%s>\n' "$DAEMON_BINARY" "$RUNTIME_SOCKET"
    "$DAEMON_BINARY" --test-socket "$RUNTIME_SOCKET" >"$RUNTIME_DIR/daemon.stdout" \
        2>"$RUNTIME_DIR/daemon.stderr" &
    DAEMON_PID=$!
    SOCKET_READY=0
    ATTEMPT=0
    while [ "$ATTEMPT" -lt 10 ]; do
        if [ -e "$RUNTIME_SOCKET" ] || [ -L "$RUNTIME_SOCKET" ]; then
            SOCKET_READY=1
            break
        fi
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            break
        fi
        sleep 1
        ATTEMPT=$((ATTEMPT + 1))
    done

    if [ "$SOCKET_READY" -ne 1 ]; then
        printf '%s\n' 'DAEMON_TEST_SOCKET_STARTUP: FAIL (private socket did not appear within 10 seconds).'
        if [ -f "$RUNTIME_DIR/daemon.stderr" ]; then print_file_lines "$RUNTIME_DIR/daemon.stderr"; fi
        RUNTIME_RESULT=FAIL
        printf '%s\n' 'TEMPORARY_IPC_RESULT: FAIL'
        runtime_cleanup
        return 0
    fi
    printf '%s\n' 'DAEMON_TEST_SOCKET_STARTUP: PASS (isolated socket created).'
    if stat -f '%Lp' "$RUNTIME_SOCKET" >/dev/null 2>&1; then
        SOCKET_MODE=$(stat -f '%Lp' "$RUNTIME_SOCKET" 2>/dev/null)
    elif stat -c '%a' "$RUNTIME_SOCKET" >/dev/null 2>&1; then
        SOCKET_MODE=$(stat -c '%a' "$RUNTIME_SOCKET" 2>/dev/null)
    else
        SOCKET_MODE=
    fi
    if [ "$SOCKET_MODE" = 600 ]; then
        printf '%s\n' 'TEST_SOCKET_MODE: PASS (0600).'
    elif [ -n "$SOCKET_MODE" ]; then
        printf 'TEST_SOCKET_MODE: FAIL (observed mode %s; expected 0600).\n' "$SOCKET_MODE"
        RUNTIME_RESULT=FAIL
    else
        printf '%s\n' 'MISSING_COMMAND: stat with a supported mode format (test socket mode could not be verified).'
        RUNTIME_RESULT=FAIL
    fi
    if command_available ls; then ls -ld "$RUNTIME_SOCKET" 2>&1; else printf 'MISSING_COMMAND: ls (test socket owner/group listing)\n'; fi
    stat_line "$RUNTIME_SOCKET" || :

    if record_run 'CLI read-only IPC check' "$RUNTIME_DIR/cli.check" \
        "$CLI_BINARY" --test-socket "$RUNTIME_SOCKET" check; then
        CHECK_STATUS=0
    else
        CHECK_STATUS=$?
    fi
    for CHECK_REQUEST in PING GET_STATUS GET_PREFLIGHT GET_LIFECYCLE_STATUS; do
        if contains_text "$CHECK_REQUEST: PASS" "$RUNTIME_DIR/cli.check"; then
            printf '%s: PASS (read-only IPC reply received).\n' "$CHECK_REQUEST"
        else
            printf '%s: FAIL (required response not reported; CLI exit=%s).\n' "$CHECK_REQUEST" "$CHECK_STATUS"
            RUNTIME_RESULT=FAIL
        fi
    done
    if [ -n "$RUNTIME_UID" ] && [ -n "$RUNTIME_GID" ] &&
        contains_text "peer_uid=$RUNTIME_UID; peer_gid=$RUNTIME_GID" "$RUNTIME_DIR/cli.check"; then
        printf 'GETPEEREID_RESULT: PASS (server-reported peer matches effective uid=%s gid=%s for this SSH session).\n' \
            "$RUNTIME_UID" "$RUNTIME_GID"
    else
        printf '%s\n' 'GETPEEREID_RESULT: FAIL (reported identity did not match, or comparison data was unavailable).'
        RUNTIME_RESULT=FAIL
    fi

    if record_run 'CLI read-only status' "$RUNTIME_DIR/cli.status" \
        "$CLI_BINARY" --test-socket "$RUNTIME_SOCKET" status; then
        printf '%s\n' 'GET_STATUS_CLI_RESULT: PASS.'
    else
        STATUS_CODE=$?
        printf 'GET_STATUS_CLI_RESULT: FAIL (CLI exit=%s).\n' "$STATUS_CODE"
        RUNTIME_RESULT=FAIL
    fi

    printf 'COMMAND: <kill> <-TERM> <%s>\n' "$DAEMON_PID"
    if kill -TERM "$DAEMON_PID" 2>&1; then
        if wait "$DAEMON_PID"; then
            DAEMON_EXIT=0
        else
            DAEMON_EXIT=$?
        fi
        DAEMON_PID=
        printf 'DAEMON_SIGTERM_EXIT_STATUS: %s\n' "$DAEMON_EXIT"
        if [ "$DAEMON_EXIT" -eq 0 ]; then
            printf '%s\n' 'DAEMON_SIGTERM_SHUTDOWN: PASS (clean exit).'
        else
            printf '%s\n' 'DAEMON_SIGTERM_SHUTDOWN: FAIL (nonzero exit; signal cause not inferred).'
            RUNTIME_RESULT=FAIL
        fi
    else
        printf '%s\n' 'DAEMON_SIGTERM_SHUTDOWN: FAIL (SIGTERM could not be delivered).'
        RUNTIME_RESULT=FAIL
    fi
    if [ -e "$RUNTIME_SOCKET" ]; then
        printf '%s\n' 'TEST_SOCKET_CLEANUP: FAIL (daemon left its isolated socket path behind).'
        RUNTIME_RESULT=FAIL
    else
        printf '%s\n' 'TEST_SOCKET_CLEANUP: PASS (isolated socket path removed).'
    fi
    if [ -f "$RUNTIME_DIR/daemon.stderr" ]; then
        printf '%s\n' 'DAEMON_STDERR:'
        print_file_lines "$RUNTIME_DIR/daemon.stderr"
    fi
    printf '%s\n' 'SSH_CONTINUITY: NOT RUN by script; operator must verify an unrelated SSH session and a new SSH command.'
    printf '%s\n' 'ROOT_AND_NONROOT_MATRIX: only the current uid/gid was tested; repeat explicitly from each already available SSH identity.'
    runtime_cleanup
    printf 'TEMPORARY_IPC_RESULT: %s\n' "$RUNTIME_RESULT"
    printf '%s\n' 'DEVICE_RUNTIME_QUALIFICATION: PARTIAL until SSH continuity and both available identity cases are independently recorded.'
    return 0
}

printf 'P006 iOS device runtime qualification\n'
if [ "$FIXTURE_MODE" -eq 1 ]; then
    printf 'MODE: HOST FIXTURE ONLY (root prefix %s; no device evidence).\n' "$ROOT_PREFIX"
else
    printf '%s\n' 'MODE: read-only inventory; temporary runtime test is disabled unless --runtime-test is supplied.'
fi
if command_available date; then
    observe 'qualification timestamp UTC (system clock)' date -u '+%Y-%m-%dT%H:%M:%SZ' || :
else
    printf 'MISSING_COMMAND: date (qualification timestamp)\n'
fi

report_host_facts
report_runtime_path_inventory
if [ "$FIXTURE_MODE" -eq 1 ]; then
    printf '\n%s\n' 'AMETHYST_PACKAGE_EVIDENCE: NOT RUN in fixture mode (host package database not queried).'
    printf '%s\n' 'LAUNCHD_READ_ONLY_INSPECTION: NOT RUN in fixture mode (host launchd not queried).'
else
    query_amethyst_package
    report_launchd
fi

printf '\nPREFLIGHT_INTERPRETATION:\n'
printf '%s\n' 'OBSERVED file presence/type/readability and platform facts do not prove installed Amethyst binary provenance or live hook injection.'
printf '%s\n' 'INFERRED compatibility may be UNVERIFIED; this harness never promotes a source SHA or filename to installed-build identity.'
printf '%s\n' 'AD_HOC_SIGNATURE, signature validity, Amethyst trust, sandbox exemption, and successful startup are separate facts.'

if [ "$FIXTURE_MODE" -eq 1 ]; then
    printf '%s\n' 'TEMPORARY_IPC_TEST: NOT RUN in fixture mode.'
    printf '%s\n' 'RESULT: host fixture inventory completed; this is not iOS, Amethyst, IPC, or launchd device evidence.'
elif [ "$RUNTIME_TEST" -eq 1 ]; then
    run_runtime_test
else
    printf '%s\n' 'TEMPORARY_IPC_TEST: NOT RUN (read-only inventory mode).'
    printf '%s\n' 'RESULT: inventory completed; this is not full device runtime qualification.'
fi

exit 0
