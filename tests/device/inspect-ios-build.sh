#!/bin/sh
# Read-only host-side inspection of the Apple ARM64 build outputs.
# This reports Mach-O and signing metadata; it never signs or deploys files.

set -u

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf '%s\n' 'Usage: inspect-ios-build.sh IOS_CLI IOS_DAEMON [IOS_INSTALLER_HELPER]' >&2
    exit 2
fi

INSPECTION_STATUS=0

report() {
    LABEL=$1
    shift
    printf '\n%s\n' "$LABEL"
    printf 'COMMAND:'
    for ARG do printf ' <%s>' "$ARG"; done
    printf '\n'
    "$@" 2>&1
    RC=$?
    printf 'EXIT_STATUS: %s\n' "$RC"
    return 0
}

required_report() {
    LABEL=$1
    shift
    printf '\n%s\n' "$LABEL"
    printf 'COMMAND:'
    for ARG do printf ' <%s>' "$ARG"; done
    printf '\n'
    "$@" 2>&1
    RC=$?
    printf 'EXIT_STATUS: %s\n' "$RC"
    if [ "$RC" -ne 0 ]; then INSPECTION_STATUS=1; fi
    return 0
}

inspect_binary() {
    BINARY=$1
    printf '\nBINARY: %s\n' "$BINARY"
    if [ ! -f "$BINARY" ]; then
        printf '%s\n' 'RESULT: FAIL (build output is absent or not a regular file).'
        INSPECTION_STATUS=1
        return
    fi

    if command -v shasum >/dev/null 2>&1; then
        required_report 'SHA256' shasum -a 256 "$BINARY"
    elif command -v sha256sum >/dev/null 2>&1; then
        required_report 'SHA256' sha256sum "$BINARY"
    else
        printf '%s\n' 'MISSING_COMMAND: shasum or sha256sum (build hash unavailable).'
        INSPECTION_STATUS=1
    fi

    if command -v file >/dev/null 2>&1; then
        printf '\n%s\n' 'FILE_FORMAT_AND_ARCHITECTURE'
        printf 'COMMAND: <file> <%s>\n' "$BINARY"
        FORMAT_OUTPUT=$(file "$BINARY" 2>&1)
        FORMAT_STATUS=$?
        printf 'EXIT_STATUS: %s\n%s\n' "$FORMAT_STATUS" "$FORMAT_OUTPUT"
        case "$FORMAT_OUTPUT" in
            *Mach-O*arm64*)
                if [ "$FORMAT_STATUS" -eq 0 ]; then
                    printf '%s\n' 'MACH_O_ARM64_CHECK: PASS.'
                else
                    printf '%s\n' 'MACH_O_ARM64_CHECK: FAIL (file returned a nonzero status).'
                    INSPECTION_STATUS=1
                fi
                ;;
            *)
                printf '%s\n' 'MACH_O_ARM64_CHECK: FAIL (expected a Mach-O arm64 image).'
                INSPECTION_STATUS=1
                ;;
        esac
    else
        printf '%s\n' 'MISSING_COMMAND: file (Mach-O format and architecture).'
        INSPECTION_STATUS=1
    fi

    if command -v otool >/dev/null 2>&1; then
        required_report 'MACH_O_HEADER (CPU type and file type)' otool -hv "$BINARY"
        required_report 'MACH_O_DEPENDENCIES (dynamic loader dependencies)' otool -L "$BINARY"
        printf '\n%s\n' 'MACH_O_LOAD_COMMANDS (minimum OS, SDK, UUID, signature load command)'
        printf 'COMMAND: <otool> <-l> <%s>\n' "$BINARY"
        LOAD_OUTPUT=$(otool -l "$BINARY" 2>&1)
        LOAD_STATUS=$?
        printf 'EXIT_STATUS: %s\n%s\n' "$LOAD_STATUS" "$LOAD_OUTPUT"
        case "$LOAD_OUTPUT" in
            *LC_BUILD_VERSION*minos\ 12.0*|*LC_VERSION_MIN_IPHONEOS*version\ 12.0*)
                if [ "$LOAD_STATUS" -ne 0 ]; then
                    printf '%s\n' 'IOS_12_DEPLOYMENT_TARGET_CHECK: FAIL (otool returned a nonzero status).'
                    INSPECTION_STATUS=1
                else
                    printf '%s\n' 'IOS_12_DEPLOYMENT_TARGET_CHECK: PASS.'
                fi
                ;;
            *)
                printf '%s\n' 'IOS_12_DEPLOYMENT_TARGET_CHECK: FAIL (iOS 12.0 minimum target not found in load commands).'
                INSPECTION_STATUS=1
                ;;
        esac
    else
        printf '%s\n' 'MISSING_COMMAND: otool (Mach-O headers, load commands, and dependencies).'
        INSPECTION_STATUS=1
    fi

    if command -v codesign >/dev/null 2>&1; then
        printf '%s\n' 'CODESIGN_DISPLAY is metadata only; it does not establish Amethyst trust, sandbox exemption, or startup.'
        report 'CODESIGN_METADATA' codesign -dv --verbose=4 "$BINARY"
        printf '%s\n' 'CODESIGN_VERIFY checks local signature validity only; an ad-hoc result is not trust evidence.'
        report 'CODESIGN_VALIDATION' codesign --verify --strict --verbose=2 "$BINARY"
    else
        printf '%s\n' 'MISSING_COMMAND: codesign (signature metadata and host validation).'
        INSPECTION_STATUS=1
    fi
}

printf '%s\n' 'P006 Apple ARM64 build inspection (read-only; host-side evidence only).'
printf '%s\n' 'No signing, trust-cache, deployment, or device startup operation is performed.'
inspect_binary "$1"
inspect_binary "$2"
if [ "$#" -eq 3 ]; then
    inspect_binary "$3"
    if nm -g "$3" | grep -q '_iu_builder_admin_v1'; then
        printf '%s\n' 'PRIVILEGED_BUILDER_LINKAGE: PASS.'
    else
        printf '%s\n' 'PRIVILEGED_BUILDER_LINKAGE: FAIL.'
        INSPECTION_STATUS=1
    fi
    if nm -g "$3" | grep -q 'iu_builder_admin_test_v1'; then
        printf '%s\n' 'PRODUCTION_TEST_HOOK_CHECK: FAIL.'
        INSPECTION_STATUS=1
    else
        printf '%s\n' 'PRODUCTION_TEST_HOOK_CHECK: PASS.'
    fi
    if strings "$3" | grep -Eq 'builder-disk-full|builder-fail-post-rename-fsync'; then
        printf '%s\n' 'PRODUCTION_FAULT_OVERRIDE_CHECK: FAIL.'
        INSPECTION_STATUS=1
    fi
fi

if [ "$INSPECTION_STATUS" -eq 0 ]; then
    printf '%s\n' 'BUILD_INSPECTION_RESULT: PASS (all inspection tools ran; review recorded output for target facts).'
    exit 0
fi
printf '%s\n' 'BUILD_INSPECTION_RESULT: FAIL (required build outputs or inspection commands are missing).'
exit 1
