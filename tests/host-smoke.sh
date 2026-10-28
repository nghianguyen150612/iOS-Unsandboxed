#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cli="$repo_root/target/debug/ios-unsandboxed"
daemon="$repo_root/build/host/ios-unsandboxedd"

"$cli" --help >/dev/null
[ "$("$cli" --version)" = 'ios-unsandboxed 0.1.0' ]

check_cli_unimplemented() {
    if output=$("$cli" "$@" 2>&1); then
        echo "CLI command '$1' unexpectedly succeeded" >&2
        exit 1
    else
        status=$?
    fi
    [ "$status" -eq 3 ] || {
        echo "CLI command '$1' returned $status, expected 3" >&2
        exit 1
    }
    printf '%s\n' "$output" | grep -F 'is not implemented' >/dev/null
}

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/iu-inspect-smoke.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
fixture="$fixture_dir/unsigned-arm64"
python3 - "$fixture" <<'PY'
import struct
import sys

image = bytearray(32)
struct.pack_into("<IIIIIIII", image, 0, 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
with open(sys.argv[1], "wb") as output:
    output.write(image)
PY
chmod 0700 "$fixture"
inspect_output=$("$cli" inspect "$fixture")
printf '%s\n' "$inspect_output" | grep -F 'Architecture: ARM64' >/dev/null
printf '%s\n' "$inspect_output" | grep -F 'Signature: NO_LC_CODE_SIGNATURE' >/dev/null
printf '%s\n' "$inspect_output" | grep -F 'Preparation: PREPARATION_REQUIRED_BUT_NOT_IMPLEMENTED' >/dev/null
printf '%s\n' "$inspect_output" | grep -F 'Launch permission: NOT GRANTED' >/dev/null
printf '\000\000' >"$fixture_dir/truncated"
chmod 0700 "$fixture_dir/truncated"
if bad_output=$("$cli" inspect "$fixture_dir/truncated" 2>&1); then
    echo 'CLI inspection accepted a truncated Mach-O' >&2
    exit 1
else
    status=$?
fi
[ "$status" -eq 4 ]
printf '%s\n' "$bad_output" | grep -F 'Inspection: INVALID_BINARY' >/dev/null
printf '%s\n' "$bad_output" | grep -F 'Signature: TRUNCATED_OR_CORRUPT' >/dev/null
check_cli_unimplemented sign ./binary
check_cli_unimplemented sign ./binary --entitlements ./entitlements.plist
check_cli_unimplemented install ./binary
check_cli_unimplemented enable
check_cli_unimplemented disable
check_cli_unimplemented logs

if output=$("$cli" status 2>&1); then
    echo 'CLI status unexpectedly connected to absent daemon' >&2
    exit 1
else
    status=$?
fi
[ "$status" -eq 4 ]
printf '%s\n' "$output" | grep -F 'Activation: UNKNOWN' >/dev/null

# Local inspection remains independent of the absent daemon.
"$cli" inspect "$fixture" | grep -F 'Inspection: COMPLETE' >/dev/null

if output=$("$cli" doctor 2>&1); then
    echo 'CLI doctor unexpectedly reported operational compatibility' >&2
    exit 1
else
    status=$?
fi
[ "$status" -eq 4 ] || {
    echo "CLI doctor returned $status, expected fail-closed status 4" >&2
    exit 1
}
printf '%s\n' "$output" | grep -F 'Detected platform: linux' >/dev/null
printf '%s\n' "$output" | grep -F 'Amethyst compatibility verification: UNSUPPORTED_PLATFORM' >/dev/null
printf '%s\n' "$output" | grep -F 'Device acceptance: NOT TESTED' >/dev/null

"$daemon" --help >/dev/null
[ "$("$daemon" --version)" = 'ios-unsandboxedd 0.1.0' ]

if output=$("$daemon" 2>&1); then
    echo 'Daemon service mode unexpectedly succeeded' >&2
    exit 1
else
    status=$?
fi
[ "$status" -eq 3 ] || {
    echo "Daemon service mode returned $status, expected 3" >&2
    exit 1
}
printf '%s\n' "$output" | grep -F 'daemon service mode is not implemented' >/dev/null

if output=$("$daemon" start 2>&1); then
    echo 'Unsupported daemon operation unexpectedly succeeded' >&2
    exit 1
else
    status=$?
fi
[ "$status" -eq 3 ] || {
    echo "Unsupported daemon operation returned $status, expected 3" >&2
    exit 1
}
printf '%s\n' "$output" | grep -F 'operation '\''start'\'' is not implemented' >/dev/null

if output=$("$daemon" --probe 2>&1); then
    echo 'Daemon probe unexpectedly reported operational compatibility' >&2
    exit 1
else
    status=$?
fi
[ "$status" -eq 4 ] || {
    echo "Daemon probe returned $status, expected fail-closed status 4" >&2
    exit 1
}
printf '%s\n' "$output" | grep -F 'Detected platform: Linux' >/dev/null
printf '%s\n' "$output" | grep -F 'UNSUPPORTED_PLATFORM' >/dev/null
printf '%s\n' "$output" | grep -F 'Device acceptance: NOT TESTED' >/dev/null

echo 'Host CLI and daemon read-only/fail-safe smoke checks passed.'
