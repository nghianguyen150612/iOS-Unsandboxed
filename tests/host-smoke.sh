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

check_cli_unimplemented status
check_cli_unimplemented inspect ./binary
check_cli_unimplemented sign ./binary
check_cli_unimplemented sign ./binary --entitlements ./entitlements.plist
check_cli_unimplemented install ./binary
check_cli_unimplemented enable
check_cli_unimplemented disable
check_cli_unimplemented logs

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
