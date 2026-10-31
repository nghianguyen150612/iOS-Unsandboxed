#!/bin/sh
# Stable management entrypoint. The paired C helper owns all parsing and
# filesystem changes, including builder-trust administration and recovery.
# This script never sources package, manifest, or CLI plan data.
set -eu

case "$0" in
    */*) SELF_DIR=${0%/*}; [ -n "$SELF_DIR" ] || SELF_DIR=/ ;;
    *) SELF_DIR=. ;;
esac
SELF_DIR=$(CDPATH= cd -P "$SELF_DIR" && pwd -P)
HELPER="$SELF_DIR/installer-helper"

if [ ! -x "$HELPER" ]; then
    printf '%s\n' 'ios-unsandboxed installer helper is missing or not executable.' >&2
    printf '%s\n' 'Run this manager from a complete rootful package or installed project directory.' >&2
    exit 2
fi

exec "$HELPER" "$@"
