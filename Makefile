SHELL := /bin/sh
CC ?= cc
IOS_TARGET := aarch64-apple-ios
IOS_DEPLOYMENT_TARGET := 12.0
HOST_DAEMON := build/host/ios-unsandboxedd
IOS_DAEMON := build/ios/ios-unsandboxedd

.PHONY: help build host-build test smoke-test clean check-ios-toolchain build-ios

help:
	@printf '%s\n' \
	  'make build       Build the host CLI and diagnostic daemon' \
	  'make test        Run Rust tests and host smoke checks' \
	  'make smoke-test  Check host CLI and daemon help/version/fail-safe modes' \
	  'make build-ios   Cross-compile CLI and daemon for ARM64 iOS 12.0+' \
	  'make clean       Remove generated build artifacts'

build: host-build

host-build:
	cargo build --workspace
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 daemon/src/main.c -o $(HOST_DAEMON)

test: host-build
	cargo test --workspace
	$(MAKE) smoke-test

smoke-test: host-build
	./tests/host-smoke.sh

check-ios-toolchain:
	@case "$$(uname -s)" in \
	  Darwin) ;; \
	  *) echo 'iOS builds require macOS, Xcode command line tools, and the iPhoneOS SDK.' >&2; exit 2 ;; \
	esac
	@command -v xcrun >/dev/null 2>&1 || { echo 'xcrun is required; install Xcode command line tools.' >&2; exit 2; }
	@xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1 || { echo 'The iPhoneOS SDK is unavailable; install Xcode.' >&2; exit 2; }
	@rustup target list --installed 2>/dev/null | grep -Fx '$(IOS_TARGET)' >/dev/null || { echo 'Rust target $(IOS_TARGET) is missing; run: rustup target add $(IOS_TARGET)' >&2; exit 2; }

build-ios: check-ios-toolchain
	mkdir -p build/ios
	SDKROOT="$$(xcrun --sdk iphoneos --show-sdk-path)" IPHONEOS_DEPLOYMENT_TARGET=$(IOS_DEPLOYMENT_TARGET) cargo build --release --target $(IOS_TARGET) --workspace
	xcrun --sdk iphoneos clang -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 \
	  -target arm64-apple-ios$(IOS_DEPLOYMENT_TARGET) \
	  -isysroot "$$(xcrun --sdk iphoneos --show-sdk-path)" \
	  -o $(IOS_DAEMON) daemon/src/main.c

clean:
	cargo clean
	rm -rf build
