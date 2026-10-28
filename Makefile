SHELL := /bin/sh
CC ?= cc
IOS_TARGET := aarch64-apple-ios
IOS_DEPLOYMENT_TARGET := 12.0
HOST_DAEMON := build/host/ios-unsandboxedd
HOST_NATIVE_TEST := build/host/native-preflight-test
HOST_PEER_AUTH_TEST := build/host/peer-auth-test
HOST_STATE_TEST := build/host/service-state-test
HOST_INSTALLER_HELPER := build/host/installer-helper
IOS_DAEMON := build/ios/ios-unsandboxedd
IOS_INSTALLER_HELPER := build/ios/installer-helper
NATIVE_SOURCES := native/src/iu_preflight.c native/src/iu_policy.c native/src/iu_service_state.c
LIFECYCLE_SOURCE := native/src/iu_service_lifecycle.c
NATIVE_INCLUDES := -Inative/include

.PHONY: help build host-build test native-test state-test ipc-test packaging-test installer-test service-test package-rootful device-harness-test smoke-test clean check-ios-toolchain build-ios

help:
	@printf '%s\n' \
	  'make build       Build the host CLI and diagnostic daemon' \
	  'make test        Run Rust, native, IPC, package, lifecycle, and host smoke checks' \
	  'make service-test Run mocked service lifecycle fixtures' \
	  'make native-test Run C17 preflight, policy, and peer-auth fixtures' \
	  'make state-test  Run read-only persistent-state safety fixtures' \
	  'make ipc-test    Run local socket, protocol, and peer-auth tests' \
	  'make packaging-test Parse and check the passive LaunchDaemon plist' \
	  'make installer-test Run isolated rootful installer transaction fixtures' \
	  'make package-rootful Build the deterministic Apple ARM64 rootful distribution (macOS)' \
	  'make device-harness-test Run host fixtures for the safe device harness' \
	  'make smoke-test  Check host CLI and daemon help/version/fail-safe modes' \
	  'make build-ios   Cross-compile CLI, daemon, and installer helper for ARM64 iOS 12.0+' \
	  'make clean       Remove generated build artifacts'

build: host-build

host-build:
	cargo build --locked --workspace
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) -Idaemon/include \
	  daemon/src/main.c daemon/src/ipc_server.c daemon/src/peer_auth.c $(NATIVE_SOURCES) -o $(HOST_DAEMON)
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 -DIU_INSTALLER_TESTING $(NATIVE_INCLUDES) \
	  native/src/iu_installer.c native/src/iu_service_state.c $(LIFECYCLE_SOURCE) -o $(HOST_INSTALLER_HELPER)

test: host-build
	cargo test --locked --workspace
	$(MAKE) native-test
	$(MAKE) ipc-test
	$(MAKE) packaging-test
	$(MAKE) installer-test
	$(MAKE) service-test
	$(MAKE) device-harness-test
	$(MAKE) smoke-test

native-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) \
	  tests/native-preflight-test.c $(NATIVE_SOURCES) -o $(HOST_NATIVE_TEST)
	./$(HOST_NATIVE_TEST)
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) \
	  tests/peer-auth-test.c daemon/src/peer_auth.c -Idaemon/include -o $(HOST_PEER_AUTH_TEST)
	./$(HOST_PEER_AUTH_TEST)
	$(MAKE) state-test

state-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 -pthread $(NATIVE_INCLUDES) \
	  tests/service-state-test.c native/src/iu_service_state.c -o $(HOST_STATE_TEST)
	./$(HOST_STATE_TEST)

ipc-test: host-build
	python3 tests/ipc-integration.py

packaging-test:
	python3 tests/packaging-plist-test.py

installer-test: host-build
	python3 tests/packaging/installer-integration.py $(HOST_INSTALLER_HELPER)

service-test: host-build
	python3 tests/service/service-lifecycle-test.py $(HOST_INSTALLER_HELPER)

device-harness-test:
	python3 tests/device/host-fixture-test.py

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
	SDKROOT="$$(xcrun --sdk iphoneos --show-sdk-path)" IPHONEOS_DEPLOYMENT_TARGET=$(IOS_DEPLOYMENT_TARGET) cargo build --locked --release --target $(IOS_TARGET) --workspace
	xcrun --sdk iphoneos clang -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) \
	  -target arm64-apple-ios$(IOS_DEPLOYMENT_TARGET) \
	  -isysroot "$$(xcrun --sdk iphoneos --show-sdk-path)" \
	  -Idaemon/include -o $(IOS_DAEMON) daemon/src/main.c daemon/src/ipc_server.c daemon/src/peer_auth.c $(NATIVE_SOURCES)
	xcrun --sdk iphoneos clang -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) \
	  -target arm64-apple-ios$(IOS_DEPLOYMENT_TARGET) \
	  -isysroot "$$(xcrun --sdk iphoneos --show-sdk-path)" \
	  native/src/iu_installer.c native/src/iu_service_state.c $(LIFECYCLE_SOURCE) -o $(IOS_INSTALLER_HELPER)

package-rootful: build-ios
	python3 scripts/build-rootful-package.sh

clean:
	cargo clean
	rm -rf build
