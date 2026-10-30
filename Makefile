SHELL := /bin/sh
CC ?= cc
IOS_TARGET := aarch64-apple-ios
IOS_DEPLOYMENT_TARGET := 12.0
HOST_DAEMON := build/host/ios-unsandboxedd
HOST_NATIVE_TEST := build/host/native-preflight-test
HOST_PEER_AUTH_TEST := build/host/peer-auth-test
HOST_STATE_TEST := build/host/service-state-test
HOST_ADAPTER_TEST := build/host/amethyst-adapter-test
HOST_INSTALLER_HELPER := build/host/installer-helper
IOS_DAEMON := build/ios/ios-unsandboxedd
IOS_INSTALLER_HELPER := build/ios/installer-helper
NATIVE_SOURCES := native/src/iu_preflight.c native/src/iu_policy.c native/src/iu_service_state.c native/src/iu_amethyst_adapter.c native/src/iu_amethyst_capabilities.c
PLANNER_SOURCE := native/src/iu_execution_planner.c
P012_SOURCES := native/src/iu_artifact_provenance.c native/src/iu_launch_binding.c native/src/iu_policy_store.c
LIFECYCLE_SOURCE := native/src/iu_service_lifecycle.c
POLICY_SOURCES := native/src/iu_policy_store.c native/src/iu_policy_manager.c native/src/iu_trust_store.c native/src/iu_trust_transaction.c native/src/iu_builder_transaction.c native/src/iu_trust_manager.c $(NATIVE_SOURCES) $(PLANNER_SOURCE)
NATIVE_INCLUDES := -Inative/include

.PHONY: provenance-test launch-binding-test authenticated-binding-test build-attestation-test builder-trust-test builder-transaction-test trust-provider-test trust-format-test trust-manager-test trust-recovery-test origin-policy-test help build host-build test native-test state-test ipc-test packaging-test installer-test service-test package-rootful device-harness-test smoke-test adapter-test planner-test policy-test clean check-ios-toolchain build-ios

help:
	@printf '%s\n' \
	  'make build       Build the host CLI and diagnostic daemon' \
	  'make test        Run Rust, native, planner, IPC, package, lifecycle, and host smoke checks' \
	  'make service-test Run mocked service lifecycle fixtures' \
	  'make adapter-test Run read-only Amethyst adapter and Mach-O fixtures' \
	  'make planner-test Run read-only executable identity planner fixtures' \
	  'make policy-test  Run policy store and manager fixtures' \
	  'make provenance-test Run evidence and trust-boundary fixtures' \
	  'make launch-binding-test Run identity and scope fixtures' \
	  'make authenticated-binding-test Run descriptor-bound authenticated preview fixtures' \
	  'make build-attestation-test Run DSSE/SLSA verification and P013C binding fixtures' \
	  'make builder-trust-test Run read-only builder root, policy, provider, and CLI fixtures' \
	  'make trust-provider-test Run signed-manifest and trust-anchor fixtures' \
	  'make origin-policy-test Run fail-closed origin-policy fixtures' \
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
	  native/src/iu_installer.c $(LIFECYCLE_SOURCE) $(POLICY_SOURCES) -o $(HOST_INSTALLER_HELPER)

test: host-build
	cargo test --locked --workspace
	$(MAKE) native-test
	$(MAKE) ipc-test
	$(MAKE) packaging-test
	$(MAKE) installer-test
	$(MAKE) service-test
	$(MAKE) adapter-test
	$(MAKE) planner-test
	$(MAKE) policy-test
	$(MAKE) provenance-test
	$(MAKE) launch-binding-test
	$(MAKE) authenticated-binding-test
	$(MAKE) build-attestation-test
	$(MAKE) builder-trust-test
	$(MAKE) builder-transaction-test
	$(MAKE) trust-provider-test
	$(MAKE) trust-format-test
	$(MAKE) trust-manager-test
	$(MAKE) trust-recovery-test
	$(MAKE) origin-policy-test
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

adapter-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 -DIU_AME_TESTING $(NATIVE_INCLUDES) \
	  tests/adapter/amethyst-adapter-test.c tests/adapter/mock_backend.c \
	  native/src/iu_amethyst_adapter.c native/src/iu_amethyst_capabilities.c \
	  native/src/iu_policy.c native/src/iu_preflight.c -o $(HOST_ADAPTER_TEST)
	./$(HOST_ADAPTER_TEST)
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) \
	  tests/adapter/production-classifier-test.c native/src/iu_amethyst_adapter.c \
	  native/src/iu_amethyst_capabilities.c native/src/iu_policy.c native/src/iu_preflight.c \
	  -o build/host/adapter-production-classifier-test
	./build/host/adapter-production-classifier-test

planner-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 -DIU_EXECUTION_PLANNER_TESTING $(NATIVE_INCLUDES) \
	  tests/planner/execution-planner-test.c $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/execution-planner-test
	python3 tests/planner/planner-fixtures.py build/host/execution-planner-test
	@if $(CC) -std=c17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
	  -DIU_EXECUTION_PLANNER_TESTING $(NATIVE_INCLUDES) tests/planner/execution-planner-test.c \
	  $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/execution-planner-sanitized-test >/dev/null 2>&1; then \
	  ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
	    python3 tests/planner/planner-fixtures.py build/host/execution-planner-sanitized-test; \
	else echo 'Planner sanitizers unavailable; strict C17 fixture run completed.'; fi

policy-test: host-build
	python3 tests/policy/policy-manager-test.py $(HOST_INSTALLER_HELPER)

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
	  native/src/iu_installer.c $(LIFECYCLE_SOURCE) $(POLICY_SOURCES) -o $(IOS_INSTALLER_HELPER)

package-rootful: build-ios
	python3 scripts/build-rootful-package.sh

clean:
	cargo clean
	rm -rf build

provenance-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 -DIU_PROVENANCE_TESTING $(NATIVE_INCLUDES) tests/provenance/provenance-test.c tests/provenance/mock_verifier.c native/src/iu_artifact_provenance.c $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/provenance-test
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) tests/provenance/provenance-test.c native/src/iu_artifact_provenance.c $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/provenance-production-test
	python3 tests/launch-binding/fixtures.py build/host/provenance-test build/host/provenance-production-test
	@if nm build/host/provenance-production-test | grep -q iu_provenance_test_verify; then echo 'test verifier leaked into production' >&2; exit 1; fi
	@if $(CC) -std=c17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -DIU_PROVENANCE_TESTING $(NATIVE_INCLUDES) tests/provenance/provenance-test.c tests/provenance/mock_verifier.c native/src/iu_artifact_provenance.c $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/provenance-sanitized-test >/dev/null 2>&1; then ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/launch-binding/fixtures.py build/host/provenance-sanitized-test; else echo 'Provenance sanitizers unavailable'; fi

launch-binding-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 -DIU_LAUNCH_BINDING_TESTING $(NATIVE_INCLUDES) tests/launch-binding/launch-binding-test.c $(P012_SOURCES) $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/launch-binding-test
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 -DIU_LAUNCH_BINDING_TESTING -DIU_PROVENANCE_TESTING $(NATIVE_INCLUDES) tests/launch-binding/scope-test.c tests/provenance/mock_verifier.c $(P012_SOURCES) $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/launch-scope-test
	python3 tests/launch-binding/fixtures.py build/host/launch-scope-test build/host/launch-binding-test
	@if $(CC) -std=c17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -DIU_LAUNCH_BINDING_TESTING $(NATIVE_INCLUDES) tests/launch-binding/launch-binding-test.c $(P012_SOURCES) $(NATIVE_SOURCES) $(PLANNER_SOURCE) -o build/host/launch-binding-sanitized-test >/dev/null 2>&1; then ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/launch-binding/fixtures.py build/host/launch-binding-sanitized-test; else echo 'Launch binding sanitizers unavailable'; fi
	@if [ -x target/debug/ios-unsandboxed ]; then python3 tests/launch-binding/cli-test.py; if nm target/debug/ios-unsandboxed | grep -q iu_provenance_test_verify; then echo 'test verifier leaked into CLI' >&2; exit 1; fi; fi

authenticated-binding-test:
	cargo test --locked --workspace authenticated_binding::tests::
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) \
	  tests/authenticated-binding/abi-test.c $(P012_SOURCES) $(NATIVE_SOURCES) $(PLANNER_SOURCE) \
	  -o build/host/authenticated-binding-abi-test
	python3 tests/authenticated-binding/abi-fixtures.py build/host/authenticated-binding-abi-test
	@if $(CC) -std=c17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
	  $(NATIVE_INCLUDES) tests/authenticated-binding/abi-test.c $(P012_SOURCES) $(NATIVE_SOURCES) \
	  $(PLANNER_SOURCE) -o build/host/authenticated-binding-abi-sanitized-test >/dev/null 2>&1; then \
	  ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
	    python3 tests/authenticated-binding/abi-fixtures.py build/host/authenticated-binding-abi-sanitized-test; \
	else echo 'Authenticated-binding sanitizers unavailable; strict C17 ABI fixture run completed.'; fi

build-attestation-test:
	cargo test --locked --workspace build_attestation::tests::
	cargo test --locked --workspace authenticated_binding::tests::attestation
	cargo build --locked --workspace
	python3 tests/attestation/cli-test.py target/debug/ios-unsandboxed

builder-trust-test:
	cargo build --locked --workspace
	cargo test --locked --workspace builder_trust::tests::
	python3 tests/builder-trust/cli-test.py target/debug/ios-unsandboxed

builder-transaction-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) tests/builder-trust/transaction-test.c native/src/iu_builder_transaction.c -o build/host/builder-transaction-test
	python3 tests/builder-trust/transaction-fixtures.py build/host/builder-transaction-test
	cargo test --locked --workspace builder_transaction::tests::
	@if $(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie $(NATIVE_INCLUDES) tests/builder-trust/transaction-test.c native/src/iu_builder_transaction.c -o build/host/builder-transaction-sanitized >/dev/null 2>&1; then ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/builder-trust/transaction-fixtures.py build/host/builder-transaction-sanitized; else echo 'Builder transaction sanitizers unavailable'; fi

trust-provider-test:
	cargo test --locked --workspace provenance::tests::

trust-format-test:
	mkdir -p build/host
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) tests/trust/trust-store-test.c native/src/iu_trust_store.c native/src/iu_trust_transaction.c native/src/iu_trust_manager.c $(NATIVE_SOURCES) -o build/host/trust-store-test
	python3 tests/trust/trust-format-roundtrip.py build/host/trust-store-test
	@if $(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie $(NATIVE_INCLUDES) tests/trust/trust-store-test.c native/src/iu_trust_store.c native/src/iu_trust_transaction.c native/src/iu_trust_manager.c $(NATIVE_SOURCES) -o build/host/trust-store-sanitized-test >/dev/null 2>&1; then ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/trust/trust-format-roundtrip.py build/host/trust-store-sanitized-test; else echo 'Trust format sanitizers unavailable'; fi

origin-policy-test:
	cargo test --locked --workspace provenance::tests::signed_claims_are_authenticated_but_origin_remains_unverified
	cargo test --locked --workspace provenance::tests::revoked_anchor_has_valid_signature_but_is_not_trusted

.PHONY: trust-manager-test
trust-manager-test: host-build
	python3 tests/trust/trust-manager-test.py $(HOST_INSTALLER_HELPER)

trust-recovery-test: host-build
	$(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O2 $(NATIVE_INCLUDES) tests/trust/trust-transaction-test.c native/src/iu_trust_transaction.c -o build/host/trust-transaction-test
	./build/host/trust-transaction-test
	python3 tests/trust/trust-recovery-test.py $(HOST_INSTALLER_HELPER)
	@if $(CC) -std=c17 -Wall -Wextra -Wpedantic -Werror -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -DIU_INSTALLER_TESTING $(NATIVE_INCLUDES) native/src/iu_installer.c $(LIFECYCLE_SOURCE) $(POLICY_SOURCES) -o build/host/installer-helper-sanitized >/dev/null 2>&1; then ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/trust/trust-recovery-test.py build/host/installer-helper-sanitized; else echo 'Trust recovery sanitizers unavailable; strict C17 recovery fixtures completed.'; fi
