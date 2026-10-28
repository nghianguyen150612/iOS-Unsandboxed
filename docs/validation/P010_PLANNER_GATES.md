# P010 executable identity planner gates

## Offline implementation gates

Run on a host with Rust 1.74+, a strict-warning C17 compiler, Make, and Python 3:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
make build
make test
make native-test
make ipc-test
make packaging-test
make installer-test
make service-test
make adapter-test
make planner-test
make device-harness-test
make smoke-test
```

`make planner-test` compiles the planner and descriptor parser in strict C17 mode, creates all files under a private temporary fixture directory, and exercises normal and adversarial input. Where the compiler supports them, it repeats the fixtures with AddressSanitizer and UndefinedBehaviorSanitizer. Fixtures include a structurally parseable CodeDirectory, ad-hoc state, malformed and empty signatures, no `LC_CODE_SIGNATURE`, wrong architecture and Mach-O type, truncated/random/bad-magic input, huge `ncmds`, zero `cmdsize`, out-of-bounds signature offset, invalid SuperBlob index, corrupt CodeDirectory length, and duplicate signature commands. It also checks symlink/hard-link/type rejection, SHA-256 against the standard `abc` vector, same-size byte mutation, mode change, inode replacement, ABI and policy validation, fixture-only hypothetical eligibility, production denial, and no authorization. `planner-fixtures.py` creates only isolated temporary inputs. This finite set is not exhaustive parser verification.

Linux CI runs the full host test target, including planner fixtures. macOS Apple ARM64 CI runs the iOS 12.0+ CLI/native build, package inspection, archive integrity, and reproducibility checks. The Rust CLI links the planner as a static C archive; the package inspection gate checks architecture, minimum OS, dependencies, and signing metadata. Linux host binaries are not substituted for iOS executables.

## Device-only gates — NOT RUN

Physical device validation is not part of P010 offline completion. The reference iPad mini 2 Wi-Fi A1489 (`iPad4,4`), iOS 12.5.7, Amethyst rootful with Procursus bootstrap must still be used to collect authoritative installed Amethyst identity, independent hook/runtime evidence, SSH launch-path coverage, filesystem behavior, and runtime launch observations in a separately reviewed future phase. P010 does not attempt device launch or claim unsigned execution, signature acceptance, trust-cache support, kernel acceptance, unsandboxing, or Amethyst runtime integration.

P011 prerequisites are listed in [the planner architecture contract](../architecture/launch-preparation-planner.md#p011-prerequisites). P011 is not part of this work.
