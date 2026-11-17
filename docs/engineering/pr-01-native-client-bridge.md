# PR 01: native client and shared Rust bridge

- Status: implementation and local simulator/emulator verification complete; [PR #1 is open](https://github.com/getsotto/sotto-authenticator/pull/1)
- Scope: prove native iOS and Android shells call one Rust library through generated bindings
- Related decision: [ADR 0001](../decisions/0001-native-clients-and-shared-rust-core.md)

## User-visible result

Each minimal app displays a fixed message returned by the same Rust function. This is a wiring proof only. It introduces no MFA enrollment, OTP generation, account storage, credentials, network access, analytics, or permissions.

## Implementation contract

1. Workspace root owns an isolated `authenticator-bridge` Rust library and a host-only `authenticator-bindgen` tool. The UniFFI CLI dependency must not be enabled in native targets.
2. UniFFI exports a minimal, no-secret function. Generated Swift/Kotlin source is checked in; generated native binaries are not. The generator is a host-only workspace tool, not part of native target dependency graphs.
3. iOS is a SwiftUI app linked to a locally built iOS XCFramework.
4. Android is a Compose app loading the Rust library through UniFFI's Kotlin/JNA binding. APK ABI filters match the Rust libraries built for `arm64-v8a` and `x86_64`.
5. Scripts regenerate bindings and build platform libraries. Gradle wrapper pins the Android build distribution.
6. No backend, remote service, account model, persistent data, or production security claim is added.

## Review sequence

Review Rust API and generated binding diffs first, then iOS linkage, then Android linkage and native-library packaging, then build/reproduction documentation. Keep the PR focused on proving the shared-core seam. Do not expand it into authenticator behavior.

## Verification evidence

Record the exact result and tool version for each check in the PR body:

- `cargo test -p authenticator-bridge`
- `./scripts/generate-bindings.sh` twice; second run has no tracked diff
- `./scripts/smoke-swift-bridge.sh`
- `./scripts/build-rust-ios.sh` and simulator app build/launch
- `./scripts/build-rust-android.sh` and Gradle assemble/emulator launch
- Inspect the APK native-library entries to confirm supported ABIs match the built Rust libraries.
- `git diff --check`

Local evidence on 2026-11-16: `cargo test -p authenticator-bridge` passed (1 test); Swift bridge smoke printed the shared Rust message; repeated binding generation produced identical SHA-256 hashes for all four generated files; iOS simulator build and launch passed on iPhone 17 Pro / iOS 26.5; Android `assembleDebug`, install, and launch passed on Pixel 10 / API 37. Physical devices were not tested.

Copilot review follow-up on 2026-11-17: `./gradlew assembleDebug` passed with ABI filters set; APK inspection confirmed native libraries are packaged only for `arm64-v8a` and `x86_64`, with `libauthenticator_bridge.so` present in both.

Simulator and emulator evidence must be labeled accurately; neither implies a physical-device test. If either app cannot be built and launched, keep the PR in draft and state the exact blocker.

## Risks and decisions deferred

The Kotlin binding currently uses JNA. Confirm its Android packaging and licensing implications before production use. This PR does not select secure storage APIs, define key backup or recovery, set cryptographic formats, define migration from existing authenticators, or implement desktop/CLI clients. Those decisions remain separate reviewable PRs.
