# Native TOTP integration spike

PR 03 proves that both native shells call the same Rust implementation through
generated UniFFI bindings. Each app displays the RFC 6238 Appendix B SHA-1
example for timestamp 59, a 30-second period, and 8 digits. The expected code
is `94287082`.

The apps also pass the invalid synthetic input `NOT*BASE32` and show a generic
safe-rejection message. Neither input is entered by a user, persisted, or
written to logs. The timestamp is fixed; the clients do not read the clock or
implement TOTP themselves.

## Native packaging

- iOS uses `./scripts/build-rust-ios.sh` to build the Rust library for arm64
  device and simulator targets and package them into
  `build/ios/AuthenticatorCore.xcframework`.
- Android uses `./scripts/build-rust-android.sh` and `cargo-ndk` to package
  arm64-v8a and x86_64 shared libraries under `apps/android/app/src/main/jniLibs`.
  The APK ABI filters remain restricted to those two architectures.
- UniFFI generated bindings live in the iOS and Android source trees and are
  regenerated with `./scripts/generate-bindings.sh`.

## Reproduce

From the repository root on macOS with the documented toolchains installed:

```sh
cargo test --locked --workspace
./scripts/generate-bindings.sh
./scripts/build-rust-ios.sh
xcodegen generate --spec apps/ios/project.yml --project apps/ios
xcodebuild -project apps/ios/AuthenticatorSpike.xcodeproj \
  -scheme AuthenticatorSpike \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.3.1' build
./scripts/build-rust-android.sh
cd apps/android && ./gradlew assembleDebug
```

Install and launch the iOS build in the selected simulator, or install the
Android APK on an API 37 emulator. Confirm both show `94287082` and the generic
invalid-input rejection. Inspect the Android APK with `unzip -l` to confirm it
contains only `lib/arm64-v8a/libauthenticator_bridge.so` and
`lib/x86_64/libauthenticator_bridge.so`.

## Evidence and limits

Verified locally with Xcode 26.6 and the iPhone 17 Pro simulator on iOS 26.3.1;
Android emulator API 37 (Android 17), Gradle 9.3.1, and the included Gradle
wrapper. Both builds and app launches succeeded. UI hierarchy inspection
confirmed the expected code and safe error text on each platform. The Android
APK contained both configured ABIs, and a log scan found neither synthetic
input string. Physical devices were not tested.

This spike has no enrollment, editable seed, account list, real-time countdown,
credential storage, backup, clipboard, or online verification. It demonstrates
native-to-Rust wiring and result parity; it is not production UX or a security
assessment.
