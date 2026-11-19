# Sotto Authenticator

Sotto Authenticator is an open-source, project-aware authenticator for people who manage work and personal accounts across multiple projects and instances.

## Project status

This repository is at the native platform and shared-core proof stage. The Android shell calls the Rust library through generated UniFFI bindings, displays a fixed synthetic RFC 6238 vector, and hosts a disposable Android Keystore authentication experiment. The iOS shell hosts an experiment for authentication-gated Secure Enclave signing with a disposable key; it does not display the TOTP vector. Both apps include a temporary encrypted snapshot interoperability experiment that uses a public synthetic key only; it is not a backup format or a native key handoff. The apps do not accept user-provided seeds or store accounts, synchronize data, or connect to a service. See the [TOTP core note](docs/engineering/totp-core.md), [native integration evidence](docs/engineering/native-totp-integration.md), [Android key-access findings](docs/engineering/android-device-bound-key-access.md), [iOS key-access findings](docs/engineering/ios-device-bound-key-access.md), and [snapshot interoperability findings](docs/engineering/cross-platform-encrypted-snapshot.md).

The agreed product direction is mobile first, native on iOS and Android, with a shared Rust domain core. The current spike exists to validate that platform boundary before account, cryptography, storage, and user experience decisions are implemented. See [architecture decisions](docs/decisions/0001-native-clients-and-shared-rust-core.md), the [Step 1 threat model and architecture gate](docs/engineering/step-1-threat-model-and-architecture-gate.md), the [native vault-key protection findings](docs/engineering/native-vault-key-protection.md), the [proposed local vault key hierarchy](docs/decisions/0003-local-vault-key-hierarchy.md), the [local vault design options](docs/engineering/local-vault-key-hierarchy-options.md), and the [Step 2 local vault plan](docs/engineering/step-2-local-vault-plan.md).

## Local development

The build scripts require macOS with Xcode 26.6 command line tools, Rust 1.99.0, Android SDK platform 37, Android NDK 27.1, `cargo-ndk` 4.1.2, XcodeGen 2.46.0, Java 17 or later, and the Gradle wrapper included here.

```sh
cargo test -p authenticator-bridge
./scripts/generate-bindings.sh
./scripts/smoke-swift-bridge.sh
./scripts/build-rust-ios.sh
xcodegen generate --spec apps/ios/project.yml --project apps/ios
xcodebuild -project apps/ios/AuthenticatorSpike.xcodeproj \
  -scheme AuthenticatorSpike \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
xcodebuild test -project apps/ios/AuthenticatorSpike.xcodeproj \
  -scheme AuthenticatorSpike \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  CODE_SIGNING_ALLOWED=NO
./scripts/build-rust-android.sh
./apps/android/gradlew -p apps/android assembleDebug
./apps/android/gradlew -p apps/android connectedAndroidTest
./scripts/smoke-cross-platform-snapshot.sh
```

The Android app can be launched on a connected emulator with `adb install -r app/build/outputs/apk/debug/app-debug.apk` followed by `adb shell am start -n dev.getsotto.authenticator/.MainActivity`.

Generated bindings are committed for review and reproducible native builds. Regenerate them only through the script. Native libraries and build outputs are generated locally and are not committed.

## License

Licensed under Apache License 2.0. See [LICENSE](LICENSE).
