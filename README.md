# Sotto Authenticator

Sotto Authenticator is an open-source, project-aware authenticator for people who manage work and personal accounts across multiple projects and instances.

## Project status

This repository is at the native platform and shared-core proof stage. The iOS and Android shells call the same Rust library through generated UniFFI bindings. The shared core can generate deterministic TOTP codes from caller-supplied parameters and time; the apps do not yet store accounts or secrets, synchronize data, or connect to a service. See the [TOTP core note](docs/engineering/totp-core.md).

The agreed product direction is mobile first, native on iOS and Android, with a shared Rust domain core. The current spike exists to validate that platform boundary before account, cryptography, storage, and user experience decisions are implemented. See [architecture decisions](docs/decisions/0001-native-clients-and-shared-rust-core.md) and [PR 01 engineering plan](docs/engineering/pr-01-native-client-bridge.md).

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
./scripts/build-rust-android.sh
cd apps/android && ./gradlew assembleDebug
```

The Android app can be launched on a connected emulator with `adb install -r app/build/outputs/apk/debug/app-debug.apk` followed by `adb shell am start -n dev.getsotto.authenticator/.MainActivity`.

Generated bindings are committed for review and reproducible native builds. Regenerate them only through the script. Native libraries and build outputs are generated locally and are not committed.

## License

Licensed under Apache License 2.0. See [LICENSE](LICENSE).
