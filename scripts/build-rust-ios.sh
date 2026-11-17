#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

ios_device="aarch64-apple-ios"
ios_simulator="aarch64-apple-ios-sim"
rustup target add "$ios_device" "$ios_simulator"
cargo build -p authenticator-bridge --release --target "$ios_device"
cargo build -p authenticator-bridge --release --target "$ios_simulator"

output="$repo_root/build/ios/AuthenticatorCore.xcframework"
rm -rf "$output"
xcodebuild -create-xcframework \
  -library "target/$ios_device/release/libauthenticator_bridge.a" \
  -headers apps/ios/Authenticator/Generated \
  -library "target/$ios_simulator/release/libauthenticator_bridge.a" \
  -headers apps/ios/Authenticator/Generated \
  -output "$output"
