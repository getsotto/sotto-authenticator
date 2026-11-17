#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

cargo build -p authenticator-bridge --lib
./scripts/generate-bindings.sh
swiftc \
  -Xcc -fmodule-map-file=apps/ios/Authenticator/Generated/authenticator_bridgeFFI.modulemap \
  -I apps/ios/Authenticator/Generated \
  -L target/debug -lauthenticator_bridge \
  apps/ios/Authenticator/Generated/authenticator_bridge.swift \
  scripts/SwiftBridgeSmoke.swift \
  -o target/swift-bridge-smoke
DYLD_LIBRARY_PATH="$repo_root/target/debug${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  target/swift-bridge-smoke
