#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"
export LC_ALL=C

# The existing snapshot experiment is a separate, synthetic API used by both apps.
expected_entry_points='func_decrypt_test_snapshot
func_encrypt_test_snapshot
func_generate_totp_code
func_platform_message'

check_entry_points() {
  local label="$1" actual
  actual="$(sed -nE 's/(^_?|.*[^[:alnum:]_])uniffi_authenticator_bridge_fn_([[:alnum:]_]+).*/\2/p' | sort -u)"
  if ! diff -u <(printf '%s\n' "$expected_entry_points") - <<< "$actual"; then
    echo "Unexpected UniFFI entry points in $label" >&2
    return 1
  fi
}

check_target() {
  local target="$1" library="$2"
  local build_inputs="target/$target/release/libauthenticator_bridge.d"
  local dependencies
  dependencies="$(cargo tree --locked -p authenticator-bridge --target "$target" \
    --edges normal --prefix depth --format ' {p} [{f}]')"
  # UniFFI already brings in tempfile. Only the bridge's direct use is test-only.
  if grep -E '^([0-9]+ (bip39|rusqlite|libsqlite3-sys)|1 tempfile) ' <<< "$dependencies"; then
    echo "Portable vault test dependency in $target" >&2
    return 1
  fi

  # The mobile bridge uses these crates too. Keep the fixture-only features out.
  if grep -E \
    -e '^[0-9]+ (aes|aes-gcm|sha2) v[^ ]+ \[([^]]*,)?zeroize(,|])' \
    -e '^[0-9]+ serde v[^ ]+ \[([^]]*,)?rc(,|])' \
    -e '^[0-9]+ zeroize v[^ ]+ \[([^]]*,)?serde(,|])' <<< "$dependencies"; then
    echo "Portable vault test dependency feature in $target" >&2
    return 1
  fi

  if ! grep -q '/authenticator-bridge/src/lib\.rs' "$build_inputs"; then
    echo "Missing bridge build inputs for $target. Run the native build scripts first." >&2
    return 1
  fi
  if grep -E '/authenticator-bridge/src/portable_vault(\.rs|/)' "$build_inputs"; then
    echo "Portable vault source compiled for $target" >&2
    return 1
  fi

  # Xcode's nm can read the native symbols without decoding newer Rust LLVM bitcode.
  xcrun nm --no-llvm-bc --defined-only --extern-only --format=just-symbols "$library" \
    | check_entry_points "$target"
  echo "Checked build inputs, dependencies and UniFFI entry points for $target"
}

ios_framework="build/ios/AuthenticatorCore.xcframework"
android_libraries="apps/android/app/src/main/jniLibs"
check_target aarch64-apple-ios "$ios_framework/ios-arm64/libauthenticator_bridge.a"
check_target aarch64-apple-ios-sim "$ios_framework/ios-arm64-simulator/libauthenticator_bridge.a"
check_target aarch64-linux-android "$android_libraries/arm64-v8a/libauthenticator_bridge.so"
check_target x86_64-linux-android "$android_libraries/x86_64/libauthenticator_bridge.so"

for binding in \
  apps/ios/Authenticator/Generated/authenticator_bridge.swift \
  apps/ios/Authenticator/Generated/authenticator_bridgeFFI.h \
  apps/android/app/src/main/java/dev/getsotto/authenticator/authenticator_bridge.kt; do
  check_entry_points "${binding##*/}" < "$binding"
  echo "Checked UniFFI entry points in ${binding##*/}"
done
