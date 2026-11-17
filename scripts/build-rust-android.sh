#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

rustup target add aarch64-linux-android x86_64-linux-android
cargo ndk -t arm64-v8a -t x86_64 -o apps/android/app/src/main/jniLibs \
  build -p authenticator-bridge --release
