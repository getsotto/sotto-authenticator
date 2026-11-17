#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

cargo build -p authenticator-bridge --lib
library="$repo_root/target/debug/libauthenticator_bridge.dylib"
if [[ ! -f "$library" ]]; then
  echo "Expected host library at $library" >&2
  exit 1
fi

cargo run -p authenticator-bindgen -- \
  generate --library "$library" --language swift --out-dir \
  apps/ios/Authenticator/Generated --no-format
cargo run -p authenticator-bindgen -- \
  generate --library "$library" --language kotlin --out-dir \
  apps/android/app/src/main/java --no-format

# UniFFI's no-format output has trailing spaces; normalize it so generated diffs
# stay clean without requiring a formatter installation on developer machines.
python3 - <<'PY'
from pathlib import Path

generated = [
    Path("apps/ios/Authenticator/Generated/authenticator_bridge.swift"),
    Path("apps/ios/Authenticator/Generated/authenticator_bridgeFFI.h"),
    Path("apps/ios/Authenticator/Generated/authenticator_bridgeFFI.modulemap"),
    Path("apps/android/app/src/main/java/dev/getsotto/authenticator/authenticator_bridge.kt"),
]
for path in generated:
    lines = path.read_text().splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    path.write_text("\n".join(line.rstrip() for line in lines) + "\n")
PY
