#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

./scripts/build-rust-android.sh
swift_envelope="$(./scripts/smoke-swift-bridge.sh | sed -n 's/^ENVELOPE_BASE64=//p')"
if [[ -z "$swift_envelope" ]]; then
  echo "Swift bridge did not emit a synthetic snapshot envelope." >&2
  exit 1
fi

./apps/android/gradlew -p apps/android connectedAndroidTest
adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk >/dev/null
adb shell am start -S -n dev.getsotto.authenticator/.MainActivity \
  --es dev.getsotto.authenticator.extra.SYNTHETIC_ENVELOPE "$swift_envelope" >/dev/null
sleep 2
android_decrypt_status=""
for _ in 1 2 3; do
  adb shell uiautomator dump /sdcard/window.xml >/dev/null
  android_decrypt_status="$(adb shell cat /sdcard/window.xml | python3 -c '
import sys
import xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
print(next((node.get("text", "") for node in root.iter("node") if node.get("text", "").startswith("Cross-platform synthetic snapshot")), ""))
')"
  [[ "$android_decrypt_status" == "Cross-platform synthetic snapshot decrypted and matched." ]] && break
  sleep 1
done
if [[ "$android_decrypt_status" != "Cross-platform synthetic snapshot decrypted and matched." ]]; then
  echo "Android did not decrypt the envelope produced by the Swift binding." >&2
  exit 1
fi
echo "Android decrypted the runtime envelope produced by Swift."

adb shell am start -S -n dev.getsotto.authenticator/.MainActivity \
  --ez dev.getsotto.authenticator.extra.ENCRYPT_SYNTHETIC_SNAPSHOT true >/dev/null
sleep 2
android_envelope=""
for _ in 1 2 3 4; do
  adb shell uiautomator dump /sdcard/window.xml >/dev/null
  android_envelope="$(adb shell cat /sdcard/window.xml | python3 -c '
import sys
import xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
print(next((node.get("text", "") for node in root.iter("node") if node.get("text", "").startswith("U09U")), ""))
')"
  [[ -n "$android_envelope" ]] && break
  adb shell input swipe 540 2100 540 700 400
done
if [[ -z "$android_envelope" ]]; then
  echo "Android app did not emit a synthetic snapshot envelope." >&2
  exit 1
fi

DYLD_LIBRARY_PATH="$repo_root/target/debug${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  target/swift-bridge-smoke --decrypt-base64 "$android_envelope"
