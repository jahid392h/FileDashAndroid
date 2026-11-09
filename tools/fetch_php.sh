#!/usr/bin/env bash
# Downloads a static PHP CLI (linux aarch64, runs on Android) and stores it as the APK's native lib "libphp.so".
# Override with:  PHP_URL=https://…/php-8.3.x-cli-linux-aarch64.tar.gz tools/fetch_php.sh
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=app/src/main/jniLibs/arm64-v8a/libphp.so
BASE=https://dl.static-php.dev/static-php-cli/common
mkdir -p "$(dirname "$OUT")"

URL="${PHP_URL:-}"
if [ -z "$URL" ]; then
  NAME=$(curl -fsSL "$BASE/?format=json" | python3 -c '
import sys, json, re
items = json.load(sys.stdin)
names = [(i.get("name") if isinstance(i, dict) else i) for i in items]
rx = re.compile(r"^php-(8)\.(\d+)\.(\d+)-cli-linux-aarch64\.tar\.gz$")
c = [(int(m.group(2)), int(m.group(3)), n) for n in names if n and (m := rx.match(n))]
pref = [x for x in c if x[0] == 3] or c            # prefer 8.3.x (stable), else newest
print(sorted(pref)[-1][2] if pref else "")
') || true
  [ -n "$NAME" ] || { echo "Could not find a php-8.x cli-linux-aarch64 build at $BASE — set PHP_URL=…" >&2; exit 1; }
  URL="$BASE/$NAME"
fi

echo "Downloading $URL"
TMP=$(mktemp -d)
curl -fsSL "$URL" -o "$TMP/php.tgz"
tar -xzf "$TMP/php.tgz" -C "$TMP"
BIN=$(find "$TMP" -type f -name php -perm -u+x | head -n1); [ -n "$BIN" ] || BIN=$(find "$TMP" -type f -name php | head -n1)
[ -n "$BIN" ] || { echo "php binary not found inside the archive" >&2; exit 1; }
cp "$BIN" "$OUT"; chmod +x "$OUT"
file "$OUT" | grep -qi "aarch64" || { echo "Not an aarch64 binary: $(file "$OUT")" >&2; exit 1; }
ls -l "$OUT"
