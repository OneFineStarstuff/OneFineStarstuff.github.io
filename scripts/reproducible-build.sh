#!/usr/bin/env sh
# A4 (WP-114): reproducible build gate.
# Acceptance: prints "REPRODUCIBLE: <sha256-of-hashlist>" and exits 0; exits 1 otherwise.
set -eu
cd "$(dirname "$0")/.."
for f in dist-a dist-b dist; do rm -rf "$f"; done

npm run build
mv dist dist-a
npm run build
mv dist dist-b

hashlist() {
  find "$1" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | awk '{print $1}' | sha256sum | awk '{print $1}'
}

A=$(hashlist dist-a)
B=$(hashlist dist-b)
if [ "$A" = "$B" ]; then
  echo "REPRODUCIBLE: $A"
  rm -rf dist-a dist-b
  exit 0
fi
echo "NON_REPRODUCIBLE: $A vs $B (fix bundler nondeterminism; do not weaken the gate)."
exit 1
