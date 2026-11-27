#!/usr/bin/env sh
# A4 (WP-114): reproducible build gate for the React/Vite application.
# Acceptance: prints "REPRODUCIBLE: <sha256-of-hashlist>" and exits 0;
# exits 1 if two clean builds differ.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WEBAPP_DIR=${WEBAPP_DIR:-"$REPO_ROOT/webapp"}

if [ ! -f "$WEBAPP_DIR/package.json" ]; then
  echo "ERROR: webapp package.json not found under $WEBAPP_DIR" >&2
  exit 2
fi

cd "$WEBAPP_DIR"
rm -rf dist-a dist-b dist
trap 'rm -rf dist-a dist-b dist' EXIT HUP INT TERM

npm run build
mv dist dist-a
npm run build
mv dist dist-b

hashlist() {
  find "$1" -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum |
    awk '{print $1}' |
    sha256sum |
    awk '{print $1}'
}

A=$(hashlist dist-a)
B=$(hashlist dist-b)
if [ "$A" = "$B" ]; then
  echo "REPRODUCIBLE: $A"
  exit 0
fi

echo "NON_REPRODUCIBLE: $A vs $B (fix build nondeterminism; do not weaken the gate)."
exit 1
