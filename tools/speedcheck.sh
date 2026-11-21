#!/bin/sh
# Compares 67z with 7-Zip on the same files (same threads, default level).
# Usage: tools/speedcheck.sh file [file...]     (needs 7z or 7zz in PATH)
set -eu
Z67="${Z67:-$(dirname "$0")/../target/release/67z}"
SZ="$(command -v 7zz || command -v 7z)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
t() { s=$(date +%s.%N); "$@" >/dev/null 2>&1; e=$(date +%s.%N); echo "$e - $s" | bc; }
pct() { echo "scale=1; 100 * $1 / $2" | bc; }
for f in "$@"; do
  a=$(t "$SZ" a -mx5 "$tmp/r.7z" "$f"); b=$(t "$Z67" a -bd -mx5 "$tmp/o.7z" "$f")
  c=$(t "$SZ" t "$tmp/r.7z");          d=$(t "$Z67" t -bd "$tmp/r.7z")
  echo "$(basename "$f"): compress $(pct "$a" "$b")% of 7-Zip speed (size $(stat -c%s "$tmp/o.7z") vs $(stat -c%s "$tmp/r.7z")), extract $(pct "$c" "$d")%"
  rm -f "$tmp"/*.7z
done
