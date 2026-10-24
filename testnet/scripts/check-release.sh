#!/usr/bin/env bash
# Verify a release directory before install-node.sh installs from it.
#
#   check-release.sh DIR REV BINARY...
#
# DIR is what build-node-binaries.sh wrote. The release is accepted only if
#   - BUILD-INFO names tos_revision REV, the commit the operator pinned, so a
#     release of another commit is refused even when it is self-consistent;
#   - SHA256SUMS lists every other file in DIR and each one verifies;
#   - every BINARY named (the role's binaries) is present.
# SHA256SUMS is written on the same host as the binaries, so it detects damage
# and mix-ups, not a deliberate edit: compare it with the other hosts' (the
# build is reproducible for one commit and one toolchain) to detect that.
set -euo pipefail

die() { echo "check-release: $*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: check-release.sh DIR REV BINARY..."
DIR=$1 REV=$2
shift 2
[[ "$REV" =~ ^[0-9a-f]{40}$ ]] || die "the revision must be a full 40-character commit id"
[ -d "$DIR" ] || die "$DIR is not a directory"
[ -f "$DIR/SHA256SUMS" ] || die "$DIR/SHA256SUMS is missing; install only a verified release"
[ -f "$DIR/BUILD-INFO" ] || die "$DIR/BUILD-INFO is missing; it names the commit the release was built from"

built=$(awk '$1 == "tos_revision" {print $2}' "$DIR/BUILD-INFO")
[ -n "$built" ] || die "$DIR/BUILD-INFO names no tos_revision"
[ "$built" = "$REV" ] || die "$DIR was built from $built, not the pinned $REV"

(cd "$DIR" && sha256sum --check --strict --quiet SHA256SUMS) || die "release digest check failed"
for path in "$DIR"/*; do
  name=$(basename "$path")
  case "$name" in SHA256SUMS | BUILD-INFO) continue ;; esac
  awk -v n="$name" '$2 == n {found = 1} END {exit !found}' "$DIR/SHA256SUMS" \
    || die "$name is not covered by SHA256SUMS"
done
for name in "$@"; do
  [ -f "$DIR/$name" ] || die "the release lacks $name"
done
