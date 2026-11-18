#!/usr/bin/env bash
# Install tosctl from a release directory fetch-release.py wrote. Run as root.
#
#   install-tosctl.sh --release DIR --rev COMMIT
#
# DIR is the result of `fetch-release.py --role tosctl --rev COMMIT --out DIR`:
# tosctl, SHA256SUMS and BUILD-INFO. This is the production path, which needs
# no Rust toolchain on the host; the testnet builds tosctl on each host with
# build-tosctl.sh. Nothing is downloaded or built here. The install is refused
# unless
#   - check-release.sh accepts DIR for the binary tosctl: BUILD-INFO names
#     tos_revision COMMIT and SHA256SUMS covers and verifies every file;
#   - BUILD-INFO carries the release tag and the provenance digest
#     fetch-release.py recorded, so the installed record names its source;
#   - the copy staged for installation has the SHA-256 that SHA256SUMS lists
#     for tosctl;
#   - that staged copy runs on this host and `--version` prints the exact line
#     COMMIT_ID: COMMIT.
# The verified copy is staged beside its destination and renamed into place,
# so /usr/local/bin/tosctl is always either the old binary or the new one. A
# tosctl process already running keeps the old binary until it is restarted.
# /etc/tos/TOSCTL-BUILD-INFO then records tos_revision and sha256, as
# build-tosctl.sh writes them, followed by the release's source and recipe
# lines and the time of the install.
#
# Nothing here touches a key, a vault or a service.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# TOS_INSTALL_PREFIX roots every host path under a directory, for the tests
# that run this script unprivileged on a fake host. A run whose effective uid
# is 0 refuses it. The uid comes from the absolute /usr/bin/id: bash takes an
# EUID passed in the environment as an ordinary variable, and a PATH tool can
# be replaced.
PREFIX=${TOS_INSTALL_PREFIX:-}
BIN=$PREFIX/usr/local/bin
ETC=$PREFIX/etc/tos

die() { echo "install-tosctl: $*" >&2; exit 1; }
if [ -n "$PREFIX" ] && [ "$(/usr/bin/id -u)" = 0 ]; then die "TOS_INSTALL_PREFIX is for unprivileged tests only; unset it"; fi

[ "$(id -u)" = 0 ] || die "run as root"
RELEASE="" REV=""
while [ $# -gt 0 ]; do
  case "$1" in
    --release) [ $# -ge 2 ] || die "--release needs a directory"; RELEASE=$2; shift 2 ;;
    --rev) [ $# -ge 2 ] || die "--rev needs a commit id"; REV=$2; shift 2 ;;
    *) die "unknown option $1; usage: install-tosctl.sh --release DIR --rev COMMIT" ;;
  esac
done
[ -n "$RELEASE" ] || die "--release DIR is required: the directory fetch-release.py --role tosctl wrote"
[[ "$REV" =~ ^[0-9a-f]{40}$ ]] || die "--rev must be a full 40-character commit id"
[ -d "$RELEASE" ] || die "$RELEASE is not a directory"

bash "$HERE/check-release.sh" "$RELEASE" "$REV" tosctl || die "release $RELEASE refused"
[ ! -L "$RELEASE/tosctl" ] || die "$RELEASE/tosctl is a symbolic link, not the fetched binary"

# The lines fetch-release.py writes: without them the directory is not a
# fetched release, and the installed record would name no source.
INFO=$RELEASE/BUILD-INFO
TAG=$(awk '$1 == "source" && $2 == "github-release" && NF == 3 {print $3}' "$INFO")
[ -n "$TAG" ] || die "$INFO names no 'source github-release <tag>'; install only what fetch-release.py --role tosctl wrote"
[ "$(wc -l <<<"$TAG")" = 1 ] || die "$INFO names more than one source release"
PROVENANCE=$(awk '$1 == "provenance_sha256" && NF == 2 {print $2}' "$INFO")
[[ "$PROVENANCE" =~ ^[0-9a-f]{64}$ ]] || die "$INFO carries no provenance_sha256 digest; install only what fetch-release.py --role tosctl wrote"
EXPECTED=$(awk '$2 == "tosctl" {print $1}' "$RELEASE/SHA256SUMS")
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || die "$RELEASE/SHA256SUMS does not list tosctl exactly once"

install -d -m 0755 -o root -g root "$BIN" "$ETC" || die "cannot create $BIN and $ETC"
STAGED_BIN="" STAGED_INFO="" RECORD=""
cleanup() {
  local path
  for path in "$STAGED_BIN" "$STAGED_INFO" "$RECORD"; do
    if [ -n "$path" ]; then rm -f -- "$path"; fi
  done
}
trap cleanup EXIT
STAGED_BIN=$(mktemp "$BIN/.tosctl.XXXXXX") || die "cannot create a file in $BIN"
STAGED_INFO=$(mktemp "$ETC/.TOSCTL-BUILD-INFO.XXXXXX") || die "cannot create a file in $ETC"
RECORD=$(mktemp) || die "cannot create a temporary file"

# Everything below checks the staged copy: the bytes that were verified are
# the bytes that are renamed into place.
install -m 0755 -o root -g root "$RELEASE/tosctl" "$STAGED_BIN" || die "cannot copy $RELEASE/tosctl to $BIN"
ACTUAL=$(sha256sum "$STAGED_BIN" | cut -d' ' -f1)
[ "$ACTUAL" = "$EXPECTED" ] \
  || die "the staged tosctl has sha256 $ACTUAL, but $RELEASE/SHA256SUMS lists $EXPECTED"
STATUS=0
REPORTED=$("$STAGED_BIN" --version 2>&1) || STATUS=$?
[ "$STATUS" = 0 ] \
  || die "tosctl --version failed on this host (exit $STATUS): $(tail -c 300 <<<"$REPORTED"); tosctl needs libssl.so.3 and libcrypto.so.3 (Ubuntu package libssl3t64)"
grep -qxF "COMMIT_ID: $REV" <<<"$REPORTED" \
  || die "tosctl --version does not report COMMIT_ID: $REV: $(tail -c 300 <<<"$REPORTED")"

{
  echo "tos_revision $REV"
  echo "sha256 $EXPECTED"
  awk '$1 != "tos_revision" && $1 != "sha256" && $1 != "installed"' "$INFO"
  echo "installed $(date -u +%FT%TZ)"
} >"$RECORD"
install -m 0644 -o root -g root "$RECORD" "$STAGED_INFO" || die "cannot write the build record in $ETC"

mv -fT -- "$STAGED_BIN" "$BIN/tosctl" || die "cannot rename the staged tosctl to $BIN/tosctl; the installed tosctl is unchanged"
STAGED_BIN=""
mv -fT -- "$STAGED_INFO" "$ETC/TOSCTL-BUILD-INFO" \
  || die "tosctl is installed, but $ETC/TOSCTL-BUILD-INFO could not be written; run this command again"
STAGED_INFO=""
echo "installed $BIN/tosctl (sha256 $EXPECTED) from release $TAG at $REV"
