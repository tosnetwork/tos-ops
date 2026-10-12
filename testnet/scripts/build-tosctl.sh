#!/usr/bin/env bash
# Build tosctl on the validator host that will run it. Run as root.
#
#   build-tosctl.sh --rev <tos commit> [--jobs N]
#
# Run it after build-node-binaries.sh, which leaves the tos checkout in
# /var/lib/tos-build/tos. The checkout must be at --rev with no local changes;
# tosctl comes from the same commit as the node it drives. The Rust toolchain
# is installed by tos scripts/install-rust-toolchain.sh at the version tos
# pins, and the build uses the committed Cargo.lock (--locked). The binary
# goes to /usr/local/bin/tosctl, with its digest in /etc/tos/TOSCTL-BUILD-INFO.
set -euo pipefail

WORK=/var/lib/tos-build
SRC=$WORK/tos
REV="" JOBS=""
die() { echo "build-tosctl: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
while [ $# -gt 0 ]; do
  case "$1" in
    --rev) REV=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$REV" =~ ^[0-9a-f]{40}$ ]] || die "--rev must be a full 40-character commit id"
[ -d "$SRC/.git" ] || die "$SRC is missing; run build-node-binaries.sh --rev $REV first"
[ "$(git -C "$SRC" rev-parse HEAD)" = "$REV" ] || die "$SRC is not at $REV"
[ -z "$(git -C "$SRC" status --porcelain)" ] || die "$SRC has local changes"
if [ -z "$JOBS" ]; then
  JOBS=$(nproc)
  [ "$JOBS" -le 4 ] || JOBS=4
fi

export HOME=/root
bash "$SRC/scripts/install-rust-toolchain.sh"
# shellcheck disable=SC1091
. /root/.cargo/env
(cd "$SRC/tosctl/src" && CARGO_TARGET_DIR=$WORK/tosctl-target cargo build --release --locked -p tosctl -j "$JOBS") \
  >"$WORK/tosctl-build-$REV.log" 2>&1 || die "build failed; see $WORK/tosctl-build-$REV.log"
install -m 0755 -o root -g root "$WORK/tosctl-target/release/tosctl" /usr/local/bin/tosctl
install -d -m 0755 /etc/tos
{
  echo "tos_revision $REV"
  echo "sha256 $(sha256sum /usr/local/bin/tosctl | cut -d' ' -f1)"
  echo "built $(date -u +%FT%TZ)"
} > /etc/tos/TOSCTL-BUILD-INFO
/usr/local/bin/tosctl --version
