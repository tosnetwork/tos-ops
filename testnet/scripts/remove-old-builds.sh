#!/usr/bin/env bash
# Remove the build trees and releases of revisions a host no longer runs. Run as root.
#
#   remove-old-builds.sh --keep <tos commit>
#
# Removes /var/lib/tos-build/build-<rev> and release-<rev> for every full 40-hex
# revision other than --keep, and /opt/tos-testnet.old. Keeps the kept revision,
# every log file, build-tosctl.sh and the /opt/tos-testnet.prev-* bundles. Refuses
# when the kept release is missing or a running node's executable is under
# /var/lib/tos-build. Copy the old releases' SHA256SUMS and BUILD-INFO off the host
# first if they are wanted as provenance.
set -euo pipefail

die() { echo "remove-old-builds: $*" >&2; exit 1; }

# REMOVE_OLD_BUILDS_TEST=1 lets the tests run it unprivileged on scratch directories.
[ "$(id -u)" = 0 ] || [ "${REMOVE_OLD_BUILDS_TEST:-}" = 1 ] || die "run as root"
KEEP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$KEEP" =~ ^[0-9a-f]{40}$ ]] || die "--keep must be a full 40-character commit id"
WORK=${TOS_BUILD_ROOT:-/var/lib/tos-build}
OPT=${TOS_OPT_ROOT:-/opt}
if [ -d "$WORK" ]; then
  [ -d "$WORK/release-$KEEP" ] || die "$WORK/release-$KEEP is missing; refusing"
fi
for pid in $(pidof validator-engine dht-server 2>/dev/null || true); do
  case "$(readlink "/proc/$pid/exe")" in
    "$WORK"/*) die "a node runs from $WORK; install its release first" ;;
  esac
done

before=$(df --output=used -B1M "$WORK" 2>/dev/null | tail -1 || echo 0)
if [ -d "$WORK" ]; then
  for dir in "$WORK"/build-* "$WORK"/release-*; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    rev=${name#*-}
    [[ "$rev" =~ ^[0-9a-f]{40}$ ]] || continue
    [ "$rev" = "$KEEP" ] && continue
    rm -rf -- "$dir"
    echo "removed $name"
  done
fi
if [ -d "$OPT/tos-testnet.old" ]; then
  rm -rf -- "$OPT/tos-testnet.old"
  echo "removed $OPT/tos-testnet.old"
fi
after=$(df --output=used -B1M "$WORK" 2>/dev/null | tail -1 || echo 0)
echo "freed $((before - after)) MiB"
