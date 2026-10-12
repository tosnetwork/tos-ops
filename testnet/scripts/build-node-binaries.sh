#!/usr/bin/env bash
# Build the node binaries from source on the host that will run them. Run as root.
#
#   build-node-binaries.sh --rev <tos commit> --role validator|fullnode|dht [--jobs N] [--with-dht]
#
# Every host compiles its own binaries from the pinned tos commit instead of
# receiving them from another machine. A binary built for one CPU can stop
# with SIGILL on another: RocksDB defaults to -march=native, and a build made
# on a newer Xeon used instructions these hosts do not have. The build here
# follows tos CI and targets x86-64-v2 (TOS_ARCH and RocksDB PORTABLE), so a
# provider that live-migrates the VM to an older CPU does not break it either.
#
# Steps: install the prerequisites from tos BUILD.md; install clang-21 with
# tos scripts/install-llvm-toolchain.sh, which checks the apt.llvm.org key
# committed in tos; clone tos at --rev with its submodules; configure a
# production Release build; build the role's targets; write
# /var/lib/tos-build/release-<rev>/ with the binaries, SHA256SUMS and
# BUILD-INFO. Install them with `install-node.sh binaries --release <dir>`.
#
# The source checkout is reused on a rerun only if it is at --rev with no
# local changes; otherwise the script refuses.
set -euo pipefail

TOS_REPO_URL=${TOS_REPO_URL:-https://github.com/tosnetwork/tos.git}
WORK=/var/lib/tos-build
REV="" ROLE="" JOBS="" WITH_DHT=0
die() { echo "build-node-binaries: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
while [ $# -gt 0 ]; do
  case "$1" in
    --rev) REV=$2; shift 2 ;;
    --role) ROLE=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    --with-dht) WITH_DHT=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$REV" =~ ^[0-9a-f]{40}$ ]] || die "--rev must be a full 40-character commit id"
case "$ROLE" in
  validator|fullnode) TARGETS=(validator-engine validator-engine-console lite-client generate-random-id tos-pq-consensus-key) ;;
  dht) TARGETS=(dht-server generate-random-id) ;;
  *) die "--role must be validator, fullnode or dht" ;;
esac
[ "$WITH_DHT" = 1 ] && TARGETS+=(dht-server)

# One compile job per 2.5 GiB of memory, at most one per core: the large
# translation units need about 2 GiB each.
if [ -z "$JOBS" ]; then
  mem_gib=$(awk '/MemTotal/ {print int($2 / 1048576)}' /proc/meminfo)
  JOBS=$(( mem_gib * 2 / 5 ))
  [ "$JOBS" -ge 1 ] || JOBS=1
  [ "$JOBS" -le "$(nproc)" ] || JOBS=$(nproc)
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  build-essential git cmake ninja-build ccache autoconf automake libtool texinfo \
  pkg-config python3 python3-dev libgflags-dev libreadline-dev libgsl-dev libblas-dev \
  libgslcblas0 libjemalloc-dev libssl-dev libgmp-dev gperf gawk wget curl lsb-release \
  software-properties-common gnupg >/dev/null

install -d -m 0755 "$WORK"
SRC=$WORK/tos
if [ -d "$SRC/.git" ]; then
  git -C "$SRC" fetch -q origin
  [ -z "$(git -C "$SRC" status --porcelain)" ] || die "$SRC has local changes"
else
  git clone -q "$TOS_REPO_URL" "$SRC"
fi
git -C "$SRC" -c advice.detachedHead=false checkout -q "$REV"
[ "$(git -C "$SRC" rev-parse HEAD)" = "$REV" ] || die "checkout is not at $REV"
git -C "$SRC" submodule sync -q --recursive
git -C "$SRC" submodule update -q --init --recursive

command -v clang++-21 >/dev/null || bash "$SRC/scripts/install-llvm-toolchain.sh" 21

BUILD=$WORK/build-$REV
cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
  -DTOS_ARCH=x86-64-v2 -DPORTABLE=x86-64-v2 \
  -DTOS_USE_JEMALLOC=ON -DTOS_PRODUCTION_BUILD=ON >"$WORK/cmake-$REV.log"
echo "building ${TARGETS[*]} with $JOBS jobs"
cmake --build "$BUILD" --parallel "$JOBS" --target "${TARGETS[@]}" >"$WORK/build-$REV.log" 2>&1 \
  || die "build failed; see $WORK/build-$REV.log"

declare -A PATHS=(
  [validator-engine]=validator-engine/validator-engine
  [validator-engine-console]=validator-engine-console/validator-engine-console
  [lite-client]=lite-client/lite-client
  [generate-random-id]=utils/generate-random-id
  [tos-pq-consensus-key]=crypto/pq/tos-pq-consensus-key
  [dht-server]=dht-server/dht-server
)
OUT=$WORK/release-$REV
rm -rf "$OUT.tmp"
install -d -m 0755 "$OUT.tmp"
for t in $(printf '%s\n' "${TARGETS[@]}" | sort -u); do
  install -m 0755 "$BUILD/${PATHS[$t]}" "$OUT.tmp/$t"
done
(cd "$OUT.tmp" && sha256sum $(ls | grep -v -E '^(SHA256SUMS|BUILD-INFO)$') > SHA256SUMS)
{
  echo "tos_revision $REV"
  echo "host $(hostname)"
  echo "cpu $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "compiler $(clang++-21 --version | head -1)"
  echo "flags TOS_ARCH=x86-64-v2 PORTABLE=x86-64-v2 TOS_PRODUCTION_BUILD=ON TOS_USE_JEMALLOC=ON Release"
  echo "built $(date -u +%FT%TZ)"
} > "$OUT.tmp/BUILD-INFO"
rm -rf "$OUT"
mv "$OUT.tmp" "$OUT"
"$OUT/$(printf '%s\n' "${TARGETS[@]}" | head -1)" -V | head -1
echo "release $OUT"
