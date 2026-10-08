#!/bin/bash
# Host-side live controls for the CI runner (run as root while the three slot
# VMs are running). Each negative check has a positive control beside it, so
# a probe that cannot reach anything cannot pass. Exit status = failures.
set -uo pipefail
[[ $EUID == 0 ]] || { echo "run as root" >&2; exit 2; }

fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
expect_ok() { local name=$1; shift; if "$@" > /dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
expect_no() { local name=$1; shift; if "$@" > /dev/null 2>&1; then fail "$name"; else pass "$name"; fi; }

pid_of() { systemctl show -p MainPID --value "tos-ci-vm@$1.service"; }
as_slot_in_sandbox() {  # $1 slot, rest: command run as that slot inside its unit's mount namespace
  local slot=$1; shift
  # Same identity as the slot's QEMU: its account plus the kvm group.
  nsenter -t "$(pid_of "$slot")" -m -- setpriv --reuid="tos-ci-slot$slot" --regid="tos-ci-slot$slot" \
    --groups=kvm --no-new-privs -- "$@"
}
slotctl_as() {  # $1 account, $2 request line (printf format)
  setpriv --reuid="$1" --regid="$1" --clear-groups -- \
    python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect("/run/tos-ci/slotctl.sock")
s.sendall(sys.argv[1].encode()); print(s.recv(256).decode().strip())' "$2"
}

for n in 1 2 3; do
  [[ $(systemctl is-active "tos-ci-vm@$n") == active ]] || { echo "slot $n is not running; start the supervisor first" >&2; exit 2; }
done

echo "== identity and limits of each QEMU"
declare -A CPUS=([1]=72-79,168-175 [2]=80-87,176-183 [3]=88-95,184-191)
for n in 1 2 3; do
  pid=$(pid_of "$n")
  [[ $(stat -c %U "/proc/$pid") == "tos-ci-slot$n" ]] && pass "slot $n QEMU runs as tos-ci-slot$n" || fail "slot $n QEMU account"
  [[ $(awk '/^CapEff:/ {print $2}' "/proc/$pid/status") == 0000000000000000 ]] && pass "slot $n QEMU has no capabilities" || fail "slot $n CapEff"
  bad=0
  for t in /proc/"$pid"/task/*; do
    [[ $(awk '/^Cpus_allowed_list:/ {print $2}' "$t/status") == "${CPUS[$n]}" ]] || bad=1
  done
  [[ $bad == 0 ]] && pass "slot $n every QEMU thread pinned to ${CPUS[$n]}" || fail "slot $n thread affinity"
  cg=/sys/fs/cgroup$(cut -d: -f3 "/proc/$pid/cgroup")
  [[ $(cat "$cg/memory.max") == $((17 * 1024 * 1024 * 1024)) ]] && pass "slot $n memory.max = 17G" || fail "slot $n memory.max $(cat "$cg/memory.max")"
  [[ $(cat "$cg/memory.swap.max") == 0 ]] && pass "slot $n swap.max = 0" || fail "slot $n swap.max"
done
slice=/sys/fs/cgroup/tos.slice/tos-ci.slice
[[ -d $slice ]] || slice=/sys/fs/cgroup/tos-ci.slice
[[ $(cat "$slice/memory.max") == $((54 * 1024 * 1024 * 1024)) ]] && pass "slice memory.max = 54G" || fail "slice memory.max $(cat "$slice/memory.max")"
[[ $(cat "$slice/cpuset.cpus.effective") == 72-95,168-191 ]] && pass "slice CPUs = 72-95,168-191" || fail "slice cpuset $(cat "$slice/cpuset.cpus.effective")"

echo "== cross-slot isolation, from slot 1's own sandbox"
expect_ok "slot 1 reads its own overlay (positive control)" as_slot_in_sandbox 1 head -c 4 /var/lib/tos-ci/slot1/overlay.qcow2
expect_ok "slot 1 reads its own seed (positive control)" as_slot_in_sandbox 1 head -c 4 /var/lib/tos-ci/seed1/seed.iso
expect_no "slot 1 cannot read slot 2's overlay" as_slot_in_sandbox 1 head -c 4 /var/lib/tos-ci/slot2/overlay.qcow2
expect_no "slot 1 cannot read slot 2's seed" as_slot_in_sandbox 1 head -c 4 /var/lib/tos-ci/seed2/seed.iso
expect_no "slot 1 cannot write slot 2's overlay" as_slot_in_sandbox 1 sh -c ': >> /var/lib/tos-ci/slot2/overlay.qcow2'
expect_no "slot 1 cannot write a base image" as_slot_in_sandbox 1 sh -c ': >> /var/lib/tos-ci/images/current.qcow2'
expect_no "slot 1 cannot write /etc" as_slot_in_sandbox 1 sh -c ': > /etc/tos-ci-probe'
expect_ok "slot 1 signals its own QEMU (positive control)" as_slot_in_sandbox 1 kill -0 "$(pid_of 1)"
expect_no "slot 1 cannot signal slot 2's QEMU" as_slot_in_sandbox 1 kill -0 "$(pid_of 2)"
expect_no "slot 1 cannot read slot 2's environ" as_slot_in_sandbox 1 head -c 1 "/proc/$(pid_of 2)/environ"
expect_no "slot 1 cannot read slot 2's memory" as_slot_in_sandbox 1 head -c 1 "/proc/$(pid_of 2)/mem"
expect_ok "slot 1 opens /dev/kvm (positive control)" as_slot_in_sandbox 1 sh -c 'exec 3<> /dev/kvm'

echo "== slot control helper"
[[ $(slotctl_as tos-ci $'status 1\n') == "active $(pid_of 1)" ]] && pass "tos-ci: status 1 answered (positive control)" || fail "tos-ci status 1"
for req in $'start 4\n' $'start 1; id\n' $'start 01\n' $'restart 1\n' "$(printf 'start %0100d\n' 1)" $'start 1'; do
  reply=$(slotctl_as tos-ci "$req" 2>&1 | tail -1)
  [[ $reply == "refused request" ]] && pass "slotctl refuses $(printf %q "$req" | cut -c1-24)" || fail "slotctl accepted $(printf %q "$req") -> $reply"
done
expect_no "tos-ci-slot1 cannot use slotctl" slotctl_as tos-ci-slot1 $'status 1\n'

echo "== the supervisor account has no systemd rights"
as_ci() { setpriv --reuid=tos-ci --regid=tos-ci --clear-groups -- "$@"; }
expect_no "transient unit with the permitted name and /bin/sh" as_ci systemd-run --no-ask-password --unit=tos-ci-vm@1 /bin/sh -c id
expect_no "transient unit with User=root" as_ci systemd-run --no-ask-password -p User=root --unit=tos-ci-vm@1 /bin/true
expect_no "set-property AllowedCPUs=0-191" as_ci systemctl --no-ask-password set-property tos-ci-vm@1 AllowedCPUs=0-191
expect_no "set-property MemoryMax=100G" as_ci systemctl --no-ask-password set-property tos-ci-vm@1 MemoryMax=100G
expect_no "systemctl stop tos-ci-vm@1 directly" as_ci systemctl --no-ask-password stop tos-ci-vm@1
expect_no "daemon-reload" as_ci systemctl --no-ask-password daemon-reload
expect_no "write the unit file" as_ci sh -c ': >> /etc/systemd/system/tos-ci-vm@.service'
expect_no "write a cpus drop-in" as_ci sh -c ': >> /etc/systemd/system/tos-ci-vm@1.service.d/cpus.conf'
expect_no "write a slot script" as_ci sh -c ': >> /usr/lib/tos-ci/slot-qemu'

echo "== admission sockets"
probe_connect() {  # $1 account, $2 slot socket
  setpriv --reuid="$1" --regid="$1" --clear-groups -- \
    python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
s.sendall(b"{}\n"); data=s.recv(64); sys.exit(0 if data else 3)' "$2"
}
expect_no "slot 2's account cannot connect to slot 1's socket" probe_connect tos-ci-slot2 /run/tos-ci/slot1/admission.sock
before=$(journalctl -u tos-ci-supervisor -o cat --no-pager | grep -c admission_peer_refused)
probe_connect tos-ci-slot1 /run/tos-ci/slot1/admission.sock > /dev/null 2>&1
sleep 2
after=$(journalctl -u tos-ci-supervisor -o cat --no-pager | grep -c admission_peer_refused)
(( after > before )) && pass "slot 1's account, not its QEMU, is refused by the peer check" || fail "peer check did not refuse a non-QEMU peer"

echo "== result: $fails failure(s)"
exit "$fails"
