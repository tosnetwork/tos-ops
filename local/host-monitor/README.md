# Test-host contact supervision

Host deployment only; no blockchain identity, value, validator, signing or reboot
operations. Explicitly approve the named host installation under AGENTS.md.

`tos-host-monitor.service` is a root system service enabled at multi-user boot,
with automatic process recovery, OOM preference,128MiB and10%CPU bounds. Every30s
it checks SSH, Tailscale, networkd/resolved, the existing NIC watchdog, the target
user manager and four readonly RPC/proof tunnels. It starts only stopped/failed
allowlisted contact services; transient starting/stopping states are left alone.
A locally unresponsive/stopped Tailscale API needs three polls before restarting
that daemon; actions have120s cooldown. Remote relay/network probe failures alone
never restart a working overlay agent. Login-required state is reported without
attempting enrollment or reading credentials.

A netcheck every120s records only UDP/IPv4/relay reachability booleans, not peers,
IPs, login URLs or tokens. Local metrics include memory, load, free disk, maximum
sensor temperature and uptime; low memory/disk or>=90C is reported. Snapshot
`/var/lib/tos-host-monitor/status.json` is atomically replaced/fsynced and readable
by the operator. Journald retains heartbeat/recovery/boot-change records; use an
already persistent system journal. A network probe is not an external inbound
SSH acceptance test or a guarantee against power/hardware failure.

The pilot timer and money-carrying pilot service are observed only, never started
or restarted by this monitor. Existing execution/transaction markers survive a
reboot and prevent payment replay. The installer enables linger and the existing
readonly tunnels without restarting them; this corrects disabled-at-boot tunnel
units. It does not edit their templates or reset failed payment units.

After reviewing exact source/template hashes and non-author review:

```sh
sudo /usr/bin/python3 -I local/host-monitor/install.py --user "$HOST_USER" \
  --source-sha256 "$REVIEWED_SOURCE_SHA" --unit-sha256 "$REVIEWED_UNIT_SHA"
systemctl is-enabled tos-host-monitor.service
systemctl is-active tos-host-monitor.service
cat /var/lib/tos-host-monitor/status.json
```

The installer snapshots code root-owned under `/usr/local/lib/tos-host-monitor`,
uses the reviewed template and refuses an existing deployment. Stop the monitor
before deliberate maintenance of its supervised contact services. Do not fault
inject real SSH/network loss or reboot an active money-carrying test merely to
check this deployment. Safe mock tests and `--dry-run --once` verify decisions;
restarting only the monitor checks its own lifecycle while keeping SSH/tunnels.

```sh
/usr/bin/python3 -I local/tests/test_host_monitor.py -v
sudo /usr/bin/python3 -I local/host-monitor/host-monitor.py --user "$HOST_USER" \
  --dry-run --once --state-dir "$NEW_DIAGNOSTIC_DIRECTORY"
```

Upstream comparison: this TOS-specific host deployment/configuration path is
absent in TON master857b8a57a178e6ae0fe7fa86e7d81c5233de8560. Existing Linux,
networking and NIC watchdog implementations remain unchanged.
