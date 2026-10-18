# Host uplink: I219 transmit-hang workaround

**Host-specific local workaround, not a testnet validator requirement.**
The templates target `eno1`/`e1000e`; confirm the actual hardware and obtain
explicit approval before installation or fault injection. Keep provider console
access: link recovery deliberately interrupts connectivity. Never test `/dev/kmsg`
fault injection on a public validator. On a refusal, retain logs and stop.

The host's on-board Intel I219-LM (`eno1`, driver `e1000e`) can wedge its
transmit queue under sustained traffic, such as several CI VMs downloading
through NAT. The kernel then logs `eno1: Detected Hardware Unit Hang` every
two seconds, the driver never resets the adapter, and the host drops off the
network (DNS, Tailscale, GitHub) while everything else keeps running. Only a
power cycle used to recover it.

Two units address this:

| Unit | Role |
|---|---|
| `tos-nic-offload.service` | Turns TSO and GSO off on `eno1` at boot and whenever the device reappears; this is the known trigger. |
| `tos-nic-watchdog.service` | Runs `nic-watchdog.py`: on two or more hang reports in a poll, or six consecutive gateway ping failures, it bounces the link, re-applies the offload settings and reconfigures networkd. If the link is still bad afterwards, the next recovery reloads the driver. Recoveries are at least 120 s apart. |

Install:

```sh
sudo install -m 0644 local/host-nic/tos-nic-*.service /etc/systemd/system/
sudo install -d /usr/local/lib/tos-host-nic
sudo install -m 0755 local/host-nic/nic-watchdog.py /usr/local/lib/tos-host-nic/
sudo systemctl daemon-reload
sudo systemctl enable --now tos-nic-offload.service tos-nic-watchdog.service
```

Verify: `ethtool -k eno1 | grep segmentation` shows TSO and GSO off, and
`journalctl -u tos-nic-watchdog` shows `started` with no `recovering`
events. `--dry-run --polls N` logs the recovery commands without running them;
writing two `eno1: Detected Hardware Unit Hang` lines to `/dev/kmsg` while it
runs is a positive control for detection. Tests: `python3 -I local/tests/test_nic_watchdog.py`.

A discrete NIC (for example an Intel i210) removes the underlying defect.
