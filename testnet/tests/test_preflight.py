import importlib.util
import json
import re
import subprocess
import sys

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("preflight", SCRIPTS / "preflight.py")
preflight = importlib.util.module_from_spec(spec)
sys.modules["preflight"] = preflight  # dataclasses resolve their module through sys.modules
spec.loader.exec_module(preflight)

PROFILE = lib.load_profile()

GOOD_FACTS = {
    "os_id": "ubuntu",
    "os_version": "24.04",
    "arch": "x86_64",
    "cpus": "6",
    "cpu_model": "Intel Xeon Processor (Icelake)",
    "cpu_flags": "fpu cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3 avx2",
    "mem_kib": str(int(11.6 * 1048576)),
    "disk_free_kib": str(88 * 1048576),
    "ipv4": "203.0.113.10 ",
    "ntp": "yes",
    "ntp_source": "ntpd:1",
    "ufw": "Status: active||To Action From|-- ------ ----|OpenSSH ALLOW Anywhere|30001/udp ALLOW Anywhere|31001/udp ALLOW Anywhere|30001/udp (v6) ALLOW Anywhere (v6)|",
    # ss truncates process names to 15 characters, exactly as on the real hosts.
    "udp_listen": '0.0.0.0:30001@users:(("validator-engin",pid=1,fd=5)) 127.0.0.53%lo:53@users:(("systemd-resolve",pid=2,fd=3))',
    "tcpdump": "/usr/bin/tcpdump",
    "python3": "/usr/bin/python3",
}


def host(name="node-1", address="203.0.113.10", roles=("validator",)):
    return preflight.Host(name=name, address=address, roles=list(roles))


def statuses(results):
    return {r.check: r.status for r in results}


def test_a_good_validator_passes_every_host_check():
    results = preflight.evaluate_host(host(), dict(GOOD_FACTS), PROFILE)
    assert set(statuses(results).values()) == {"PASS"}, [r for r in results if r.status != "PASS"]


@pytest.mark.parametrize(
    "key,value,check",
    [
        ("os_version", "22.04", "os"),
        ("arch", "riscv64", "arch"),
        ("cpus", "2", "cpu"),
        ("cpu_flags", "fpu sse2", "cpu"),
        ("mem_kib", str(4 * 1048576), "memory"),
        ("disk_free_kib", str(10 * 1048576), "disk"),
        ("ntp", "no", "time"),
    ],
)
def test_each_floor_fails_when_not_met(key, value, check):
    facts = dict(GOOD_FACTS, **{key: value})
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))[check] == "FAIL"


@pytest.mark.parametrize("source", ["ntpd:0", "chrony:0", "none:0", ""])
def test_a_synchronized_flag_without_a_selected_server_fails(source):
    """The kernel said synchronized while ntpsec had no server at all; that must not pass."""
    facts = dict(GOOD_FACTS, ntp_source=source)
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))["time"] == "FAIL"


@pytest.mark.parametrize("source", ["ntpd:1", "chrony:1", "timesyncd:1"])
def test_any_daemon_with_a_selected_server_passes(source):
    facts = dict(GOOD_FACTS, ntp_source=source)
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))["time"] == "PASS"


def test_a_4gb_vm_is_enough_for_dht_but_not_for_a_validator():
    facts = dict(GOOD_FACTS, mem_kib=str(int(3.8 * 1048576)), cpus="4")
    assert (
        statuses(preflight.evaluate_host(host(roles=["dht"]), facts, PROFILE))["memory"] == "PASS"
    )
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))["memory"] == "FAIL"


@pytest.mark.parametrize(
    "roles,memory_gib,expected",
    [
        (["fullnode"], 7.7, "PASS"),
        (["fullnode"], 7, "PASS"),
        (["fullnode"], 6.99, "FAIL"),
        (["validator"], 7.7, "FAIL"),
        (["validator"], 11, "PASS"),
        (["fullnode", "validator"], 7.7, "FAIL"),
        (["dht"], 3, "PASS"),
        (["dht"], 2.99, "FAIL"),
    ],
)
def test_role_memory_boundaries(roles, memory_gib, expected):
    facts = dict(GOOD_FACTS, mem_kib=str(int(memory_gib * 1048576)))
    results = preflight.evaluate_host(host(roles=roles), facts, PROFILE)
    assert statuses(results)["memory"] == expected


def test_a_host_with_two_roles_takes_the_stricter_floor_and_both_port_sets():
    assert preflight.role_floor(["dht", "validator"], PROFILE)["min_memory_gib"] == 11
    assert preflight.role_udp_ports(["validator", "dht"], PROFILE) == [30001, 30300, 31001]
    assert preflight.role_udp_ports(["dht"], PROFILE) == [30300]


def test_nat_is_a_warning_not_a_failure():
    facts = dict(GOOD_FACTS, ipv4="192.168.1.156 ")
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))["address"] == "WARN"


def test_ufw_missing_quic_port_fails():
    facts = dict(GOOD_FACTS, ufw="Status: active|30001/udp ALLOW Anywhere|")
    results = preflight.evaluate_host(host(), facts, PROFILE)
    ufw = next(r for r in results if r.check == "ufw")
    assert ufw.status == "FAIL" and "31001" in ufw.detail


def test_ufw_only_v6_rule_does_not_count():
    facts = dict(
        GOOD_FACTS,
        ufw="Status: active|30001/udp (v6) ALLOW Anywhere (v6)|31001/udp ALLOW Anywhere|",
    )
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))["ufw"] == "FAIL"


def test_an_open_console_port_fails():
    facts = dict(GOOD_FACTS, ufw=GOOD_FACTS["ufw"] + "30002/tcp ALLOW Anywhere|")
    results = preflight.evaluate_host(host(), facts, PROFILE)
    assert next(r for r in results if r.check == "ufw").status == "FAIL"


def test_inactive_ufw_is_a_warning():
    facts = dict(GOOD_FACTS, ufw="Status: inactive|")
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))["ufw"] == "WARN"


def test_a_port_held_by_another_program_fails():
    facts = dict(GOOD_FACTS, udp_listen='0.0.0.0:30001@users:(("someapp",pid=9,fd=3))')
    assert statuses(preflight.evaluate_host(host(), facts, PROFILE))["ports"] == "FAIL"


def test_probe_payload_is_found_in_a_tcpdump_ascii_capture():
    capture = (
        "06:10:01.1 eth0 In  IP 198.51.100.7.40123 > 203.0.113.10.30001: UDP, length 20\n"
        "E..0..@.@.....PROB:node-2:30001\n"
        "06:10:01.2 eth0 In  IP 10.0.0.5.40123 > 203.0.113.10.31001: UDP, length 20\n"
        "E..0..@.@.....PROB:node-nat:31001\n"
    )
    assert preflight.received_probes(capture) == {("node-2", 30001), ("node-nat", 31001)}


def test_probe_command_names_every_target():
    command = preflight.probe_command("node-1", [("203.0.113.11", 30001), ("203.0.113.12", 30300)])
    assert "203.0.113.11:30001" in command and "203.0.113.12:30300" in command
    assert "PROB:%s:%s" in command


class FakeNetwork:
    """Runs commands as if on real hosts; `blocked` lists (sender, target, port) that are dropped."""

    def __init__(self, hosts, blocked=()):
        self.hosts = {h.name: h for h in hosts}
        self.by_address = {h.address: h for h in hosts}
        self.blocked = set(blocked)
        self.sent = []

    def __call__(self, h, command, timeout):
        if command == preflight.FACTS_SCRIPT:
            facts = dict(GOOD_FACTS, ipv4=h.address + " ")
            return subprocess.CompletedProcess(
                [], 0, "\n".join(f"{k}={v}" for k, v in facts.items()), ""
            )
        if command.startswith("python3 -c"):
            sender = command.split('" ', 1)[1].split()[0]
            for pair in command.split('" ', 1)[1].split()[1:]:
                address, port = pair.rsplit(":", 1)
                self.sent.append((sender, self.by_address[address].name, int(port)))
            return subprocess.CompletedProcess([], 0, "", "")
        if command.startswith("timeout"):
            import time

            time.sleep(6)  # the probes are sent while the capture runs
            ports = [int(p) for p in re.findall(r"dst port (\d+)", command)]
            lines = [
                f"PROB:{s}:{p}"
                for s, t, p in self.sent
                if t == h.name and p in ports and (s, t, p) not in self.blocked
            ]
            return subprocess.CompletedProcess([], 0, "\n".join(lines), "")
        raise AssertionError(command)


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(preflight, "CAPTURE_SECONDS", 1)


def test_full_mesh_passes(quick):
    hosts = [host("a", "203.0.113.1"), host("b", "203.0.113.2"), host("c", "203.0.113.3", ["dht"])]
    results = preflight.check_udp(hosts, PROFILE, FakeNetwork(hosts))
    assert {r.status for r in results} == {"PASS"}
    assert {r.check for r in results if r.host == "c"} == {"udp:30300"}


def test_a_dropped_path_names_the_target_port_and_sender(quick):
    hosts = [host("a", "203.0.113.1"), host("b", "203.0.113.2"), host("c", "203.0.113.3")]
    net = FakeNetwork(hosts, blocked={("a", "c", 31001)})
    results = preflight.check_udp(hosts, PROFILE, net)
    failed = [r for r in results if r.status == "FAIL"]
    assert len(failed) == 1
    assert failed[0].host == "c" and failed[0].check == "udp:31001" and "['a']" in failed[0].detail


def test_a_provider_that_admits_only_ssh_fails_every_port(quick):
    hosts = [host("a", "203.0.113.1"), host("b", "203.0.113.2")]
    net = FakeNetwork(
        hosts, blocked={(s, t, p) for s in "ab" for t in "ab" for p in (30001, 31001)}
    )
    results = preflight.check_udp(hosts, PROFILE, net)
    assert {r.status for r in results} == {"FAIL"} and len(results) == 4


def test_run_preflight_reports_an_unreachable_host(quick):
    hosts = [host("a", "203.0.113.1"), host("b", "203.0.113.2")]
    net = FakeNetwork(hosts)

    def run(h, command, timeout):
        if h.name == "b" and command == preflight.FACTS_SCRIPT:
            return subprocess.CompletedProcess([], 255, "", "Host key verification failed.")
        return net(h, command, timeout)

    results = preflight.run_preflight(hosts, PROFILE, run, install_tools=False)
    ssh_b = next(r for r in results if r.host == "b" and r.check == "ssh")
    assert ssh_b.status == "FAIL" and "Host key verification failed" in ssh_b.detail
    assert not any(r.check.startswith("udp") for r in results), (
        "one reachable host cannot test a mesh"
    )


def test_inventory_validation(tmp_path):
    path = tmp_path / "inv.json"
    path.write_text(
        json.dumps({"hosts": [{"name": "a", "address": "203.0.113.1", "roles": ["miner"]}]})
    )
    with pytest.raises(lib.TestnetError, match="roles"):
        preflight.load_inventory(path)
    path.write_text(
        json.dumps(
            {
                "hosts": [
                    {"name": "a", "address": "203.0.113.1", "roles": ["dht"]},
                    {"name": "a", "address": "203.0.113.2", "roles": ["dht"]},
                ]
            }
        )
    )
    with pytest.raises(lib.TestnetError, match="name"):
        preflight.load_inventory(path)
    path.write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "name": "a",
                        "address": "203.0.113.1",
                        "roles": ["dht"],
                        "ssh_key": "~/.ssh/k.pem",
                    }
                ]
            }
        )
    )
    loaded = preflight.load_inventory(path)
    assert not loaded[0].ssh_key.startswith("~")


def test_the_example_inventory_loads():
    hosts = preflight.load_inventory(lib.PROFILE_PATH.parent / "inventory.example.json")
    assert {r for h in hosts for r in h.roles} == {"validator", "dht"}
    assert all(h.waive == {} for h in hosts)


# ---------------------------------------------------------------- per-host floor waivers

REASON = "owner 2026-11-17: small validator host under install-node.sh resources"
BELOW_FLOOR = {
    "memory": ("mem_kib", str(int(3.9 * 1048576))),
    "cpu": ("cpus", "2"),
    "disk": ("disk_free_kib", str(30 * 1048576)),
}


def waived_host(waive):
    return preflight.Host(name="v4", address="203.0.113.10", roles=["validator"], waive=waive)


@pytest.mark.parametrize("check", sorted(BELOW_FLOOR))
def test_a_waived_floor_reports_waived_with_its_value_and_reason(check):
    key, value = BELOW_FLOOR[check]
    facts = dict(GOOD_FACTS, **{key: value})
    results = preflight.evaluate_host(waived_host({check: REASON}), facts, PROFILE)
    result = next(r for r in results if r.check == check)
    assert result.status == "WAIVED"
    assert result.detail.endswith(f"; waived: {REASON}")
    assert "need" in result.detail  # the measured value and the floor stay visible
    # Only that check is waived: every other check still passes on its own.
    assert {r.status for r in results if r.check != check} == {"PASS"}


@pytest.mark.parametrize("check", sorted(BELOW_FLOOR))
def test_a_waiver_covers_only_its_own_check(check):
    others = [c for c in BELOW_FLOOR if c != check]
    facts = dict(GOOD_FACTS)
    for other in others:
        key, value = BELOW_FLOOR[other]
        facts[key] = value
    found = statuses(preflight.evaluate_host(waived_host({check: REASON}), facts, PROFILE))
    assert found[check] == "PASS"
    assert all(found[other] == "FAIL" for other in others)


def test_a_waiver_on_a_passing_check_says_it_was_not_needed():
    results = preflight.evaluate_host(waived_host({"memory": REASON}), dict(GOOD_FACTS), PROFILE)
    memory = next(r for r in results if r.check == "memory")
    assert memory.status == "PASS" and memory.detail.endswith("; waiver not needed")


def test_a_waived_cpu_floor_does_not_waive_missing_x86_64_v2():
    # The cpu check also carries the instruction set the build targets; a waiver
    # says the host is small, not that a binary built for x86-64-v2 runs on it.
    facts = dict(GOOD_FACTS, cpus="2", cpu_flags="fpu sse2")
    result = next(
        r
        for r in preflight.evaluate_host(waived_host({"cpu": REASON}), facts, PROFILE)
        if r.check == "cpu"
    )
    assert result.status == "FAIL"
    assert "missing x86-64-v2 flags" in result.detail
    assert result.detail.endswith("; not waivable")


def test_the_report_counts_waived_checks_and_waived_alone_does_not_fail(tmp_path, monkeypatch):
    facts = dict(GOOD_FACTS, mem_kib=BELOW_FLOOR["memory"][1])
    results = preflight.evaluate_host(waived_host({"memory": REASON}), facts, PROFILE)
    text = preflight.report(results)
    assert text.splitlines()[0].startswith("WAIVED")
    assert text.rstrip().endswith("0 failed, 1 waived")
    assert not any(r.status == "FAIL" for r in results)


def write_inventory(tmp_path, waive):
    path = tmp_path / "inv.json"
    entry = {"name": "v4", "address": "203.0.113.1", "roles": ["validator"], "waive": waive}
    path.write_text(json.dumps({"hosts": [entry]}))
    return path


def test_the_inventory_carries_waivers_with_their_reasons(tmp_path):
    hosts = preflight.load_inventory(write_inventory(tmp_path, {"memory": f"  {REASON} "}))
    assert hosts[0].waive == {"memory": REASON}


@pytest.mark.parametrize(
    "waive,message",
    [
        ({"ufw": REASON}, r"only \['memory', 'cpu', 'disk'\] can be waived, not \['ufw'\]"),
        ({"time": REASON}, "can be waived, not \\['time'\\]"),
        ({"os": REASON, "memory": REASON}, "can be waived, not \\['os'\\]"),
        ({"memory": ""}, "the memory waiver needs a reason"),
        ({"disk": "   "}, "the disk waiver needs a reason"),
        ({"cpu": None}, "the cpu waiver needs a reason"),
        ({"cpu": 4}, "the cpu waiver needs a reason"),
        (["memory"], "waive must be an object"),
        ("memory", "waive must be an object"),
    ],
)
def test_the_inventory_refuses_a_bad_waiver(tmp_path, waive, message):
    with pytest.raises(lib.TestnetError, match=message):
        preflight.load_inventory(write_inventory(tmp_path, waive))


def test_main_refuses_a_bad_waiver_as_a_usage_error(tmp_path, capsys):
    assert preflight.main(["--inventory", str(write_inventory(tmp_path, {"ssh": REASON}))]) == 2
    assert "refused:" in capsys.readouterr().err
