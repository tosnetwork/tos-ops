import argparse
import importlib.util
import io
import json
import os
import socket
import subprocess
import urllib.error
import urllib.parse

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location("alert_relay", SCRIPTS / "alert-relay.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)

TOKEN = "123456:TEST-TOKEN-NOT-REAL"
CHAT = "-1001234"
T0 = 1_800_000_000.0


class Clock:
    def __init__(self, start=T0):
        self.t = start

    def now(self):
        return self.t


class FakeApi:
    """Stands in for urlopen: records every call, answers from `updates`, can fail."""

    def __init__(self):
        self.calls = []
        self.fail = 0  # this many next calls raise a network error
        self.updates = []
        self.next_id = 100

    def __call__(self, request, timeout):
        method = request.full_url.rsplit("/", 1)[1]
        params = dict(urllib.parse.parse_qsl(request.data.decode()))
        assert request.full_url.startswith(f"{relay.API}/bot{TOKEN}/")
        if self.fail:
            self.fail -= 1
            raise urllib.error.URLError("network unreachable")
        self.calls.append((method, params))
        if method == "sendMessage":
            self.next_id += 1
            result = {"message_id": self.next_id}
        else:
            offset = int(params["offset"])
            result = [u for u in self.updates if u["update_id"] >= offset]
        return io.BytesIO(json.dumps({"ok": True, "result": result}).encode())

    def sent(self):
        return [p["text"] for m, p in self.calls if m == "sendMessage"]


def telegram(api):
    return relay.Telegram(TOKEN, CHAT, opener=api, sleep=lambda _s: None)


def notifier(tmp_path, api, clock):
    return relay.Notifier(telegram(api), tmp_path, tmp_path / "silence", clock.now)


def records(tmp_path, name="alerts.jsonl"):
    path = tmp_path / name
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


LINE1 = "ANOMALY 2027-01-15T08:00:00 node-1:head_age=155s node-3:unit=inactive"
LINE2 = "ANOMALY 2027-01-15T08:01:00 node-1:head_age=215s node-3:unit=inactive"


# ---------------------------------------------------------------- anomaly keys


def test_anomaly_keys_ignore_the_changing_value():
    keys = relay.anomaly_keys(
        "ANOMALY 2027-01-15T08:00:00 node-1:head_age=155s node-2:unreachable "
        "node-1:head_stuck_at=332135 node-4:free=12.5GiB junk"
    )
    assert set(keys) == {
        "node-1:head_age",
        "node-2:unreachable",
        "node-1:head_stuck_at",
        "node-4:free",
    }
    assert keys["node-1:head_age"] == "node-1:head_age=155s"


def test_new_key_sends_once_then_one_reminder_per_half_hour(tmp_path):
    api, clock = FakeApi(), Clock()
    tracker = relay.AnomalyTracker(notifier(tmp_path, api, clock))
    tracker.on_line(LINE1, clock.t)
    assert len(api.sent()) == 1
    assert "node-1:head_age node-3:unit" in api.sent()[0] and LINE1 in api.sent()[0]
    clock.t += 60
    tracker.on_line(LINE2, clock.t)  # same keys, new values: nothing new
    tracker.tick(clock.t)
    assert len(api.sent()) == 1
    clock.t = T0 + 1799
    tracker.tick(clock.t)
    assert len(api.sent()) == 1
    clock.t = T0 + 1800
    tracker.tick(clock.t)
    assert len(api.sent()) == 2 and api.sent()[1].startswith("TOS testnet REMINDER")
    assert LINE2 in api.sent()[1]
    clock.t = T0 + 3599
    tracker.tick(clock.t)
    assert len(api.sent()) == 2
    clock.t = T0 + 3600
    tracker.tick(clock.t)
    assert len(api.sent()) == 3
    kinds = [r["kind"] for r in records(tmp_path)]
    assert kinds == ["anomaly", "reminder", "reminder"]


def test_an_added_key_alerts_only_for_itself(tmp_path):
    api, clock = FakeApi(), Clock()
    tracker = relay.AnomalyTracker(notifier(tmp_path, api, clock))
    tracker.on_line(LINE1, clock.t)
    tracker.on_line(LINE2 + " node-2:restarts=3", clock.t + 60)
    assert len(api.sent()) == 2
    assert records(tmp_path)[1]["keys"] == ["node-2:restarts"]


def test_cleared_keys_and_recovered_line_send_recoveries(tmp_path):
    api, clock = FakeApi(), Clock()
    tracker = relay.AnomalyTracker(notifier(tmp_path, api, clock))
    tracker.on_line(LINE1, clock.t)
    clock.t += 600
    tracker.on_line("ANOMALY 2027-01-15T08:10:00 node-3:unit=inactive", clock.t)
    assert api.sent()[1].startswith("TOS testnet RECOVERED node-1:head_age (after 10 min)")
    assert "still active: node-3:unit" in api.sent()[1]
    clock.t += 60
    tracker.on_line("RECOVERED 2027-01-15T08:11:00 all clear", clock.t)
    assert "node-3:unit (after 11 min)" in api.sent()[2]
    assert tracker.active == {}
    tracker.on_line("RECOVERED 2027-01-15T08:12:00 all clear", clock.t)
    assert len(api.sent()) == 3  # nothing left to recover
    assert [r["kind"] for r in records(tmp_path)] == ["anomaly", "recovered", "recovered"]


def test_summary_is_not_sent_unless_a_digest_is_asked_for(tmp_path):
    api, clock = FakeApi(), Clock()
    tracker = relay.AnomalyTracker(notifier(tmp_path, api, clock))
    tracker.on_line("SUMMARY 2027-01-15T08:00:00 heights node-1=10", clock.t)
    assert api.sent() == []
    tracker = relay.AnomalyTracker(notifier(tmp_path, api, clock), digest_every=3600)
    tracker.on_line("SUMMARY 2027-01-15T08:00:00 heights node-1=10", clock.t)
    tracker.on_line("SUMMARY 2027-01-15T08:15:00 heights node-1=20", clock.t + 900)
    tracker.on_line("SUMMARY 2027-01-15T09:00:00 heights node-1=60", clock.t + 3600)
    assert len(api.sent()) == 2 and "node-1=60" in api.sent()[1]


def test_watch_exit_alerts_once_and_a_clear_first_round_recovers(tmp_path):
    api, clock = FakeApi(), Clock()
    tracker = relay.AnomalyTracker(notifier(tmp_path, api, clock))
    tracker.child_started()
    tracker.on_line(LINE1, clock.t)
    tracker.child_exited(1, clock.t)
    tracker.child_exited(1, clock.t + 30)
    assert sum("exited with status 1" in t for t in api.sent()) == 1
    tracker.child_started()
    clock.t += 60
    tracker.on_line("SUMMARY 2027-01-15T08:01:00 heights node-1=11", clock.t)
    assert tracker.active == {}
    assert "watch:exited" in api.sent()[2]
    assert "node-1:head_age" in api.sent()[3] and "node-3:unit" in api.sent()[3]


# ---------------------------------------------------------------- heartbeats


def coordinator_args(tmp_path, **overrides):
    values = dict(
        state_dir=tmp_path,
        silence_file=tmp_path / "silence",
        interval=60.0,
        dead_after=300.0,
        digest_hours=0.0,
        remote_dir="/var/lib/tos-alert",
    )
    values.update(overrides)
    return argparse.Namespace(**values)


def test_remote_beat_command_touches_ours_and_reads_the_peer():
    command = relay.remote_beat_command("/var/lib/tos-alert")
    assert "touch /var/lib/tos-alert/heartbeat-coordinator" in command
    assert "stat -c %Y /var/lib/tos-alert/heartbeat-peer" in command
    assert relay.parse_remote_beat("now=1000\npeer=990\n") == 10
    assert relay.parse_remote_beat("now=1000\npeer=-\n") is None
    assert relay.parse_remote_beat("") is None


def test_coordinator_alerts_once_on_a_stale_peer_and_reports_recovery(tmp_path):
    api, clock = FakeApi(), Clock()
    remote = {"mtime": T0, "code": 0}
    commands = []

    def ssh(command):
        commands.append(command)
        return subprocess.CompletedProcess(
            [], remote["code"], stdout=f"now={int(clock.t)}\npeer={int(remote['mtime'])}\n"
        )

    coordinator = relay.Coordinator(
        coordinator_args(tmp_path), telegram(api), ssh, clock.now, uptime=lambda: None
    )
    for _ in range(5):  # peer stops beating at T0; 300 s later it is dead
        coordinator.tick()
        clock.t += 60
    assert [t for t in api.sent() if "heartbeat" in t] == []
    coordinator.tick()  # T0 + 300: age 300, not above
    clock.t += 60
    coordinator.tick()  # T0 + 360
    clock.t += 60
    coordinator.tick()
    stale = [t for t in api.sent() if "peer heartbeat stale" in t]
    assert len(stale) == 1 and "360 s" in stale[0]
    remote["mtime"] = clock.t
    clock.t += 60
    coordinator.tick()
    assert "RECOVERED peer heartbeat" in api.sent()[-1]
    assert len(commands) == 9
    kinds = [r["kind"] for r in records(tmp_path)]
    assert kinds == ["heartbeat-dead", "heartbeat-alive"]


def test_coordinator_started_soon_after_boot_sends_one_notice(tmp_path):
    api, clock = FakeApi(), Clock()

    def ssh(command):
        return subprocess.CompletedProcess(
            [], 0, stdout=f"now={int(clock.t)}\npeer={int(clock.t)}\n"
        )

    coordinator = relay.Coordinator(
        coordinator_args(tmp_path), telegram(api), ssh, clock.now, uptime=lambda: 41.7
    )
    notices = [t for t in api.sent() if "coordinator rebooted" in t]
    assert len(notices) == 1 and "41 s ago" in notices[0]
    coordinator.tick()
    clock.t += 60
    coordinator.tick()
    assert len([t for t in api.sent() if "coordinator rebooted" in t]) == 1
    assert [r["kind"] for r in records(tmp_path)] == ["coordinator-booted"]


def test_coordinator_restarted_long_after_boot_or_without_uptime_sends_nothing(tmp_path):
    for uptime in (relay.BOOT_NOTICE_WITHIN, 86400.0, None, -1.0):
        api, clock = FakeApi(), Clock()
        relay.Coordinator(
            coordinator_args(tmp_path),
            telegram(api),
            lambda c: None,
            clock.now,
            uptime=lambda: uptime,
        )
        assert api.sent() == []


def test_system_uptime_reads_proc_format_and_survives_garbage(tmp_path):
    good, bad = tmp_path / "uptime", tmp_path / "bad"
    good.write_text("1234.56 98765.43\n")
    bad.write_text("not a number\n")
    assert relay.system_uptime(good) == 1234.56
    assert relay.system_uptime(bad) is None
    assert relay.system_uptime(tmp_path / "missing") is None


def test_coordinator_unreadable_peer_counts_as_dead_after_the_window(tmp_path):
    api, clock = FakeApi(), Clock()

    def ssh(_command):
        return subprocess.CompletedProcess([], 255, stdout="", stderr="no route")

    coordinator = relay.Coordinator(
        coordinator_args(tmp_path), telegram(api), ssh, clock.now, uptime=lambda: None
    )
    for _ in range(6):
        coordinator.tick()
        clock.t += 60
    assert api.sent() == []
    coordinator.tick()  # T0 + 360
    assert len(api.sent()) == 1 and "unreadable" in api.sent()[0]


def peer_args(tmp_path):
    return argparse.Namespace(
        state_dir=tmp_path, silence_file=tmp_path / "silence", interval=60.0, dead_after=300.0
    )


def test_peer_touches_its_beat_and_watches_the_coordinator(tmp_path):
    api, clock = FakeApi(), Clock()
    theirs = tmp_path / "heartbeat-coordinator"
    theirs.touch()
    os.utime(theirs, (T0, T0))
    peer = relay.Peer(peer_args(tmp_path), telegram(api), clock.now)
    peer.tick()
    assert (tmp_path / "heartbeat-peer").stat().st_mtime == T0
    clock.t = T0 + 300
    peer.tick()
    assert api.sent() == []
    clock.t = T0 + 301
    peer.tick()
    clock.t = T0 + 400
    peer.tick()
    assert len(api.sent()) == 1 and "coordinator heartbeat stale" in api.sent()[0]
    os.utime(theirs, (clock.t, clock.t))
    clock.t += 60
    peer.tick()
    assert len(api.sent()) == 2 and "RECOVERED coordinator heartbeat" in api.sent()[1]


def test_peer_with_no_coordinator_beat_alerts_after_the_window(tmp_path):
    api, clock = FakeApi(), Clock()
    peer = relay.Peer(peer_args(tmp_path), telegram(api), clock.now)
    clock.t = T0 + 300
    peer.tick()
    assert api.sent() == []
    clock.t = T0 + 301
    peer.tick()
    assert len(api.sent()) == 1 and "unreadable" in api.sent()[0]


# ---------------------------------------------------------------- silence


def test_silence_records_without_sending_then_summarises(tmp_path):
    api, clock = FakeApi(), Clock()
    relay.write_silence(tmp_path / "silence", T0 + 600, "planned  restart\nof node-2")
    assert (tmp_path / "silence").read_text() == f"{int(T0 + 600)} planned restart of node-2\n"
    n = notifier(tmp_path, api, clock)
    tracker = relay.AnomalyTracker(n)
    n.tick()
    tracker.on_line("ANOMALY 2027-01-15T08:00:00 node-2:unit=inactive", clock.t)
    clock.t += 60
    tracker.on_line("RECOVERED 2027-01-15T08:01:00 all clear", clock.t)
    n.tick()
    assert api.sent() == []
    logged = records(tmp_path)
    assert [r["silenced"] for r in logged] == [True, True]
    assert logged[0]["silence_reason"] == "planned restart of node-2"
    clock.t = T0 + 601
    n.tick()
    assert len(api.sent()) == 1
    summary = api.sent()[0]
    assert "silence ended (planned restart of node-2); 2 alert(s) were suppressed" in summary
    assert "anomaly node-2:unit" in summary and "recovered node-2:unit" in summary
    n.tick()
    assert len(api.sent()) == 1


def test_unsilence_ends_silence_early_and_reports_active_keys(tmp_path):
    api, clock = FakeApi(), Clock()
    relay.write_silence(tmp_path / "silence", T0 + 3600, "work")
    n = notifier(tmp_path, api, clock)
    n.tick()
    assert relay.main(["unsilence", "--silence-file", str(tmp_path / "silence")]) == 0
    n.tick(["node-1:head_age"])
    assert "nothing was suppressed" in api.sent()[0]
    assert "still active: node-1:head_age" in api.sent()[0]


def test_malformed_silence_file_silences_nothing(tmp_path):
    api, clock = FakeApi(), Clock()
    (tmp_path / "silence").write_text("tomorrow maybe\n")
    notifier(tmp_path, api, clock).alert("anomaly", ["node-1:unit"], "x")
    assert len(api.sent()) == 1


def test_silence_command_writes_the_file_and_refuses_the_past(tmp_path, capsys):
    path = tmp_path / "silence"
    assert (
        relay.main(["silence", "--silence-file", str(path), "--until", "+30", "--reason", "x"]) == 0
    )
    until, reason = relay.read_silence(path)
    assert reason == "x" and 1700 < until - __import__("time").time() <= 1800
    status = relay.main(
        ["silence", "--silence-file", str(path), "--until", "2020-01-01T00:00", "--reason", "x"]
    )
    assert status == 1 and "not in the future" in capsys.readouterr().err
    assert relay.parse_until("2030-01-01T00:00:00", T0) == 1893456000


# ---------------------------------------------------------------- secrets


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_world_or_group_readable_secret_files_are_refused(tmp_path, mode, capsys):
    token, chat = tmp_path / "token", tmp_path / "chat"
    token.write_text(TOKEN + "\n")
    chat.write_text(CHAT + "\n")
    token.chmod(0o600)
    chat.chmod(0o600)
    assert relay.read_secret(token, "token") == TOKEN
    for loose in (token, chat):
        loose.chmod(mode)
        with pytest.raises(lib.TestnetError, match="readable by group or others"):
            relay.read_secret(loose, "x")
        argv = ["peer", "--token-file", str(token), "--chat-file", str(chat)]
        assert relay.main(argv + ["--state-dir", str(tmp_path / "state")]) == 1
        err = capsys.readouterr().err
        assert "REFUSED" in err and TOKEN not in err and CHAT not in err
        loose.chmod(0o600)


def test_send_errors_never_carry_the_token(tmp_path):
    def opener(request, timeout):
        raise urllib.error.URLError(f"failed for {request.full_url}")

    with pytest.raises(relay.SendError) as caught:
        relay.Telegram(TOKEN, CHAT, opener=opener, sleep=lambda _s: None).send("x")
    assert TOKEN not in str(caught.value) and "<token>" in str(caught.value)


# ---------------------------------------------------------------- Telegram and acks


def test_send_failure_is_kept_and_retried_without_crashing(tmp_path):
    api, clock = FakeApi(), Clock()
    n = notifier(tmp_path, api, clock)
    api.fail = 3  # every retry of the first cycle fails
    n.alert("anomaly", ["node-1:unit"], "ALERT new: node-1:unit")
    assert api.sent() == [] and len(n.outbox) == 1 and records(tmp_path) == []
    clock.t += 60
    n.tick()
    assert api.sent() == ["TOS testnet ALERT new: node-1:unit"]
    [receipt] = records(tmp_path)
    assert receipt["latency_s"] == 60 and receipt["message_id"] == 101
    assert receipt["raised_utc"] == relay.utc(T0) and receipt["silenced"] is False


def test_a_transient_failure_is_retried_with_backoff(tmp_path):
    api, slept = FakeApi(), []
    api.fail = 2
    t = relay.Telegram(TOKEN, CHAT, opener=api, sleep=slept.append)
    assert t.send("hello") == 101
    assert slept == [1.0, 2.0]
    assert api.calls[0][1] == {
        "chat_id": CHAT,
        "text": "hello",
        "disable_web_page_preview": "true",
    }


def test_a_client_error_is_not_retried():
    calls = []

    def opener(request, timeout):
        calls.append(request)
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {}, None)

    with pytest.raises(relay.SendError, match="HTTP 400"):
        relay.Telegram(TOKEN, CHAT, opener=opener, sleep=lambda _s: None).send("x")
    assert len(calls) == 1


def update(update_id, text, chat=CHAT, date=1_800_000_100, reply_to=None):
    message = {"chat": {"id": int(chat)}, "date": date, "text": text, "from": {"username": "op"}}
    if reply_to:
        message["reply_to_message"] = {"message_id": reply_to}
    return {"update_id": update_id, "message": message}


def test_replies_are_recorded_against_the_last_alert_and_the_offset_advances(tmp_path):
    api, clock = FakeApi(), Clock()
    n = notifier(tmp_path, api, clock)
    acks = relay.Acks(n, tmp_path)
    n.alert("anomaly", ["node-1:unit"], "ALERT new: node-1:unit")
    api.updates = [
        update(500, "on it", reply_to=101),
        update(501, "spam", chat="-999"),
        {"update_id": 502, "edited_message": {}},
    ]
    assert acks.poll(clock.t) == 1
    assert (tmp_path / "telegram-offset").read_text() == "503\n"
    assert api.calls[-2] == ("getUpdates", {"offset": "0", "timeout": "0"})
    assert api.sent()[-1].startswith("TOS testnet acknowledged for anomaly node-1:unit")
    [ack] = records(tmp_path, "acks.jsonl")
    assert ack["text"] == "on it" and ack["reply_to_message_id"] == 101
    assert ack["follows"]["message_id"] == 101 and ack["follows"]["kind"] == "anomaly"
    assert ack["reply_utc"] == relay.utc(1_800_000_100)
    sent_before = len(api.sent())
    assert acks.poll(clock.t + 30) == 0
    assert api.calls[-1] == ("getUpdates", {"offset": "503", "timeout": "0"})
    assert len(api.sent()) == sent_before  # no reply, no confirmation
    # A restarted relay resumes from the saved offset and its last sent alert.
    again = relay.Acks(notifier(tmp_path, api, clock), tmp_path)
    assert again.offset() == 503 and again.notifier.last_sent["message_id"] == 101


def test_a_failed_poll_keeps_the_offset(tmp_path):
    api, clock = FakeApi(), Clock()
    acks = relay.Acks(notifier(tmp_path, api, clock), tmp_path)
    acks.save_offset(42)
    api.fail = 3
    assert acks.poll(clock.t) == 0
    assert acks.offset() == 42


def test_coordinator_polls_replies_every_thirty_seconds(tmp_path):
    api, clock = FakeApi(), Clock()

    def ok(_command):
        return subprocess.CompletedProcess(
            [], 0, stdout=f"now={int(clock.t)}\npeer={int(clock.t)}\n"
        )

    coordinator = relay.Coordinator(
        coordinator_args(tmp_path), telegram(api), ok, clock.now, uptime=lambda: None
    )
    for _ in range(4):
        coordinator.tick()
        clock.t += 15
    assert [m for m, _p in api.calls].count("getUpdates") == 2


# ---------------------------------------------------------------- IPv4-first connect


CONNECT_IPV4_FIRST = relay.connect_ipv4_first  # unpatched, for tests that stub the module's


class FakeSocket:
    """Records its family and timeouts; `connect` follows the address's scripted outcome."""

    def __init__(self, net, family):
        self.net, self.family = net, family
        self.timeouts, self.closed = [], False

    def settimeout(self, value):
        self.timeouts.append(value)

    def bind(self, _address):
        pass

    def setsockopt(self, *_args):
        pass

    def connect(self, sockaddr):
        self.net.tried.append(sockaddr[0])
        outcome = self.net.outcomes.get(sockaddr[0], "ok")
        if outcome == "hang":  # an unrouted address: nothing until the timeout
            self.net.clock.t += self.timeouts[-1]
            raise TimeoutError("timed out")
        if outcome == "refuse":
            raise ConnectionRefusedError(111, "refused")

    def close(self):
        self.closed = True


class FakeNet:
    V6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0))
    V4A = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))
    V4B = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 443))

    def __init__(self, infos, outcomes=None):
        self.infos, self.outcomes = infos, outcomes or {}
        self.tried, self.sockets, self.lookups = [], [], []
        self.clock = Clock(0.0)

    def getaddrinfo(self, host, port, *_rest):
        self.lookups.append((host, port))
        return list(self.infos)

    def socket(self, family, _kind, _proto):
        sock = FakeSocket(self, family)
        self.sockets.append(sock)
        return sock

    def connect(self, timeout=15.0):
        return CONNECT_IPV4_FIRST(
            ("api.telegram.org", 443),
            timeout,
            getaddrinfo=self.getaddrinfo,
            make_socket=self.socket,
        )


def test_ipv4_addresses_are_tried_before_ipv6():
    net = FakeNet([FakeNet.V6, FakeNet.V4A])
    sock = net.connect()
    assert net.tried == ["192.0.2.1"]
    assert sock.timeouts == [relay.CONNECT_TIMEOUT, 15.0]  # short connect, then the request's


def test_a_hanging_address_costs_the_short_timeout_and_the_next_is_used():
    net = FakeNet([FakeNet.V6, FakeNet.V4A, FakeNet.V4B], {"192.0.2.1": "hang"})
    sock = net.connect()
    assert net.tried == ["192.0.2.1", "192.0.2.2"]
    assert net.clock.t == relay.CONNECT_TIMEOUT == 3.0
    assert net.sockets[0].closed and sock is net.sockets[1]
    # IPv6 is still a fallback when every IPv4 address hangs.
    net = FakeNet([FakeNet.V6, FakeNet.V4A], {"192.0.2.1": "hang"})
    net.connect()
    assert net.tried == ["192.0.2.1", "2001:db8::1"] and net.clock.t == 3.0


def test_when_every_address_fails_the_last_error_is_raised():
    net = FakeNet(
        [FakeNet.V6, FakeNet.V4A, FakeNet.V4B],
        {"192.0.2.1": "hang", "192.0.2.2": "hang", "2001:db8::1": "refuse"},
    )
    with pytest.raises(ConnectionRefusedError):
        net.connect()
    assert net.tried == ["192.0.2.1", "192.0.2.2", "2001:db8::1"]
    assert all(s.closed for s in net.sockets)
    with pytest.raises(OSError, match="no address"):
        FakeNet([]).connect()


def test_a_request_timeout_shorter_than_the_connect_timeout_wins():
    net = FakeNet([FakeNet.V4A])
    assert net.connect(timeout=1.0).timeouts == [1.0, 1.0]


def test_telegram_requests_connect_through_the_ipv4_first_path(monkeypatch):
    seen = []

    def refuse(address, timeout, source_address=None):
        seen.append((address, timeout))
        raise ConnectionRefusedError(111, "stub refused")

    monkeypatch.setattr(relay, "connect_ipv4_first", refuse)
    t = relay.Telegram(TOKEN, CHAT, sleep=lambda _s: None, attempts=1)
    with pytest.raises(relay.SendError, match="stub refused"):
        t.send("x")
    assert seen == [(("api.telegram.org", 443), 15.0)]


def test_the_https_connection_wraps_the_ipv4_first_socket_in_tls(monkeypatch):
    net = FakeNet([FakeNet.V4A])
    wrapped = []

    class Context:
        def wrap_socket(self, sock, server_hostname):
            wrapped.append((sock, server_hostname))
            return sock

    monkeypatch.setattr(relay, "connect_ipv4_first", lambda a, t, s=None: net.connect(t))
    conn = relay.IPv4FirstHTTPSConnection("api.telegram.org", timeout=15.0, context=Context())
    conn.connect()
    assert net.tried == ["192.0.2.1"]
    assert wrapped == [(net.sockets[0], "api.telegram.org")]


# ---------------------------------------------------------------- dead-man budget


def test_dead_after_defaults_to_150_s_in_the_script_and_both_units():
    parser = relay.build_parser()
    for role in ("coordinator", "peer"):
        argv = [role, "--token-file", "t", "--chat-file", "c"]
        if role == "coordinator":
            argv += ["--state-dir", "s", "--inventory", "i", "--peer", "p"]
        assert parser.parse_args(argv).dead_after == 150.0
    for unit in ("tos-testnet-alert-peer.service", "tos-testnet-alert-coordinator.service"):
        text = (SCRIPTS.parent / "systemd" / unit).read_text()
        assert "  --dead-after 150\n" in text and "--interval 60" in text


def test_a_stopped_coordinator_is_reported_well_inside_five_minutes(tmp_path):
    # Worst phase: the coordinator's last beat lands just after a peer check.
    api, clock = FakeApi(), Clock()
    theirs = tmp_path / "heartbeat-coordinator"
    theirs.touch()
    os.utime(theirs, (T0, T0))
    args = peer_args(tmp_path)
    args.dead_after = relay.DEAD_AFTER
    clock.t = T0 - 59
    peer = relay.Peer(args, telegram(api), clock.now)
    while not api.sent():
        peer.tick()
        clock.t += args.interval
    alerted = clock.t - args.interval
    assert alerted - T0 <= relay.DEAD_AFTER + args.interval
    t = relay.Telegram(TOKEN, CHAT, opener=api)
    worst_send = t.attempts * t.timeout + sum(2.0**i for i in range(t.attempts - 1))
    assert relay.DEAD_AFTER + args.interval + worst_send < 300 - 30


# ---------------------------------------------------------------- peer reads replies


def test_peer_reads_replies_only_while_the_coordinator_is_dead(tmp_path):
    api, clock = FakeApi(), Clock()
    theirs = tmp_path / "heartbeat-coordinator"
    theirs.touch()
    os.utime(theirs, (T0, T0))
    peer = relay.Peer(peer_args(tmp_path), telegram(api), clock.now)
    assert peer.period() == 60.0
    for _ in range(6):  # T0 .. T0 + 300: fresh enough, the coordinator reads
        peer.tick()
        clock.t += 60
    assert [m for m, _p in api.calls] == []
    api.updates = [update(700, "seen, looking", reply_to=101)]
    peer.tick()  # T0 + 360: dead, alert, then the first read
    assert [m for m, _p in api.calls] == ["sendMessage", "getUpdates", "sendMessage"]
    assert "coordinator heartbeat stale" in api.sent()[0]
    assert api.sent()[1].startswith(
        "TOS testnet acknowledged for heartbeat-dead coordinator:heartbeat"
    )
    [ack] = records(tmp_path, "acks.jsonl")
    assert ack["text"] == "seen, looking" and ack["update_id"] == 700
    assert ack["follows"]["kind"] == "heartbeat-dead" and ack["follows"]["message_id"] == 101
    assert (tmp_path / "telegram-offset").read_text() == "701\n"
    assert peer.period() == 30.0
    clock.t += 15
    peer.tick()  # not due yet
    clock.t += 15
    peer.tick()  # 30 s on: due, offset kept, nothing new, no confirmation
    assert [m for m, _p in api.calls].count("getUpdates") == 2
    assert api.calls[-1] == ("getUpdates", {"offset": "701", "timeout": "0"})
    assert len(api.sent()) == 2
    os.utime(theirs, (clock.t, clock.t))  # the coordinator is back
    clock.t += 30
    peer.tick()
    assert "RECOVERED coordinator heartbeat" in api.sent()[-1]
    for _ in range(4):
        clock.t += 30
        peer.tick()
    assert [m for m, _p in api.calls].count("getUpdates") == 2
    assert peer.period() == 60.0


# ---------------------------------------------------------------- non-root peer


def test_peer_unit_runs_as_its_own_user_with_root_only_secrets_as_credentials():
    text = (SCRIPTS.parent / "systemd" / "tos-testnet-alert-peer.service").read_text()
    assert "User=tos-alert\n" in text and "Group=tos-alert\n" in text
    assert "User=root" not in text
    assert "LoadCredential=token:/etc/tos-alert/token\n" in text
    assert "LoadCredential=chat:/etc/tos-alert/chat\n" in text
    assert "--token-file ${CREDENTIALS_DIRECTORY}/token" in text
    assert "--chat-file ${CREDENTIALS_DIRECTORY}/chat" in text
    assert "StateDirectory=tos-alert\n" in text and "CapabilityBoundingSet=\n" in text


def test_a_systemd_credential_with_acl_group_bits_is_read(tmp_path, monkeypatch):
    creds = tmp_path / "credentials"
    creds.mkdir()
    token = creds / "token"
    token.write_text(TOKEN + "\n")
    token.chmod(0o440)  # what an ACL mask of r-- shows as
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    assert relay.read_secret(token, "token") == TOKEN
    outside = tmp_path / "token"
    outside.write_text(TOKEN + "\n")
    outside.chmod(0o440)
    with pytest.raises(lib.TestnetError, match="readable by group or others"):
        relay.read_secret(outside, "token")
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    with pytest.raises(lib.TestnetError, match="readable by group or others"):
        relay.read_secret(token, "token")


def test_silence_written_by_root_is_handed_to_the_directory_owner(tmp_path, monkeypatch):
    chowned = []
    monkeypatch.setattr(relay.os, "geteuid", lambda: 0)
    monkeypatch.setattr(relay.os, "chown", lambda p, u, g: chowned.append((str(p), u, g)))
    owner = tmp_path.stat()
    relay.write_silence(tmp_path / "silence", T0 + 60, "work")
    assert chowned == [(str(tmp_path / "silence.tmp"), owner.st_uid, owner.st_gid)]
    assert (tmp_path / "silence").stat().st_mode & 0o777 == 0o600
    assert relay.read_silence(tmp_path / "silence") == (int(T0 + 60), "work")


def test_silence_written_by_the_owner_is_not_chowned(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    chowned = []
    monkeypatch.setattr(relay.os, "chown", lambda *a: chowned.append(a))
    relay.write_silence(tmp_path / "silence", T0 + 60, "work")
    assert chowned == []


def test_root_never_gives_a_file_to_root_when_the_directory_is_roots(tmp_path, monkeypatch):
    chowned = []
    monkeypatch.setattr(relay.os, "geteuid", lambda: 0)
    monkeypatch.setattr(relay.os, "chown", lambda *a: chowned.append(a))
    real_stat = relay.Path.stat

    def stat(self, *args, **kwargs):
        info = real_stat(self, *args, **kwargs)
        if self == tmp_path:
            return os.stat_result((info.st_mode, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return info

    monkeypatch.setattr(relay.Path, "stat", stat)
    (tmp_path / "f").touch()
    relay.give_to_directory_owner(tmp_path / "f")
    assert chowned == []


def test_remote_beat_command_hands_the_coordinator_beat_to_the_directory_owner(tmp_path):
    command = relay.remote_beat_command(str(tmp_path))
    assert f"chown --reference={tmp_path} {tmp_path}/heartbeat-coordinator" in command
    (tmp_path / "heartbeat-peer").touch()
    out = subprocess.run(["bash", "-c", command], capture_output=True, text=True, check=True)
    assert relay.parse_remote_beat(out.stdout) is not None
    beat = (tmp_path / "heartbeat-coordinator").stat()
    assert beat.st_uid == tmp_path.stat().st_uid
