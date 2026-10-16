#!/usr/bin/env python3
"""Relay testnet anomalies to a person over Telegram, with a two-host dead-man check.

  alert-relay.py coordinator --token-file F --chat-file F --state-dir DIR
                 --inventory hosts.json --peer node-dht
                 [--interval 60] [--dead-after 150] [--watch-interval 60]
                 [--digest-hours 0] [--silence-file PATH] [--remote-dir /var/lib/tos-alert]
  alert-relay.py peer --token-file F --chat-file F [--state-dir /var/lib/tos-alert]
                 [--interval 60] [--dead-after 150] [--silence-file PATH]
  alert-relay.py silence --until <ISO time | +MINUTES> --reason TEXT
                 [--state-dir DIR | --silence-file PATH]
  alert-relay.py unsilence [--state-dir DIR | --silence-file PATH]

coordinator runs on the coordinator. It keeps watch-testnet.py running as a
child without a duration (restarting it 30 s after it exits) and reads its
stdout. An `ANOMALY` line carries tokens such as `node-1:head_age=155s`; the
relay keys each one by host and kind (`node-1:head_age`), ignoring the value
that changes every round. It sends a message when a key first appears, at
most one reminder per key every 30 minutes while it persists, and a recovery
message when keys clear (a shorter `ANOMALY` set or a `RECOVERED` line).
`SUMMARY` lines are not sent unless --digest-hours asks for one digest every
that many hours. Every --interval seconds it touches the coordinator heartbeat
on the peer host over SSH and reads the age of the peer's heartbeat there; a
heartbeat older than --dead-after, or unreadable for that long, is alerted
once and its return is reported. Every 30 s it reads replies from the chat
(getUpdates, offset kept in the state directory), records each in acks.jsonl
against the most recent alert, and confirms it.

peer runs as root on the DHT host. Every --interval seconds it touches
heartbeat-peer in its state directory and checks the age of
heartbeat-coordinator (written there by the coordinator); it alerts once when
that is older than --dead-after and reports the recovery. It has no chain
access: the validators' JSON-RPC answers on loopback only, so the peer can say
that the coordinator's watch stopped, not what the chain is doing.

While the coordinator's heartbeat is dead the peer reads replies itself, every
30 s, with its own offset file, records them in its own acks.jsonl against its
own last alert and confirms them; once the beat is fresh it stops, so only one
host polls at a time. getUpdates confirms what it returns on Telegram's side,
so a reply read by one host is never seen by the other: the acknowledgement
receipts are split across the two hosts' acks.jsonl files.

Each heartbeat age is computed on the host that holds the file, with that
host's clock, so clock skew between the hosts does not move it.

Every alert, sent or not, is appended to alerts.jsonl in the state directory
(utc, kind, keys, text, Telegram message_id, send latency): the receipt that
a person was told and when. While the silence file holds an expiry time in the
future, alerts are recorded with `"silenced": true` and not sent; when it
expires (or `unsilence` removes it) one message lists what was suppressed. The
silence file is one line: `<expiry unix time> <reason>`. Silence each host
separately: the peer reads its own file.

Telegram connections try every IPv4 address of the API host before any IPv6
one, each with a short connect timeout, so a host whose IPv6 route hangs does
not stall a send until the request timeout.

The bot token and the chat id are read from --token-file and --chat-file,
which must not be readable by group or others; they are never printed. A send
that fails is retried with backoff, then kept and retried next cycle; it never
stops the loop.

Exit status: 0 for silence/unsilence, 1 on a refusal (bad file mode, bad
inventory, bad --until); the two loops run until stopped.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import queue
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import preflight  # noqa: E402
import testnet_lib as lib  # noqa: E402

WATCH = Path(__file__).resolve().parent / "watch-testnet.py"
API = "https://api.telegram.org"
REMOTE_DIR = "/var/lib/tos-alert"
PEER_BEAT = "heartbeat-peer"
COORDINATOR_BEAT = "heartbeat-coordinator"
ALERTS = "alerts.jsonl"
ACKS = "acks.jsonl"
OFFSET = "telegram-offset"
SILENCE = "silence"
REMINDER_EVERY = 1800.0
ACK_EVERY = 30.0
# Two missed coordinator beats (one per --interval, 60 s) plus SSH slack. A
# stopped side is reported at most dead-after + one interval (the check runs
# once per interval) + the send (three attempts of at most 15 s each, plus 3 s
# of backoff) after its last beat: 150 + 60 + 48 = 258 s worst case, about
# 215 s with a prompt send, inside the 5-minute alert budget. 300 s would spend
# the whole budget on waiting alone.
DEAD_AFTER = 150.0
CONNECT_TIMEOUT = 3.0
WATCH_RESTART_DELAY = 30.0
OUTBOX_LIMIT = 200
TEXT_LIMIT = 3900
PREFIX = "TOS testnet"


def utc(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    print(f"{utc(time.time())} {message}", file=sys.stderr, flush=True)


def append_jsonl(path: Path, record: dict) -> None:
    with open(path, "a") as out:
        out.write(json.dumps(record, sort_keys=True) + "\n")


def read_secret(path: Path, what: str) -> str:
    """A secret from a file only its owner can read; refuse anything looser."""
    path = Path(path)
    try:
        info = path.stat()
    except OSError as exc:
        raise lib.TestnetError(f"{what} file {path} cannot be read: {exc.strerror}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise lib.TestnetError(f"{what} file {path} is not a regular file")
    if info.st_mode & 0o077:
        raise lib.TestnetError(
            f"{what} file {path} is readable by group or others (mode "
            f"{stat.S_IMODE(info.st_mode):04o}); chmod 600 it"
        )
    value = path.read_text().strip()
    if not value or any(c.isspace() for c in value):
        raise lib.TestnetError(f"{what} file {path} must hold one non-empty value")
    return value


# ---------------------------------------------------------------- Telegram


def connect_ipv4_first(
    address: tuple[str, int],
    timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
    source_address=None,
    *,
    connect_timeout: float = CONNECT_TIMEOUT,
    getaddrinfo=socket.getaddrinfo,
    make_socket=socket.socket,
) -> socket.socket:
    """A TCP connection trying every IPv4 address before any IPv6 one.

    Each address gets at most `connect_timeout` to connect, so an address
    family without a working route (IPv6 that hangs instead of refusing) costs
    seconds, not the whole request timeout. The connected socket then uses
    `timeout` for the request itself. Raises the last address's error when
    none connects.
    """
    host, port = address
    infos = getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    ordered = [i for i in infos if i[0] == socket.AF_INET] + [
        i for i in infos if i[0] != socket.AF_INET
    ]
    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
        timeout = socket.getdefaulttimeout()
    per_address = connect_timeout if timeout is None else min(connect_timeout, timeout)
    failure: OSError | None = None
    for family, kind, proto, _name, sockaddr in ordered:
        sock = None
        try:
            sock = make_socket(family, kind, proto)
            sock.settimeout(per_address)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
        except OSError as exc:
            failure = exc
            if sock is not None:
                sock.close()
            continue
        sock.settimeout(timeout)
        return sock
    if failure is None:
        failure = OSError(f"no address found for {host}")
    raise failure


class IPv4FirstHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection whose TCP connect goes through connect_ipv4_first."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = connect_ipv4_first


class IPv4FirstHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self):
        self.tls = ssl.create_default_context()
        super().__init__(context=self.tls)

    def https_open(self, req):
        return self.do_open(IPv4FirstHTTPSConnection, req, context=self.tls)


def ipv4_first_opener():
    return urllib.request.build_opener(IPv4FirstHTTPSHandler()).open


class SendError(Exception):
    """A Telegram call that failed after its retries; the message carries no secret."""


class Telegram:
    """sendMessage and getUpdates over urllib, retried with backoff."""

    def __init__(
        self,
        token: str,
        chat_id: str,
        opener=None,
        sleep=time.sleep,
        attempts: int = 3,
        timeout: float = 15.0,
    ):
        self.token, self.chat_id = token, chat_id
        self.opener = opener if opener is not None else ipv4_first_opener()
        self.sleep = sleep
        self.attempts, self.timeout = attempts, timeout

    def scrub(self, text: str) -> str:
        return text.replace(self.token, "<token>").replace(self.chat_id, "<chat>")

    def call(self, method: str, params: dict):
        request = urllib.request.Request(
            f"{API}/bot{self.token}/{method}", data=urllib.parse.urlencode(params).encode()
        )
        delay, failure = 1.0, "no attempt"
        for attempt in range(self.attempts):
            try:
                with self.opener(request, timeout=self.timeout) as response:
                    body = json.loads(response.read().decode())
            except urllib.error.HTTPError as exc:
                failure = f"HTTP {exc.code}"
                if 400 <= exc.code < 500 and exc.code != 429:
                    break
            except (OSError, ValueError) as exc:
                failure = f"{type(exc).__name__}: {self.scrub(str(exc))}"
            else:
                if not isinstance(body, dict) or not body.get("ok"):
                    description = body.get("description") if isinstance(body, dict) else None
                    raise SendError(f"{method} refused: {self.scrub(str(description))}")
                return body.get("result")
            if attempt + 1 < self.attempts:
                self.sleep(delay)
                delay *= 2
        raise SendError(f"{method} failed: {failure}")

    def send(self, text: str) -> int | None:
        result = self.call(
            "sendMessage",
            {
                "chat_id": self.chat_id,
                "text": text[:TEXT_LIMIT],
                "disable_web_page_preview": "true",
            },
        )
        return result.get("message_id") if isinstance(result, dict) else None

    def updates(self, offset: int) -> list[dict]:
        result = self.call("getUpdates", {"offset": offset, "timeout": 0})
        return [u for u in result if isinstance(u, dict)] if isinstance(result, list) else []


# ---------------------------------------------------------------- silence


def parse_until(value: str, now: float) -> float:
    if value.startswith("+"):
        minutes = float(value[1:])
        if minutes <= 0:
            raise lib.TestnetError("--until +MINUTES must be positive")
        return now + minutes * 60
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    until = moment.timestamp()
    if until <= now:
        raise lib.TestnetError(f"--until {value} is not in the future")
    return until


def read_silence(path: Path) -> tuple[float, str] | None:
    """(expiry, reason) from the silence file, or None; a malformed file silences nothing."""
    try:
        text = Path(path).read_text().strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        log(f"silence file unreadable, alerts are sent: {exc.strerror}")
        return None
    head, _, reason = text.partition(" ")
    try:
        return float(head), reason.strip()
    except ValueError:
        log("silence file malformed, alerts are sent")
        return None


def write_silence(path: Path, until: float, reason: str) -> None:
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(f"{int(until)} {' '.join(reason.split())}\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------- alert sink


class Notifier:
    """Sends or, while silenced, only records each alert; keeps unsent ones for the next cycle."""

    def __init__(self, telegram: Telegram, state_dir: Path, silence_file: Path, now=time.time):
        self.telegram, self.now = telegram, now
        self.alerts = Path(state_dir) / ALERTS
        self.silence_file = Path(silence_file)
        self.outbox: list[dict] = []
        self.suppressed: list[dict] = []
        self.silence: tuple[float, str] | None = None
        self.last_sent: dict | None = self._last_sent_from_file()

    def _last_sent_from_file(self) -> dict | None:
        try:
            lines = self.alerts.read_text().splitlines()
        except FileNotFoundError:
            return None
        for line in reversed(lines):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("message_id") is not None:
                return record
        return None

    def silenced(self) -> tuple[float, str] | None:
        found = read_silence(self.silence_file)
        return found if found and found[0] > self.now() else None

    def alert(self, kind: str, keys: list[str], text: str) -> None:
        raised = self.now()
        record = {"raised": raised, "kind": kind, "keys": sorted(keys), "text": text}
        silence = self.silenced()
        if silence and kind != "silence-summary":
            self.suppressed.append(record)
            self.silence = silence
            append_jsonl(
                self.alerts,
                {
                    "utc": utc(raised),
                    "kind": kind,
                    "keys": record["keys"],
                    "text": text,
                    "message_id": None,
                    "latency_s": None,
                    "silenced": True,
                    "silence_reason": silence[1],
                },
            )
            return
        self.outbox.append(record)
        if len(self.outbox) > OUTBOX_LIMIT:
            dropped = self.outbox.pop(0)
            log(f"outbox full, dropped an unsent {dropped['kind']} alert")
            append_jsonl(
                self.alerts,
                {
                    "utc": utc(dropped["raised"]),
                    "kind": dropped["kind"],
                    "keys": dropped["keys"],
                    "text": dropped["text"],
                    "message_id": None,
                    "latency_s": None,
                    "silenced": False,
                    "dropped": True,
                },
            )
        self.flush()

    def flush(self) -> None:
        while self.outbox:
            record = self.outbox[0]
            try:
                message_id = self.telegram.send(f"{PREFIX} {record['text']}")
            except SendError as exc:
                log(f"send failed, {len(self.outbox)} alert(s) kept for the next cycle: {exc}")
                return
            sent = self.now()
            self.outbox.pop(0)
            receipt = {
                "utc": utc(sent),
                "raised_utc": utc(record["raised"]),
                "kind": record["kind"],
                "keys": record["keys"],
                "text": record["text"],
                "message_id": message_id,
                "latency_s": round(sent - record["raised"], 3),
                "silenced": False,
            }
            append_jsonl(self.alerts, receipt)
            self.last_sent = receipt

    def tick(self, still_active: list[str] = ()) -> None:
        """End-of-silence summary, then a retry of anything unsent."""
        silence = self.silenced()
        if silence:
            self.silence = silence
        elif self.silence is not None:
            reason, self.silence = self.silence[1], None
            lines = [f"silence ended ({reason or 'no reason given'});"]
            if self.suppressed:
                lines[0] += f" {len(self.suppressed)} alert(s) were suppressed:"
                lines += [
                    f"{utc(r['raised'])} {r['kind']} {' '.join(r['keys'])}" for r in self.suppressed
                ]
            else:
                lines[0] += " nothing was suppressed."
            if still_active:
                lines.append(f"still active: {' '.join(sorted(still_active))}")
            self.suppressed = []
            self.alert("silence-summary", list(still_active), "\n".join(lines))
        self.flush()


# ---------------------------------------------------------------- heartbeats


class Heartbeat:
    """Dead when the other side's beat is older than dead_after, or unreadable for that long."""

    def __init__(self, label: str, dead_after: float, started: float):
        self.label, self.dead_after = label, dead_after
        self.last_good = started
        self.dead = False

    def observe(self, now: float, age: float | None) -> str | None:
        """'dead' or 'alive' on a change, else None. `age` is None when unreadable."""
        if age is not None:
            self.last_good = max(self.last_good, now - age)
        stale = now - self.last_good > self.dead_after
        if stale and not self.dead:
            self.dead = True
            return "dead"
        if not stale and self.dead:
            self.dead = False
            return "alive"
        return None

    def text(self, event: str, now: float, age: float | None, what: str) -> str:
        if event == "dead":
            state = "unreadable" if age is None else f"{int(age)} s old"
            return (
                f"ALERT {self.label} heartbeat stale: no fresh beat for "
                f"{int(now - self.last_good)} s, now {state} (dead after "
                f"{int(self.dead_after)} s). {what}"
            )
        return f"RECOVERED {self.label} heartbeat is fresh again (age {int(age or 0)} s)."


def report_heartbeat(notifier: Notifier, beat: Heartbeat, now: float, age, what: str) -> None:
    event = beat.observe(now, age)
    if event:
        notifier.alert(
            f"heartbeat-{event}", [f"{beat.label}:heartbeat"], beat.text(event, now, age, what)
        )


def parse_remote_beat(stdout: str) -> float | None:
    """The peer beat age from `now=<s>` and `peer=<mtime or ->` lines."""
    values = dict(line.split("=", 1) for line in stdout.split() if "=" in line)
    try:
        return max(0.0, float(values["now"]) - float(values["peer"]))
    except (KeyError, ValueError):
        return None


def remote_beat_command(remote_dir: str) -> str:
    return (
        f"touch {remote_dir}/{COORDINATOR_BEAT} && echo now=$(date +%s) && "
        f"echo peer=$(stat -c %Y {remote_dir}/{PEER_BEAT} 2>/dev/null || echo -)"
    )


def local_beat(state_dir: Path, own: str, other: str, now: float) -> float | None:
    """Touch our beat; the other side's age by this host's clock, or None."""
    own_path = Path(state_dir) / own
    own_path.touch()
    os.utime(own_path, (now, now))
    try:
        return max(0.0, now - (Path(state_dir) / other).stat().st_mtime)
    except OSError:
        return None


# ---------------------------------------------------------------- anomaly keys


def anomaly_keys(line: str) -> dict[str, str]:
    """{host:kind: token} from `ANOMALY <utc> host:kind=value host:kind ...`."""
    out = {}
    for token in line.split()[2:]:
        host, sep, rest = token.partition(":")
        if not sep or not host or not rest:
            continue
        out[f"{host}:{rest.split('=', 1)[0]}"] = token
    return out


class AnomalyTracker:
    """New keys, reminders and recoveries from the watch's event lines."""

    def __init__(self, notifier: Notifier, digest_every: float = 0.0):
        self.notifier = notifier
        self.digest_every = digest_every
        self.active: dict[str, dict] = {}
        self.last_line = ""
        self.fresh_child = True
        self.last_digest: float | None = None

    def child_started(self) -> None:
        # A restarted watch prints ANOMALY only when its first round finds some,
        # so a first SUMMARY with no ANOMALY before it means all clear.
        self.fresh_child = True

    def child_exited(self, status: int, now: float) -> None:
        key = "watch:exited"
        if key not in self.active:
            self.active[key] = {"since": now, "reminded": now}
            self.notifier.alert(
                "anomaly",
                [key],
                f"ALERT watch-testnet.py exited with status {status}; restarting it in "
                f"{int(WATCH_RESTART_DELAY)} s. No chain observation until it is back.",
            )

    def _clear(self, keys: list[str], now: float, line: str) -> None:
        if not keys:
            return
        parts = []
        for key in sorted(keys):
            since = self.active.pop(key)["since"]
            parts.append(f"{key} (after {int((now - since) // 60)} min)")
        text = f"RECOVERED {', '.join(parts)}"
        if line:
            text += f"\n{line}"
        if self.active:
            text += f"\nstill active: {' '.join(sorted(self.active))}"
        self.notifier.alert("recovered", sorted(keys), text)

    def on_line(self, line: str, now: float) -> None:
        line = line.strip()
        word = line.split(" ", 1)[0]
        if "watch:exited" in self.active and word:
            self._clear(["watch:exited"], now, "")
        if word == "ANOMALY":
            self.fresh_child = False
            self.last_line = line
            current = anomaly_keys(line)
            self._clear([k for k in self.active if k not in current], now, line)
            new = [k for k in current if k not in self.active]
            for key in new:
                self.active[key] = {"since": now, "reminded": now}
            if new:
                self.notifier.alert("anomaly", new, f"ALERT new: {' '.join(sorted(new))}\n{line}")
        elif word == "RECOVERED":
            self.fresh_child = False
            self._clear(list(self.active), now, line)
        elif word == "SUMMARY":
            if self.fresh_child:
                self.fresh_child = False
                self._clear(list(self.active), now, "first round after a watch restart is clear")
            if self.digest_every > 0 and (
                self.last_digest is None or now - self.last_digest >= self.digest_every
            ):
                self.last_digest = now
                self.notifier.alert("digest", [], f"digest\n{line}")

    def tick(self, now: float) -> None:
        due = [k for k, v in self.active.items() if now - v["reminded"] >= REMINDER_EVERY]
        if not due:
            return
        for key in due:
            self.active[key]["reminded"] = now
        oldest = min(self.active[k]["since"] for k in due)
        text = f"REMINDER still active ({int((now - oldest) // 60)} min): {' '.join(sorted(due))}"
        if self.last_line:
            text += f"\nlast: {self.last_line}"
        self.notifier.alert("reminder", sorted(due), text)


# ---------------------------------------------------------------- acknowledgements


class Acks:
    """Replies from the configured chat, recorded against the alert they follow."""

    def __init__(self, notifier: Notifier, state_dir: Path):
        self.notifier = notifier
        self.telegram = notifier.telegram
        self.offset_file = Path(state_dir) / OFFSET
        self.acks = Path(state_dir) / ACKS

    def offset(self) -> int:
        try:
            return int(self.offset_file.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def save_offset(self, value: int) -> None:
        tmp = self.offset_file.with_name(OFFSET + ".tmp")
        tmp.write_text(f"{value}\n")
        os.replace(tmp, self.offset_file)

    def poll(self, now: float) -> int:
        """Record new replies; returns how many were acknowledgements."""
        try:
            updates = self.telegram.updates(self.offset())
        except SendError as exc:
            log(f"reading replies failed, retried next cycle: {exc}")
            return 0
        recorded, next_offset = 0, None
        for update in updates:
            update_id = update.get("update_id")
            if isinstance(update_id, int):
                next_offset = max(next_offset or 0, update_id + 1)
            message = update.get("message")
            if not isinstance(message, dict):
                continue
            if str((message.get("chat") or {}).get("id")) != self.telegram.chat_id:
                continue
            follows = self.notifier.last_sent
            reply_to = (message.get("reply_to_message") or {}).get("message_id")
            date = message.get("date")
            append_jsonl(
                self.acks,
                {
                    "utc": utc(now),
                    "reply_utc": utc(date) if isinstance(date, int) else None,
                    "update_id": update_id,
                    "from": (message.get("from") or {}).get("username"),
                    "text": message.get("text", ""),
                    "reply_to_message_id": reply_to,
                    "follows": None
                    if follows is None
                    else {k: follows.get(k) for k in ("utc", "kind", "keys", "message_id")},
                },
            )
            recorded += 1
        if next_offset is not None:
            self.save_offset(next_offset)
        if recorded:
            about = (
                f" for {self.notifier.last_sent['kind']} {' '.join(self.notifier.last_sent['keys'])}"
                if self.notifier.last_sent
                else ""
            )
            try:
                self.telegram.send(f"{PREFIX} acknowledged{about} ({utc(now)}).")
            except SendError as exc:
                log(f"acknowledgement confirmation not sent: {exc}")
        return recorded


# ---------------------------------------------------------------- roles


class Coordinator:
    """Everything the coordinator does per line and per tick, without processes or sleeps."""

    def __init__(self, args, telegram: Telegram, ssh, now=time.time):
        self.args, self.ssh, self.now = args, ssh, now
        started = now()
        self.notifier = Notifier(telegram, args.state_dir, args.silence_file, now)
        self.tracker = AnomalyTracker(self.notifier, args.digest_hours * 3600)
        self.acks = Acks(self.notifier, args.state_dir)
        self.beat = Heartbeat("peer", args.dead_after, started)
        self.next_beat = started
        self.next_ack = started

    def peer_age(self) -> float | None:
        try:
            result = self.ssh(remote_beat_command(self.args.remote_dir))
        except (OSError, subprocess.TimeoutExpired) as exc:
            log(f"peer heartbeat: {type(exc).__name__}")
            return None
        if result.returncode != 0:
            log(f"peer heartbeat: ssh exited {result.returncode}")
            return None
        return parse_remote_beat(result.stdout)

    def tick(self) -> None:
        now = self.now()
        if now >= self.next_beat:
            self.next_beat = now + self.args.interval
            report_heartbeat(
                self.notifier,
                self.beat,
                now,
                self.peer_age(),
                "The DHT-host watchdog cannot see this coordinator; check the peer host.",
            )
        if now >= self.next_ack:
            self.next_ack = now + ACK_EVERY
            self.acks.poll(now)
        self.tracker.tick(now)
        self.notifier.tick(list(self.tracker.active))


class Peer:
    """Watches the coordinator's beat; reads replies only while that beat is dead.

    The coordinator is the one reader of replies while it lives. When its beat
    is dead the peer takes over, so replies to the peer's own alerts are
    recorded and confirmed. It stops as soon as the beat is fresh, so the two
    hosts never poll getUpdates at the same time and split each other's replies.
    """

    def __init__(self, args, telegram: Telegram, now=time.time):
        self.args, self.now = args, now
        started = now()
        self.notifier = Notifier(telegram, args.state_dir, args.silence_file, now)
        self.acks = Acks(self.notifier, args.state_dir)
        self.beat = Heartbeat("coordinator", args.dead_after, started)
        self.next_ack = started

    def period(self) -> float:
        """Seconds to the next tick: faster while this host reads the replies."""
        return min(self.args.interval, ACK_EVERY) if self.beat.dead else self.args.interval

    def tick(self) -> None:
        now = self.now()
        try:
            age = local_beat(self.args.state_dir, PEER_BEAT, COORDINATOR_BEAT, now)
        except OSError as exc:
            log(f"own heartbeat not written: {exc.strerror}")
            age = None
        report_heartbeat(
            self.notifier,
            self.beat,
            now,
            age,
            "The coordinator stopped writing it: its chain watch and alerts may be down.",
        )
        if self.beat.dead and now >= self.next_ack:
            self.next_ack = now + ACK_EVERY
            self.acks.poll(now)
        self.notifier.tick()


def watch_argv(args) -> list[str]:
    return [
        sys.executable,
        str(WATCH),
        "--inventory",
        str(args.inventory),
        "--out",
        str(Path(args.state_dir) / "series.tsv"),
        "--interval",
        f"{args.watch_interval:g}",
        "--summary-every",
        "3600",
    ]


def run_coordinator(args, telegram: Telegram) -> int:
    hosts = {h.name: h for h in preflight.load_inventory(args.inventory)}
    if args.peer not in hosts:
        raise lib.TestnetError(f"--peer {args.peer} is not in the inventory")
    peer_host = hosts[args.peer]

    def ssh(command: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            preflight.ssh_argv(peer_host, accept_new=False) + [command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    coordinator = Coordinator(args, telegram, ssh)
    lines: queue.Queue = queue.Queue()
    child, restart_at = None, 0.0

    def pump(stream) -> None:
        for raw in stream:
            lines.put(raw)

    while True:
        now = time.time()
        if child is not None and child.poll() is not None:
            log(f"watch-testnet.py exited {child.returncode}")
            coordinator.tracker.child_exited(child.returncode, now)
            child, restart_at = None, now + WATCH_RESTART_DELAY
        if child is None and now >= restart_at:
            child = subprocess.Popen(watch_argv(args), stdout=subprocess.PIPE, text=True)
            coordinator.tracker.child_started()
            threading.Thread(target=pump, args=(child.stdout,), daemon=True).start()
        try:
            line = lines.get(timeout=1.0)
        except queue.Empty:
            pass
        else:
            print(line, end="", flush=True)
            coordinator.tracker.on_line(line, time.time())
        coordinator.tick()


def run_peer(args, telegram: Telegram) -> int:
    peer = Peer(args, telegram)
    while True:
        started = time.time()
        peer.tick()
        time.sleep(max(1.0, peer.period() - (time.time() - started)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    roles = {}
    for name, default_state in (("coordinator", None), ("peer", REMOTE_DIR)):
        p = sub.add_parser(name)
        p.add_argument("--token-file", type=Path, required=True)
        p.add_argument("--chat-file", type=Path, required=True)
        p.add_argument(
            "--state-dir", type=Path, required=default_state is None, default=default_state
        )
        p.add_argument("--silence-file", type=Path)
        p.add_argument("--interval", type=float, default=60.0)
        p.add_argument("--dead-after", type=float, default=DEAD_AFTER)
        roles[name] = p
    roles["coordinator"].add_argument("--inventory", type=Path, required=True)
    roles["coordinator"].add_argument("--peer", required=True)
    roles["coordinator"].add_argument("--remote-dir", default=REMOTE_DIR)
    roles["coordinator"].add_argument("--watch-interval", type=float, default=60.0)
    roles["coordinator"].add_argument("--digest-hours", type=float, default=0.0)
    for name in ("silence", "unsilence"):
        p = sub.add_parser(name)
        where = p.add_mutually_exclusive_group()
        where.add_argument("--state-dir", type=Path, default=Path(REMOTE_DIR))
        where.add_argument("--silence-file", type=Path)
        if name == "silence":
            p.add_argument("--until", required=True)
            p.add_argument("--reason", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "silence_file", None) is None:
        args.silence_file = Path(args.state_dir) / SILENCE
    try:
        if args.command == "silence":
            if not args.reason.strip():
                parser.error("--reason must not be empty")
            until = parse_until(args.until, time.time())
            write_silence(args.silence_file, until, args.reason)
            print(f"SILENCED until {utc(until)} in {args.silence_file}")
            return 0
        if args.command == "unsilence":
            args.silence_file.unlink(missing_ok=True)
            print(f"UNSILENCED {args.silence_file}")
            return 0
        if args.interval < 1 or args.dead_after <= args.interval:
            parser.error("--interval must be at least 1 s and --dead-after above it")
        if args.command == "coordinator" and (args.watch_interval < 1 or args.digest_hours < 0):
            parser.error("--watch-interval must be at least 1 s and --digest-hours not negative")
        token = read_secret(args.token_file, "token")
        chat_id = read_secret(args.chat_file, "chat")
        lib.private_dir(args.state_dir)
        telegram = Telegram(token, chat_id)
        if args.command == "coordinator":
            return run_coordinator(args, telegram)
        return run_peer(args, telegram)
    except (lib.TestnetError, OSError, KeyError, ValueError) as exc:
        print(f"REFUSED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
