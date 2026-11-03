"""Funding fences and real StateInit decoding; no live network or public sends."""

import asyncio
import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import nacl.signing
from pytosiq_core import Cell, StateInit, begin_cell

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "production"))
import br1_fund as fund
from con01_history.certificate import Refused


class Readiness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.reports = {
            "resource_gate": dict(
                result="PASS",
                observed_seconds=86400,
                identity_matches=True,
                resource_limits_passed=True,
                samples_complete=True,
                node_count=4,
                engine_sha256="8ca8b37ecdaedfc8355415c7206c90192f28c5b88ea145be6eebd0ee5145a70c",
                cli_sha256="f4e7b95b5289994bf34f4c0ecac52770422a577b8af19d28128f89f9ad9549d7",
            ),
            "history_gate": dict(
                verdict="PASS",
                rejected_count=0,
                trust_chain=dict(from_genesis=True, issue_count=0),
                handovers=[dict(status="PASS") for _ in range(3)],
            ),
            "upgrade_gate": dict(
                result="PASS",
                node_count=4,
                engine_pids_unchanged=True,
                cli_sha256="6eeaf23e8e87885b15caef8ba0c6a395b322057cecf1352033afda4b1d1476c8",
            ),
        }

    def policy(self):
        policy = {}
        for name, value in self.reports.items():
            raw = json.dumps(value).encode()
            path = self.root / (name + ".json")
            path.write_bytes(raw)
            policy[name] = dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest())
        return policy

    def test_positive_is_only_gate_metadata(self):
        self.assertEqual(len(fund.readiness(self.policy(), fund.EARLIEST)), 3)

    def test_wall_clock_cannot_replace_resource_bound(self):
        with self.assertRaisesRegex(Refused, "duration"):
            fund.readiness(self.policy(), fund.EARLIEST - 1)

    def test_short_nonfinite_or_boolean_soak_refuses(self):
        for seconds in (86399, float("inf"), True):
            self.reports["resource_gate"]["observed_seconds"] = seconds
            with self.assertRaisesRegex(Refused, "actual24h"):
                fund.readiness(self.policy(), fund.EARLIEST)

    def test_incomplete_or_wrong_release_refuses(self):
        self.reports["resource_gate"]["samples_complete"] = False
        with self.assertRaises(Refused):
            fund.readiness(self.policy(), fund.EARLIEST)
        self.reports["resource_gate"]["samples_complete"] = True
        self.reports["resource_gate"]["engine_sha256"] = "0" * 64
        with self.assertRaises(Refused):
            fund.readiness(self.policy(), fund.EARLIEST)

    def test_inconclusive_history_refuses(self):
        self.reports["history_gate"]["verdict"] = "INCONCLUSIVE"
        with self.assertRaisesRegex(Refused, "historical"):
            fund.readiness(self.policy(), fund.EARLIEST)

    def test_rejection_or_untrusted_history_refuses(self):
        self.reports["history_gate"]["rejected_count"] = 1
        with self.assertRaises(Refused):
            fund.readiness(self.policy(), fund.EARLIEST)
        self.reports["history_gate"]["rejected_count"] = 0
        self.reports["history_gate"]["trust_chain"]["from_genesis"] = False
        with self.assertRaises(Refused):
            fund.readiness(self.policy(), fund.EARLIEST)

    def test_insufficient_windows_refuse(self):
        self.reports["history_gate"]["handovers"].pop()
        with self.assertRaisesRegex(Refused, "handover"):
            fund.readiness(self.policy(), fund.EARLIEST)

    def test_engine_restart_or_wrong_cli_refuses(self):
        self.reports["upgrade_gate"]["engine_pids_unchanged"] = False
        with self.assertRaises(Refused):
            fund.readiness(self.policy(), fund.EARLIEST)
        self.reports["upgrade_gate"]["engine_pids_unchanged"] = True
        self.reports["upgrade_gate"]["cli_sha256"] = "0" * 64
        with self.assertRaises(Refused):
            fund.readiness(self.policy(), fund.EARLIEST)

    def test_report_digest_is_checked(self):
        policy = self.policy()
        target = Path(policy["resource_gate"]["path"])
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaisesRegex(Refused, "SHA"):
            fund.readiness(policy, fund.EARLIEST)


class Budget(unittest.TestCase):
    def entries(self):
        return {fund.ANCHOR_ID: dict(state="delivered", external_hash=fund.ANCHOR_HASH)}

    def test_anchor_and_dry_only_do_not_consume_allocation(self):
        entries = self.entries()
        entries["dry"] = dict(op=fund.OP, value=str(fund.AMOUNT), dry_run=True)
        fund.budget(entries)

    def test_another_or_empty_run_refuses(self):
        with self.assertRaisesRegex(Refused, "journal anchor"):
            fund.budget({})

    def test_any_existing_signed_or_terminal_funding_fences_new_funding(self):
        for state in ("signed", "unknown", "delivered", "refused-on-chain"):
            entries = self.entries()
            entries["fund"] = dict(op=fund.OP, value=str(fund.AMOUNT), state=state)
            with self.assertRaisesRegex(Refused, "already journaled"):
                fund.budget(entries)

    def test_corrupt_value_does_not_create_new_budget(self):
        entries = self.entries()
        entries["fund"] = dict(op=fund.OP, value="1", state="signed")
        with self.assertRaisesRegex(Refused, "malformed"):
            fund.budget(entries)


class Signer(unittest.TestCase):
    def guarded(self):
        self.calls = []
        outer = self

        class Blueprint:
            address = "public-address"

            def materialize(self, client):
                class Wallet:
                    address = "public-address"

                    def sign(self, message, seqno):
                        outer.calls.append((message, seqno))
                        return b"TEST-ONLY signed"

                return Wallet()

        return fund.GuardedBlueprint(Blueprint(), 3, 100).materialize(None)

    def test_current_nonce_signs_once(self):
        wallet = self.guarded()
        with patch.object(fund.time, "time", return_value=99):
            wallet.sign(b"test", 3)
            with self.assertRaisesRegex(Refused, "already claimed"):
                wallet.sign(b"test", 3)
        self.assertEqual(len(self.calls), 1)

    def test_changed_nonce_refuses_before_signing(self):
        wallet = self.guarded()
        with patch.object(fund.time, "time", return_value=99):
            with self.assertRaisesRegex(Refused, "nonce changed"):
                wallet.sign(b"test", 4)
        self.assertEqual(self.calls, [])

    def test_expired_window_refuses_before_signing(self):
        wallet = self.guarded()
        with patch.object(fund.time, "time", return_value=100):
            with self.assertRaisesRegex(Refused, "window expired"):
                wallet.sign(b"test", 3)
        self.assertEqual(self.calls, [])


class NativeInit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = dict(provider_state=str(self.root))
        self.driver = SimpleNamespace(Cell=Cell, StateInit=StateInit)
        # Ephemeral unit-test key, never exported/committed or used on a network.
        self.seed = os.urandom(32)
        self.public = bytes(nacl.signing.SigningKey(self.seed).verify_key)
        self.code = Cell.one_from_boc(
            (Path(__file__).with_name("data") / "br1-fund/v3-code.boc").read_bytes()
        )
        self.write(self.code)
        (self.root / "funding.seed").write_bytes(self.seed)
        (self.root / "funding.seed").chmod(0o600)

    def write(self, code):
        data = begin_cell().store_uint(0, 32).store_uint(3, 32).store_bytes(self.public).end_cell()
        cell = StateInit(code=code, data=data).serialize()
        self.config = dict(
            release=dict(
                global_id=2, genesis_root=fund.GENESIS_ROOT, genesis_file=fund.GENESIS_FILE
            ),
            funding_wallet="0:" + cell.hash.hex(),
        )
        (self.root / "provider.json").write_text(json.dumps(self.config))
        (self.root / "funding-init.boc").write_bytes(cell.to_boc())

    def test_real_v3_serializers_and_private_public_binding(self):
        target, _, _ = fund.checked_init(self.policy, self.driver, True)
        self.assertEqual(target, self.config["funding_wallet"])

    def test_target_address_is_not_an_arbitrary_destination(self):
        self.config["funding_wallet"] = "0:" + "0" * 64
        (self.root / "provider.json").write_text(json.dumps(self.config))
        with self.assertRaisesRegex(Refused, "StateInit/address"):
            fund.checked_init(self.policy, self.driver, False)

    def test_other_code_is_not_a_funding_wallet(self):
        self.write(Cell.empty())
        with self.assertRaisesRegex(Refused, "canonical TOS V3"):
            fund.checked_init(self.policy, self.driver, False)

    def test_wrong_network_refuses(self):
        self.config["release"]["global_id"] = 3
        (self.root / "provider.json").write_text(json.dumps(self.config))
        with self.assertRaisesRegex(Refused, "public scope"):
            fund.checked_init(self.policy, self.driver, False)

    def test_wrong_custody_key_or_mode_refuses(self):
        path = self.root / "funding.seed"
        path.write_bytes(os.urandom(32))
        with self.assertRaisesRegex(Refused, "public key mismatch"):
            fund.checked_init(self.policy, self.driver, True)
        path.chmod(0o640)
        with self.assertRaisesRegex(Refused, "unsafe funding custody"):
            fund.checked_init(self.policy, self.driver, True)


class Ordering(unittest.TestCase):
    def test_early_or_missing_plan_never_loads_key_runtime(self):
        args = SimpleNamespace(mode="fund", plan=Path("not-read"), plan_sha256="0" * 64)
        with patch.object(
            fund, "load_runtime", side_effect=AssertionError("must not load wallet runtime")
        ) as load:
            with patch.object(fund.time, "time", return_value=fund.EARLIEST - 1):
                with self.assertRaisesRegex(Refused, "duration"):
                    asyncio.run(fund.work(args, {}))
            args.plan = None
            with self.assertRaisesRegex(Refused, "dry plan"):
                asyncio.run(fund.work(args, {}))
        load.assert_not_called()


class Orchestration(unittest.TestCase):
    """Real wrapper/journal fences with a fabricated transport, no chain claim."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        private = self.root / "private"
        private.mkdir()
        (private / "journal-private.jsonl").write_text("{}\n")
        self.data = {fund.ANCHOR_ID: dict(state="delivered", external_hash=fund.ANCHOR_HASH)}
        self.calls = dict(keys=0, signs=0, sends=0, reconciles=0)
        self.now, self.deadline = fund.EARLIEST + 50, fund.EARLIEST + 200
        self.unknown = self.expire_after_sign = False
        self.mode = "dry-run"
        self.operation, self.amount = fund.OP, fund.AMOUNT
        self.marker = "br1-public-pilot-funding-v1.marker.json"
        self.acknowledge = False
        outer = self

        class Address:
            def __init__(self, value):
                self.value = value

            def to_str(self, **kwargs):
                return self.value

        class Run:
            def __init__(self, root):
                self.private = private

            def entries(self):
                return outer.data

            def unresolved(self):
                return {
                    key: value
                    for key, value in outer.data.items()
                    if value["state"] not in {"delivered", "planned-only"}
                }

        class Client:
            async def raw_get_account_state(self, address):
                return SimpleNamespace(
                    code=None,
                    balance=0 if address.value == "target" else 7 * 10**9,
                    last_transaction_id=None,
                )

        class Blueprint:
            address = Address("source")

            def materialize(self, client):
                class Wallet:
                    address = Address("source")

                    def sign(self, message, seqno):
                        outer.calls["signs"] += 1
                        if getattr(outer, "fail_after_sign", False):
                            raise OSError("TEST-ONLY cut after signature")
                        if outer.expire_after_sign:
                            outer.now = outer.deadline
                        return b"TEST-ONLY fake signed message"

                return Wallet()

        async def endpoints(args, stack):
            return [SimpleNamespace(client=Client()), SimpleNamespace(client=Client())]

        async def identity(args, peers):
            self.assertEqual(
                (args.global_id, args.allow_public, args.zero_state), (2, True, fund.GENESIS_ROOT)
            )

        async def seqno(peers, address):
            return 3

        def wallets(args):
            self.calls["keys"] += 1
            if self.mode in {"fund", "resume-before-sign"}:
                self.assertTrue((private / self.marker).exists())
            return [Blueprint()]

        async def send(args, peer, boc):
            self.calls["sends"] += 1
            if self.unknown:
                self.data["fund"]["state"] = "unknown"
                raise OSError("TEST-ONLY ambiguous write")

        async def submit(
            args, run, peers, keys, op, sender, destination, value, body, extra, secret, **kwargs
        ):
            self.assertEqual(
                (op, sender, destination, value, kwargs["bounce"]),
                (self.operation, 0, "target", self.amount, False),
            )
            if args.dry_run:
                return dict(id="dry", dry_run=True)
            signed = keys[0].materialize(peers[0].client).sign(body, 3)
            self.data["fund"] = dict(
                op=self.operation,
                state="signed",
                value=str(self.amount),
                wallet="source",
                destination="target",
                state_init_sha256="init",
            )
            await self.driver.send_bytes(args, peers[0], signed)
            self.data["fund"]["state"] = "delivered"
            return dict(id="fund", state="delivered")

        async def reconcile(args, run, peers):
            self.assertFalse(args.rebroadcast)
            self.calls["reconciles"] += 1
            self.data["fund"]["state"] = "delivered"

        self.driver = SimpleNamespace(
            Run=Run,
            Address=Address,
            open_endpoints=endpoints,
            check_identity=identity,
            seqno_of=seqno,
            funding_wallets=wallets,
            send_bytes=send,
            submit=submit,
            reconcile=reconcile,
            begin_cell=lambda: SimpleNamespace(end_cell=lambda: b"empty body"),
        )
        self.policy = dict(
            run_dir=str(self.root), funding_config="FAKE_CONFIG", funding_dir="FAKE_KEYS"
        )
        self.original_read = fund.read

    def invoke(self, mode, plan=None):
        self.mode = mode
        out = self.root / (mode + "-" + str(len(list(self.root.iterdir()))))
        out.mkdir()
        args = SimpleNamespace(
            mode=mode,
            recovery=getattr(self, "recovery", None),
            recovery_sha256=getattr(self, "recovery_sha256", None),
            acknowledge_reviewed_presign_refusal=getattr(self, "reviewed_refusal", False),
            acknowledge_client_2_tos=self.acknowledge,
            out=out,
            policy_sha256=getattr(self, "policy_sha256", "a" * 64),
            plan=plan,
            plan_sha256=hashlib.sha256(plan.read_bytes()).hexdigest() if plan else None,
        )

        def read(path, *rest, **kwargs):
            if str(path) == "FAKE_CONFIG":
                return b'{"wallets":["source"]}'
            return self.original_read(path, *rest, **kwargs)

        with (
            patch.object(fund, "readiness"),
            patch.object(fund, "load_runtime", return_value=self.driver),
            patch.object(fund, "checked_init", return_value=("target", "init-object", "init")),
            patch.object(fund, "fresh_window", return_value={"valid_until_utc": self.deadline}),
            patch.object(fund, "read", side_effect=read),
            patch.object(fund.time, "time", side_effect=lambda: self.now),
        ):
            asyncio.run(fund.work(args, self.policy))
        return out / "RESULT.json"

    def test_dry_run_does_not_sign_or_send(self):
        self.invoke("dry-run")
        self.assertEqual((self.calls["signs"], self.calls["sends"]), (0, 0))
        self.assertFalse((self.root / "private" / self.marker).exists())

    def test_fixed_initialization_once_and_marker_before_keys(self):
        plan = self.invoke("dry-run")
        self.invoke("fund", plan)
        self.assertEqual((self.calls["signs"], self.calls["sends"]), (1, 1))
        with self.assertRaises(Refused):
            self.invoke("fund", plan)
        self.assertEqual((self.calls["signs"], self.calls["sends"]), (1, 1))

    def test_ambiguous_write_only_reconciles_without_keys_or_send(self):
        plan = self.invoke("dry-run")
        self.unknown = True
        with self.assertRaises(OSError):
            self.invoke("fund", plan)
        before = dict(self.calls)
        self.invoke("reconcile")
        self.assertEqual(
            (self.calls["keys"], self.calls["signs"], self.calls["sends"]),
            (before["keys"], before["signs"], before["sends"]),
        )
        self.assertEqual(self.calls["reconciles"], 1)

    def test_window_expiring_after_signing_has_zero_broadcast(self):
        plan = self.invoke("dry-run")
        self.expire_after_sign = True
        with self.assertRaisesRegex(Refused, "window expired"):
            self.invoke("fund", plan)
        self.assertEqual((self.calls["signs"], self.calls["sends"]), (1, 0))
        self.assertTrue((self.root / "private" / self.marker).exists())


class ClientOrchestration(Orchestration):
    def setUp(self):
        super().setUp()
        self.policy["schema"] = fund.CLIENT_SCHEMA
        self.operation, self.amount = fund.CLIENT_OP, fund.CLIENT_AMOUNT
        self.marker = "br1-public-client-funding-v1.marker.json"
        self.acknowledge = True

    def test_missing_new_allocation_ack_refuses_before_keys(self):
        plan = self.invoke("dry-run")
        self.acknowledge = False
        before = dict(self.calls)
        with self.assertRaisesRegex(Refused, "acknowledgement"):
            self.invoke("fund", plan)
        self.assertEqual(self.calls, before)
        self.assertFalse((self.root / "private" / self.marker).exists())

    def test_operator_allocation_does_not_consume_client_fence(self):
        self.data["operator"] = dict(op=fund.OP, state="delivered", value=str(fund.AMOUNT))
        plan = self.invoke("dry-run")
        self.invoke("fund", plan)
        self.assertEqual(self.data["fund"]["value"], str(fund.CLIENT_AMOUNT))
        self.assertEqual(self.data["fund"]["op"], fund.CLIENT_OP)

    def test_terminal_client_failure_still_consumes_allocation(self):
        self.data["failed"] = dict(
            op=fund.CLIENT_OP, state="delivered", value=str(fund.CLIENT_AMOUNT)
        )
        with self.assertRaisesRegex(Refused, "reconcile only"):
            self.invoke("dry-run")
        self.assertEqual(self.calls["signs"], 0)


class ClientInit(NativeInit):
    # Reuse independently generated canonical V3 fixture, not network identities.
    def setUp(self):
        super().setUp()
        self.manifest = dict(
            schema="tos.br1.public-client.v1",
            **self.config["release"],
            wallet="unit-client",
            wallet_address=self.config["funding_wallet"],
            wallet_version="V3R2",
            subwallet_id=3,
            public_key_hex=self.public.hex(),
        )
        self.client_policy = dict(schema=fund.CLIENT_SCHEMA, client={})
        self.save_manifest()

    def save_manifest(self):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.manifest))
        self.client_policy["client"].update(
            manifest=str(path),
            manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            state_init=str(self.root / "funding-init.boc"),
            state_init_sha256=hashlib.sha256(
                (self.root / "funding-init.boc").read_bytes()
            ).hexdigest(),
        )

    def test_client_manifest_real_state_init(self):
        target, _, _ = fund.checked_init(self.client_policy, self.driver, False)
        self.assertEqual(target, self.config["funding_wallet"])

    def test_client_network_refused(self):
        self.manifest["global_id"] = 3
        self.save_manifest()
        with self.assertRaisesRegex(Refused, "scope"):
            fund.checked_init(self.client_policy, self.driver, False)

    def test_client_public_key_refused(self):
        self.manifest["public_key_hex"] = os.urandom(32).hex()
        self.save_manifest()
        with self.assertRaisesRegex(Refused, "public key"):
            fund.checked_init(self.client_policy, self.driver, False)

    def test_client_address_refused(self):
        self.manifest["wallet_address"] = "0:" + "00" * 32
        self.save_manifest()
        with self.assertRaisesRegex(Refused, "address"):
            fund.checked_init(self.client_policy, self.driver, False)

    def test_client_private_check_calls_vault_identity(self):
        with patch.object(
            fund, "client_vault_identity", side_effect=Refused("wrong Vault")
        ) as check:
            with self.assertRaisesRegex(Refused, "wrong Vault"):
                fund.checked_init(self.client_policy, self.driver, True)
        check.assert_called_once()

    def identity_fixture(self):
        client = self.client_policy["client"]
        for name, raw in (
            ("cli", b"test executable"),
            (
                "config",
                json.dumps(
                    {
                        "wallets": {
                            "unit-client": {
                                "version": "V3R2",
                                "subwallet_id": 3,
                                "workchain": 0,
                                "key": {"name": "unit-key"},
                            }
                        }
                    }
                ).encode(),
            ),
        ):
            path = self.root / name
            path.write_bytes(raw)
            client[name] = str(path)
            client[name + "_sha256"] = hashlib.sha256(raw).hexdigest()
        env = self.root / "env.json"
        env.write_text(json.dumps({"VAULT_URL": "file:///unit-test-vault"}))
        env.chmod(0o600)
        client["vault_env"] = str(env)
        wallets = [
            {"name": "unit-client", "address": self.manifest["wallet_address"], "wallet_type": None}
        ]
        key = "unit-key Ed25519 No 2026-11-03 00:00 " + base64.b64encode(self.public).decode()
        self.driver.Address = __import__("pytosiq_core").Address
        return client, wallets, key

    def test_offline_identity_accepts_unknown_onchain_type(self):
        client, wallets, key = self.identity_fixture()
        responses = [
            SimpleNamespace(returncode=0, stdout=json.dumps(wallets).encode(), stderr=b""),
            SimpleNamespace(returncode=0, stdout=key.encode(), stderr=b""),
        ]
        with patch.object(fund.subprocess, "run", side_effect=responses) as run:
            fund.client_vault_identity(client, self.manifest, self.driver)
        self.assertIn("--offline", run.call_args_list[0].args[0])
        self.assertEqual(len(run.call_args_list), 2)

    def test_offline_key_name_binding_refuses(self):
        client, wallets, key = self.identity_fixture()
        key = key.replace("unit-key", "another-key")
        with patch.object(
            fund.subprocess,
            "run",
            side_effect=[
                SimpleNamespace(returncode=0, stdout=json.dumps(wallets).encode(), stderr=b""),
                SimpleNamespace(returncode=0, stdout=key.encode(), stderr=b""),
            ],
        ):
            with self.assertRaisesRegex(Refused, "Vault public key"):
                fund.client_vault_identity(client, self.manifest, self.driver)

    def test_offline_wrong_carrier_address_refuses(self):
        client, wallets, key = self.identity_fixture()
        wallets[0]["address"] = "0:" + "00" * 32
        with patch.object(
            fund.subprocess,
            "run",
            side_effect=[
                SimpleNamespace(returncode=0, stdout=json.dumps(wallets).encode(), stderr=b""),
                SimpleNamespace(returncode=0, stdout=key.encode(), stderr=b""),
            ],
        ):
            with self.assertRaisesRegex(Refused, "configured wallet mismatch"):
                fund.client_vault_identity(client, self.manifest, self.driver)

    def test_offline_wrong_configured_version_refuses_before_cli(self):
        client, _, _ = self.identity_fixture()
        path = Path(client["config"])
        path.write_text(path.read_text().replace("V3R2", "V4R2"))
        client["config_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with patch.object(fund.subprocess, "run") as run:
            with self.assertRaisesRegex(Refused, "type mismatch"):
                fund.client_vault_identity(client, self.manifest, self.driver)
        run.assert_not_called()


class FixedClientBudget(unittest.TestCase):
    def test_arbitrary_amount_and_role_pairs_refused(self):
        entries = {fund.ANCHOR_ID: dict(state="delivered", external_hash=fund.ANCHOR_HASH)}
        for operation, amount in (
            (fund.CLIENT_OP, fund.AMOUNT),
            (fund.OP, fund.CLIENT_AMOUNT),
            ("other", 1),
        ):
            with self.assertRaises(Refused):
                fund.budget(entries, operation, amount)


if __name__ == "__main__":
    unittest.main()
