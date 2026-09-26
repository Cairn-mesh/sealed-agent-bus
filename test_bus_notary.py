"""bus_notary (v1.5) — notary log: chain, checkpoint, export/verify/compare, backdating, boundary integration."""
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bus_notary as bn  # noqa: E402


def write_lines(path, recs):
    with open(path, "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True) + "\n")


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class _NotaryBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "n", "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.t = [1_800_000_000_000]

        def clock():
            self.t[0] += 1000
            return self.t[0]
        self.n = bn.Notary(self.log, seed=self.seed, checkpoint_every=4, require_signing=True, clock=clock)

    def tearDown(self):
        self.tmp.cleanup()

    def fill(self, k=10):
        for i in range(k):
            self.n.record(envelope={"i": i, "body": "secret-%d" % i}, sender_identity="remote1", sender_auth="ssh-key",
                          recipient="hub", kind="msg", decision="accepted" if i % 3 else "rejected",
                          reason="" if i % 3 else "policy")
        return bn.read_lines(self.log)

    def errs(self, recs, **kw):
        return bn.verify(recs, trusted_pub=self.pub, **kw)


class NotaryChainTest(_NotaryBase):

    def test_clean_chain_verifies_with_signed_checkpoints(self):
        recs = self.fill(10)
        rep = self.errs(recs)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual([c["seq"] for c in rep["checkpoints"]], [4, 8])
        self.assertTrue(all(c["ok"] for c in rep["checkpoints"]))
        self.assertEqual(rep["head"]["seq"], 10)
        self.assertNotIn("secret", open(self.log).read())          # only hash + metadata

    def test_head_survives_new_instance(self):
        self.fill(3)
        n2 = bn.Notary(self.log, seed=self.seed, checkpoint_every=4)
        e = n2.record(envelope="x", sender_identity="a", sender_auth="ssh-key", recipient="b", kind="msg", decision="accepted")
        self.assertEqual(e["seq"], 4)
        self.assertTrue(self.errs(bn.read_lines(self.log))["ok"])

    def test_edited_entry_fails_at_that_seq(self):
        recs = self.fill(10)
        for r in recs:
            if r.get("type") == "entry" and r["seq"] == 6:
                r["decision"] = "accepted" if r["decision"] == "rejected" else "rejected"
        rep = self.errs(recs)
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["errors"][0]["seq"], 6)
        self.assertIn("rewritten", rep["errors"][0]["error"])

    def test_rewrite_with_recomputed_hash_breaks_chain_and_checkpoint(self):
        recs = self.fill(10)
        naive = json.loads(json.dumps(recs))
        for r in naive:
            if r.get("type") == "entry" and r["seq"] == 6:
                r["recipient"] = "attacker"
                r["entry_hash"] = bn.entry_hash(r)
        self.assertEqual([e["seq"] for e in self.errs(naive)["errors"]], [7])   # the next one's prev_hash breaks
        prev = None                                                 # full re-chaining from 6: the signed head at 8 gives it away
        for r in recs:
            if r.get("type") != "entry":
                continue
            if r["seq"] == 6:
                r["recipient"] = "attacker"
            if r["seq"] >= 6:
                r["prev_hash"] = prev
                r["entry_hash"] = bn.entry_hash(r)
            prev = r["entry_hash"]
        rep = self.errs(recs)
        self.assertFalse(rep["ok"])
        self.assertEqual([(e["seq"], "head_hash" in e["error"]) for e in rep["errors"]], [(8, True)])

    def test_deleted_entry_is_a_gap(self):
        recs = [r for r in self.fill(10) if not (r.get("type") == "entry" and r["seq"] == 5)]
        rep = self.errs(recs)
        self.assertFalse(rep["ok"])
        self.assertTrue(any(e["seq"] == 6 and "gap" in e["error"] for e in rep["errors"]), rep["errors"])

    def test_reordered_entries_detected(self):
        recs = self.fill(10)
        idx = [i for i, r in enumerate(recs) if r.get("type") == "entry" and r["seq"] in (2, 3)]
        recs[idx[0]], recs[idx[1]] = recs[idx[1]], recs[idx[0]]
        rep = self.errs(recs)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("reordered" in e["error"] or "chain broken" in e["error"] or "gap" in e["error"]
                            for e in rep["errors"]))

    def test_forged_checkpoint_signature_rejected(self):
        recs = self.fill(8)
        for r in recs:
            if r.get("type") == "checkpoint" and r["seq"] == 8:
                r["ts_ms"] += 1                                     # the signature no longer covers it
        rep = self.errs(recs)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("forged" in e["error"] for e in rep["errors"]))

    def test_checkpoint_by_other_key_rejected(self):
        self.fill(4)
        other_seed, other_pub = bn.keypair()
        fake = bn.Notary(self.log, seed=other_seed).checkpoint()
        rep = self.errs(bn.read_lines(self.log))
        self.assertFalse(rep["ok"])
        self.assertTrue(any("untrusted" in e["error"] for e in rep["errors"]))
        self.assertEqual(fake["notary_pub"], other_pub)

    def test_export_from_seq_verifies_and_carries_latest_checkpoint(self):
        self.fill(10)
        ex = bn.export(self.log, from_seq=5)
        self.assertEqual([r["seq"] for r in ex if r["type"] == "entry"], list(range(5, 11)))
        self.assertEqual(ex[-1]["type"], "checkpoint")
        self.assertEqual(ex[-1]["seq"], 8)
        self.assertTrue(self.errs(ex)["ok"])

    def test_diverging_exports_report_first_differing_seq(self):
        self.fill(10)
        a = bn.export(self.log, 1)
        b = json.loads(json.dumps(bn.export(self.log, 3)))
        res0 = bn.compare(a, b)
        self.assertEqual((res0["same"], res0["first_diff"], res0["reason"]), (True, None, "consistent"))
        self.assertEqual(res0["overlap"], [3, 10])
        for r in b:
            if r.get("type") == "entry" and r["seq"] >= 7:
                r["reason"] = "rewritten-later"
        res = bn.compare(a, b)
        self.assertFalse(res["same"])
        self.assertEqual(res["first_diff"], 7)

    def test_backdated_claim_flagged_not_dropped(self):
        now = self.t[0]
        self.n.record(envelope="old", sender_identity="remote1", sender_auth="ssh-key", recipient="hub", kind="msg",
                      decision="accepted", claimed_ts=(now - 3_600_000) // 1000)            # 1 hour in the past, in seconds
        self.n.record(envelope="fresh", sender_identity="remote1", sender_auth="ssh-key", recipient="hub", kind="msg",
                      decision="accepted", claimed_ts=(now + 1000) * 1_000_000)              # ns, friss
        recs = bn.read_lines(self.log)
        rep = self.errs(recs, backdate_window_s=300)
        self.assertTrue(rep["ok"])
        self.assertEqual([b["seq"] for b in rep["backdated"]], [1])
        self.assertEqual(len([r for r in recs if r["type"] == "entry"]), 2)                 # the evidence stays

    def test_cli_verify_and_compare_exit_codes(self):
        self.fill(8)
        exp = os.path.join(self.tmp.name, "a.jsonl")
        write_lines(exp, bn.export(self.log))
        with mock.patch("sys.stdout"):
            self.assertEqual(bn.main(["verify", exp, "--pub", self.pub]), 0)
            self.assertEqual(bn.main(["compare", exp, exp]), 0)
        recs = bn.read_lines(exp)
        recs[1]["kind"] = "evil"
        bad = os.path.join(self.tmp.name, "b.jsonl")
        write_lines(bad, recs)
        with mock.patch("sys.stdout"):
            self.assertEqual(bn.main(["verify", bad, "--pub", self.pub]), 1)
            self.assertEqual(bn.main(["compare", exp, bad]), 1)

    def _foreign_chain(self):
        """A made-up chain, signed with a foreign, freshly generated key, self-consistent on its own."""
        fseed, fpub = bn.keypair()
        flog = os.path.join(self.tmp.name, "f", "notary.jsonl")
        fn = bn.Notary(flog, seed=fseed, checkpoint_every=3, require_signing=True)
        for i in range(3):
            fn.record(envelope={"i": i}, sender_identity="x", sender_auth="ssh-key", recipient="hub", kind="msg",
                      decision="accepted")
        out = os.path.join(self.tmp.name, "fake.jsonl")
        write_lines(out, bn.export(flog))
        return out, fpub

    def test_M6_verify_without_pub_does_not_claim_trust_and_shows_signer(self):
        """Without --pub a fake chain signed with a foreign key CANNOT be "trusted",
        and the report shows the signing key."""
        fake, fpub = self._foreign_chain()
        rep = bn.verify(bn.read_lines(fake))
        self.assertFalse(rep["trusted"])
        self.assertTrue(rep["signer_unverified"])
        self.assertEqual([c["notary_pub"] for c in rep["checkpoints"]], [fpub])
        self.assertFalse(rep["checkpoints"][0]["trusted"])
        import io
        err = io.StringIO()
        with mock.patch("bus_notary.is_product", return_value=False), mock.patch("sys.stdout"), \
                mock.patch("sys.stderr", err):
            bn.main(["verify", fake])
        self.assertIn("--pub", err.getvalue())

    def test_M6_product_mode_verify_without_pub_refuses(self):
        fake, _ = self._foreign_chain()
        with mock.patch("bus_notary.is_product", return_value=True), mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(bn.main(["verify", fake]), 2)

    def test_M6_with_correct_pub_trusted_and_foreign_rejected(self):
        self.fill(8)
        rep = self.errs(bn.read_lines(self.log))
        self.assertTrue(rep["ok"] and rep["trusted"])
        self.assertFalse(rep["signer_unverified"])
        self.assertTrue(all(c["trusted"] and c["notary_pub"] == self.pub for c in rep["checkpoints"]))
        fake, _ = self._foreign_chain()
        rep2 = bn.verify(bn.read_lines(fake), trusted_pub=self.pub)
        self.assertFalse(rep2["ok"] or rep2["trusted"])

    def test_M6b_checkpointless_slice_with_correct_pub_not_trusted(self):
        """A slice without a checkpoint is not trusted even with the CORRECT --pub."""
        self.fill(3)                                                # checkpoint_every=4 → no checkpoint yet
        rep = self.errs(bn.export(self.log, 1))
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep.get("checkpoint_count"), 0)
        self.assertFalse(rep["trusted"])
        self.assertTrue(rep["signer_unverified"])
        self.assertTrue(rep.get("no_checkpoint_in_range"))
        self.assertEqual(rep.get("unverified_tail"), 3)

    def test_M6b_checkpoint_then_tail_reports_unverified_tail(self):
        self.fill(6)                                                # checkpoint @4, after it 5, 6 only the hash chain
        rep = self.errs(bn.export(self.log, 1))
        # round closing: because of the uncovered tail the slice is NOT trusted (previously trusted:true stood here)
        self.assertTrue(rep["ok"] and not rep["trusted"], rep)
        self.assertEqual((rep.get("verified_checkpoint_count"), rep.get("covered_to_seq"), rep.get("unverified_tail")),
                         (1, 4, 2))
        self.assertFalse(rep["no_checkpoint_in_range"])

    def test_M6b_product_mode_checkpointless_slice_refused(self):
        self.fill(3)
        exp = os.path.join(self.tmp.name, "fresh.jsonl")
        write_lines(exp, bn.export(self.log, 1))
        with mock.patch("bus_notary.is_product", return_value=True), mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertNotEqual(bn.main(["verify", exp, "--pub", self.pub]), 0)
        with mock.patch("bus_notary.is_product", return_value=False), mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(bn.main(["verify", exp, "--pub", self.pub]), 0)   # dev: rc 0, de trusted false


class Joint6RoundClose(_NotaryBase):
    """37Z, head af50521): both branches of a BLOCKER fork passed; HIGH trusted:true for uncovered
    (rewritten / made-up) entries. All red on af50521, green after it."""

    def _branch(self, name, extra, tag):
        import shutil
        d = os.path.join(self.tmp.name, name, "notary.jsonl")
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copy(self.log, d)
        n = bn.Notary(d, seed=self.seed, checkpoint_every=4, require_signing=True, clock=lambda: self.t[0])
        for i in range(extra):
            n.record(envelope={"branch": tag, "i": i}, sender_identity="remote1", sender_auth="ssh-key",
                     recipient="hub", kind="msg", decision="accepted")
        return d

    def _fork(self):
        self.fill(4)                                                 # shared history, checkpoint @4
        a = self._branch("A", 4, "A")                                # A: 5..8, checkpoint @8
        b = self._branch("B", 8, "B")                                # B: 5..12 with DIFFERENT content, checkpoints @8, @12
        return bn.export(a, 1), bn.export(b, 9)                      # A 1..8 (+ck8), B 9..12 (+ck12): no shared seq

    def _rechain(self, recs, start_seq, mutate):
        last = None
        for r in recs:
            if r.get("type") != "entry":
                continue
            if r["seq"] >= start_seq:
                mutate(r)
                r["prev_hash"] = last
                r["entry_hash"] = bn.entry_hash(r)
            last = r["entry_hash"]
        return recs

    def test_fork_both_branches_pass_verify_but_compare_and_start_prev_hash_catch_it(self):
        sa, sb = self._fork()
        ra, rb = self.errs(sa), self.errs(sb)
        self.assertTrue(ra["ok"] and rb["ok"])                      # on its own each slice is consistent
        res = bn.compare(sa, sb)
        self.assertIs(res["same"], False, res)                      # boundary chaining (B9.prev_hash != A8) = fork
        self.assertTrue(res.get("fork"), res)
        chained = bn.verify(sb, trusted_pub=self.pub, start_prev_hash=ra["head"]["hash"])
        self.assertFalse(chained["ok"])
        fa, fb = os.path.join(self.tmp.name, "fa.jsonl"), os.path.join(self.tmp.name, "fb.jsonl")
        write_lines(fa, sa)
        write_lines(fb, sb)
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertNotEqual(bn.main(["compare", fa, fb]), 0)
            self.assertNotEqual(bn.main(["verify", fb, "--pub", self.pub, "--start-prev-hash", ra["head"]["hash"]]), 0)

    def test_fork_same_seq_checkpoint_different_head_is_a_fork(self):
        self.fill(4)
        a, b = self._branch("A", 4, "A"), self._branch("B", 4, "B")
        ca = [r for r in bn.export(a, 1) if r["type"] == "checkpoint"]           # only the checkpoints (@8)
        cb = [r for r in bn.export(b, 1) if r["type"] == "checkpoint"]
        res = bn.compare(ca, cb)
        self.assertIs(res["same"], False, res)
        self.assertTrue(res.get("fork"), res)

    def test_compare_without_overlap_is_not_ok(self):
        self.fill(12)
        sa = [r for r in bn.export(self.log, 1) if r["type"] == "entry" and r["seq"] <= 3]
        sb = [r for r in bn.export(self.log, 9) if r["type"] == "entry"]
        res = bn.compare(sa, sb)
        self.assertIsNone(res["same"], res)
        self.assertEqual(res.get("reason"), "no_overlap")
        fa, fb = os.path.join(self.tmp.name, "na.jsonl"), os.path.join(self.tmp.name, "nb.jsonl")
        write_lines(fa, sa)
        write_lines(fb, sb)
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertNotEqual(bn.main(["compare", fa, fb]), 0)

    def _tail_case(self, total, ck_every, rewrite_from=None, invent=0):
        log = os.path.join(self.tmp.name, "t%d_%d" % (total, invent), "notary.jsonl")
        n = bn.Notary(log, seed=self.seed, checkpoint_every=ck_every, require_signing=True, clock=lambda: self.t[0])
        for i in range(total):
            n.record(envelope={"i": i}, sender_identity="remote1", sender_auth="ssh-key", recipient="hub", kind="msg",
                     decision="accepted")
        recs = [r for r in bn.read_lines(log)]
        if rewrite_from:
            self._rechain(recs, rewrite_from, lambda r: r.update(reason="rewritten"))
        if invent:
            entries = [r for r in recs if r["type"] == "entry"]
            last = entries[-1]
            for k in range(invent):
                e = dict(last, seq=last["seq"] + 1, prev_hash=last["entry_hash"], envelope_sha256=bn.sha256_hex(b"x%d" % k))
                e["entry_hash"] = bn.entry_hash(e)
                recs.append(e)
                last = e
        return recs

    def _assert_uncovered_not_trusted(self, recs, tail):
        rep = self.errs(recs)
        self.assertTrue(rep["ok"], rep["errors"][:3])
        self.assertFalse(rep["trusted"], {k: rep[k] for k in ("covered_to_seq", "unverified_tail")})
        self.assertEqual(rep["unverified_tail"], tail)
        f = os.path.join(self.tmp.name, "tail_%d.jsonl" % tail)
        write_lines(f, recs)
        with mock.patch("bus_notary.is_product", return_value=True), mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertNotEqual(bn.main(["verify", f, "--pub", self.pub]), 0)

    def test_20_of_70_rewritten_after_last_checkpoint_not_trusted(self):
        self._assert_uncovered_not_trusted(self._tail_case(70, 50, rewrite_from=51), 20)

    def test_1000_invented_uncovered_entries_not_trusted(self):
        self._assert_uncovered_not_trusted(self._tail_case(8, 4, invent=1000), 1000)

    def test_export_reports_prev_hash_for_chaining(self):
        self.fill(8)
        import io
        err = io.StringIO()
        with mock.patch("sys.stdout"), mock.patch("sys.stderr", err):
            bn.main(["export", "--log", self.log, "--from", "5"])
        seq4 = [r for r in bn.read_lines(self.log) if r.get("type") == "entry" and r["seq"] == 4][0]
        self.assertIn(seq4["entry_hash"], err.getvalue())


class NotaryModeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"AGENT_BUS_NOTARY_LOG": os.path.join(self.tmp.name, "notary.jsonl"),
                    "AGENT_BUS_DIR": self.tmp.name, "AGENT_BUS_ENFORCE_DIR": self.tmp.name}

    def tearDown(self):
        self.tmp.cleanup()

    def test_dev_default_off_and_switchable(self):
        with mock.patch.dict(os.environ, dict(self.env, AGENT_BUS_MODE="dev"), clear=False), \
                mock.patch("bus_notary.is_product", return_value=False):
            os.environ.pop("AGENT_BUS_NOTARY", None)
            self.assertIsNone(bn.Notary.from_env())
            os.environ["AGENT_BUS_NOTARY"] = "on"
            self.assertIsInstance(bn.Notary.from_env(), bn.Notary)

    def test_product_cannot_be_switched_off_and_needs_key(self):
        with mock.patch.dict(os.environ, dict(self.env, AGENT_BUS_MODE="product", AGENT_BUS_NOTARY="off"), clear=False):
            os.environ.pop("AGENT_BUS_NOTARY_KEY", None)
            self.assertTrue(bn.enabled())
            with self.assertRaises(bn.NotaryError):
                bn.Notary.from_env()                                 # fail-closed without a key

    def test_product_without_crypto_fails_closed(self):
        with mock.patch.object(bn, "HAVE_CRYPTO", False):
            with self.assertRaises(bn.NotaryError):
                bn.Notary(self.env["AGENT_BUS_NOTARY_LOG"], seed=b"\x01" * 32, require_signing=True)

    def test_exchange_fails_closed_when_notary_unavailable(self):
        import bus_ssh_exchange as ex
        with mock.patch.dict(os.environ, dict(self.env, AGENT_BUS_MODE="product"), clear=False), \
                mock.patch.object(bn, "HAVE_CRYPTO", False):
            res = ex.exchange("remote1", json.dumps({"messages": [{"to": "hub", "body": "x"}]}),
                              db=os.path.join(self.tmp.name, "bus.db"))
        self.assertEqual(res.get("error"), "notary unavailable (fail-closed)")
        self.assertNotIn("accepted", res)


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class NotaryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=2)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ssh_exchange_one_entry_per_item_hash_only(self):
        import agent_bus as ab
        import bus_ssh_exchange as ex
        db = os.path.join(self.tmp.name, "bus.db")
        with mock.patch.dict(os.environ, {"AGENT_BUS_DB": db, "AGENT_BRIDGE_DIR": self.tmp.name,
                                          "AGENT_BUS_DIR": self.tmp.name}, clear=False):
            ab.init_db(db) if hasattr(ab, "init_db") else None
            raw = json.dumps({"messages": [{"to": "hub", "body": "TOPSECRET-PLAINTEXT", "from": "boss",
                                            "ts": int(time.time()) - 7200},
                                           {"to": 5, "body": "bad"}]})
            res = ex.exchange("remote1", raw, db=db, attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        self.assertEqual(len(res["accepted"]), 1)
        recs = bn.read_lines(self.log)
        ents = [r for r in recs if r["type"] == "entry"]
        self.assertEqual([(e["decision"], e["sender_identity"], e["sender_auth"]) for e in ents],
                         [("accepted", "remote1", "ssh-key"), ("rejected", "remote1", "ssh-key")])
        self.assertNotIn("TOPSECRET", open(self.log).read())
        rep = bn.verify(recs, trusted_pub=self.pub)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual([b["seq"] for b in rep["backdated"]], [1])

    def test_ssh_exchange_notary_write_failure_is_fail_closed(self):
        import bus_ssh_exchange as ex
        db = os.path.join(self.tmp.name, "bus.db")
        raw = json.dumps({"messages": [{"to": "hub", "body": "a"}, {"to": "hub", "body": "b"}]})
        with mock.patch.dict(os.environ, {"AGENT_BUS_DB": db, "AGENT_BRIDGE_DIR": self.tmp.name}, clear=False), \
                mock.patch.object(self.notary, "record", side_effect=OSError("disk full")):
            res = ex.exchange("remote1", raw, db=db, attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        self.assertEqual(res["error"], "notary write failed (fail-closed)")
        self.assertEqual(res["accepted"], [])
        # (09-15): the anchor is the BUS DB, not the return value — an unlogged item cannot be on the bus
        with mock.patch.dict(os.environ, {"AGENT_BUS_DB": db, "AGENT_BRIDGE_DIR": self.tmp.name}, clear=False):
            import agent_bus as ab
            ab.recv("hub", db=db)                                                  # schema init, if the DB does not exist yet
        n = sqlite3.connect(db).execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        self.assertEqual(n, 0, "an unlogged message in the bus DB")
        self.assertEqual([r for r in bn.read_lines(self.log) if r.get("type") == "entry"], [])

    def test_ssh_exchange_send_failure_after_logging_adds_rejected_entry(self):
        import bus_ssh_exchange as ex
        import agent_bus as ab
        db = os.path.join(self.tmp.name, "bus.db")
        raw = json.dumps({"messages": [{"to": "hub", "body": "a"}, {"to": "hub", "body": "b"}]})
        real_send, calls = ab.send, {"n": 0}

        def flaky_send(*a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("database is locked")
            return real_send(*a, **kw)
        with mock.patch.dict(os.environ, {"AGENT_BUS_DB": db, "AGENT_BRIDGE_DIR": self.tmp.name}, clear=False), \
                mock.patch.object(ab, "send", side_effect=flaky_send):
            res = ex.exchange("remote1", raw, db=db, attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        self.assertNotIn("error", res)
        self.assertEqual(len(res["accepted"]), 1)
        self.assertEqual([r["index"] for r in res["rejected"]], [0])
        ents = [(e["decision"], e["reason"]) for e in bn.read_lines(self.log) if e.get("type") == "entry"]
        self.assertEqual(ents, [("accepted", ""), ("rejected", "send_failed"), ("accepted", "")])
        rep = bn.verify(bn.read_lines(self.log), trusted_pub=self.pub)
        self.assertTrue(rep["ok"], rep["errors"])

    def _attachment(self, data=b"attachment-bytes", corrupt=False):
        import base64
        import hashlib
        h = hashlib.sha256(data).hexdigest()
        desc = {"sha256": h, "size": len(data), "media_type": "application/octet-stream", "locator": "sha256:" + h}
        payload = (data[:-1] + b"X") if corrupt else data
        return h, {"attachments": [{"descriptor": desc, "chunks": [{"sha256": h, "seq": 0, "last": True,
                                                                     "data": base64.b64encode(payload).decode()}]}]}

    def test_ssh_exchange_attachment_not_stored_when_notary_write_fails(self):
        import bus_ssh_exchange as ex
        db, att = os.path.join(self.tmp.name, "bus.db"), os.path.join(self.tmp.name, "att")
        h, payload = self._attachment()
        with mock.patch.dict(os.environ, {"AGENT_BUS_DB": db, "AGENT_BRIDGE_DIR": self.tmp.name}, clear=False), \
                mock.patch.object(self.notary, "record", side_effect=OSError("disk full")):
            res = ex.exchange("remote1", json.dumps(payload), db=db, attach_root=att, notary=self.notary)
        self.assertEqual(res["error"], "notary write failed (fail-closed)")
        written = [f for _, _, fs in os.walk(att) for f in fs if h in f] if os.path.isdir(att) else []
        self.assertEqual(written, [], "an unlogged attachment in the store")

    def test_ssh_exchange_attachment_store_failure_after_logging_adds_rejected_entry(self):
        import bus_ssh_exchange as ex
        db, att = os.path.join(self.tmp.name, "bus.db"), os.path.join(self.tmp.name, "att")
        _, bad = self._attachment(corrupt=True)
        _, good = self._attachment(data=b"other-bytes")
        with mock.patch.dict(os.environ, {"AGENT_BUS_DB": db, "AGENT_BRIDGE_DIR": self.tmp.name}, clear=False):
            r1 = ex.exchange("remote1", json.dumps(bad), db=db, attach_root=att, notary=self.notary)
            r2 = ex.exchange("remote1", json.dumps(good), db=db, attach_root=att, notary=self.notary)
            r3 = ex.exchange("remote1", json.dumps({"attachments": [{"descriptor": {"sha256": "x"}, "chunks": []}]}),
                             db=db, attach_root=att, notary=self.notary)
        self.assertEqual(r1["attachments"][0]["status"], "rejected")
        self.assertEqual(r2["attachments"][0]["status"], "stored")
        self.assertEqual(r3["attachments"][0]["status"], "rejected")
        ents = [(e["kind"], e["decision"], e["reason"]) for e in bn.read_lines(self.log) if e.get("type") == "entry"]
        self.assertEqual(ents[:3], [("attachment", "accepted", "received"), ("attachment", "rejected", "store_failed"),
                                    ("attachment", "accepted", "received")])
        self.assertEqual(ents[3][:2], ("attachment", "rejected"))                   # a formal error: a single rejected, without the store
        self.assertEqual(len(ents), 4)

    def test_relay_deliver_and_pickup_notarized_sealed_ct_never_logged(self):
        import bus_relay as br
        a_sign, a_pub = br.ed25519_keypair()
        b_sign, b_pub = br.ed25519_keypair()
        a_x, a_xpub = br.x25519_keypair()
        b_x, b_xpub = br.x25519_keypair()
        relay = br.Relay(os.path.join(self.tmp.name, "spool"), {"alice": a_pub, "bob": b_pub},
                         sse_interval=0.05, notary=self.notary).start()
        try:
            peers = {"alice": a_xpub, "bob": b_xpub}
            alice = br.RelayClient(relay.url, "alice", a_sign, a_x, peers)
            bob = br.RelayClient(relay.url, "bob", b_sign, b_x, peers)
            alice.deliver("bob", "RELAY-PLAINTEXT")
            code, _ = relay.deliver({"v": 1, "from": "alice", "to": "nobody"})
            self.assertEqual(code, 400)
            self.assertEqual([m["body"] for m in bob.pickup()], ["RELAY-PLAINTEXT"])
            bad = br.sign_request("pickup", "bob", a_sign)                        # with the wrong key
            import urllib.request
            import urllib.error
            req = urllib.request.Request(relay.url + "/pickup", data=json.dumps(bad).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(cm.exception.code, 401)
        finally:
            relay.stop()
        text = open(self.log).read()
        self.assertNotIn("RELAY-PLAINTEXT", text)
        ents = [r for r in bn.read_lines(self.log) if r["type"] == "entry"]
        self.assertEqual([(e["kind"], e["decision"], e["sender_auth"]) for e in ents],
                         [("sealed", "accepted", "unauthenticated-claim"), ("sealed", "rejected", "unauthenticated-claim"),
                          ("pickup", "accepted", "pickup-sig"), ("pickup", "rejected", "unauthenticated-claim")])
        self.assertTrue(bn.verify(bn.read_lines(self.log), trusted_pub=self.pub)["ok"])

    def test_relay_notary_write_failure_is_fail_closed(self):
        import bus_relay as br
        _, a_pub = br.ed25519_keypair()
        relay = br.Relay(os.path.join(self.tmp.name, "spool"), {"alice": a_pub}, notary=self.notary)
        with mock.patch.object(self.notary, "record", side_effect=OSError("disk full")):
            code, res = relay.deliver({"v": br.V, "from": "x", "to": "alice", "ts": 1, "nonce": "n", "ct": "c", "alg": "a"})
        self.assertEqual(code, 503)
        self.assertEqual(relay.count("alice"), 0)


if __name__ == "__main__":
    unittest.main()
