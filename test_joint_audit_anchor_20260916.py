"""probe (2026-09-16 noon) — the SECOND REGISTER (`--bus-audit`) IS UNANCHORED.

Since `af50521` the `verify` requires the tail of the log slice (`unverified_tail`), and since `9838cf7`
also the START of the slice (`slice_start_seq` / `anchored`) — because an internally sound slice is not by
itself a statement about the whole log. And the `d03d2eb` policy states: in strict/product mode there is no
green light WITHOUT the bus's own hash-chained `cursor_audit` export (rc=1, "incomplete evidence").

This file measures that the same anchor requirement is MISSING on the OTHER register:
  * `agent_bus.audit_chain_verify` looks at neither genesis nor slice start (whereas the DB-side
    `audit_verify` ONE FUNCTION UP starts from `_GENESIS` — the two do not require the same thing);
  * nothing in the log binds the head of the chain (`audit_head` is NEVER called in the product code);
  * `_audit_cross` does not check that the export really belongs to the accused agent and that it
    contains the round's ack row.

Consequence (measured): the accused does not lie and does not forge — it merely hands over a SHORTER,
internally sound export, and the `pending_down` lie gets GREEN (rc=0) instead of
`audit_skipped_contradicts_log` (hard, rc=1).

The scenario is literally the producer's own `test_clamp_lied_with_audit_20260916.py`; the only
difference is the shape of the `bus_audit=` input. stdlib unittest, no network, every path under /tmp.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402

N_MAIL = 6          # this many messages waiting
N_GIVEN = 2         # this many the accused releases (4 would be lost)


class _Scenario(unittest.TestCase):
    """The accused releases 2 of the 6 and, in the round entry, denies the skip (`pending_down`)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp", prefix="ab6-anchor-")
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_WAKE_STATE_DIR": os.path.join(t, "wakestate"),
            "AGENT_BUS_NOTARY_LOG": self.log, "AGENT_BUS_ENFORCE_DIR": t, "AGENT_DUTY_STATE": os.path.join(t, "duty"),
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0", "TMPDIR": t}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def round(self, lie="pending_down", mail=N_MAIL, given=N_GIVEN, notary=None):
        """One round on the REAL release path; -> (released rows, ack target)."""
        n = notary or bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(mail):
            ab.send("hub", "peer", "secret-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[len(allr) - given:]                      # releases only the TOP `given` rows
        cur = ab.cursor_of("peer", db=self.db)
        gid = {x["id"] for x in out}
        left = [x["id"] for x in allr if x["id"] not in gid]
        c = {"at": cur, "replies": len(out), "pending": len(allr), "next_id": min(left) if left else 0}
        if lie == "pending_down":                           # "nothing was left unreleased"
            c["pending"], c["next_id"] = len(out), 0
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)), cursor=c)
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(gid)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        return out, ack_to

    def verdict(self, bus_audit):
        out, ack_to = self.out, self.ack_to
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        r = bn.reconcile(bn.export(self.log, 1), "peer", receipts, strict=True, trusted_pub=self.pub,
                         bus_audit=bus_audit)
        return {"hard": sorted({d["type"] for d in r["discrepancies"]}), "ok": r["ok"],
                "chain_ok": ab.audit_chain_verify(bus_audit)["ok"] if bus_audit is not None else None}


class AuditSliceIsUnanchored(_Scenario):
    def setUp(self):
        super().setUp()
        self.out, self.ack_to = self.round()
        self.audit = ab.audit_export("peer", db=self.db)

    # -- CONTROL 1: with the FULL export the lie fails (the producer's claim, reproduced) --
    def test_control_full_export_contradicts_the_lie(self):
        v = self.verdict(self.audit)
        self.assertEqual(v["hard"], ["audit_skipped_contradicts_log"])
        self.assertFalse(v["ok"])

    # -- CONTROL 2: the precondition -- the skip is carried by a SINGLE row (the ack) --
    def test_control_the_evidence_sits_in_one_row(self):
        carry = [a for a in self.audit if int(a.get("skipped_undelivered") or 0)]
        self.assertEqual(len(carry), 1, "the evidence is in a single row: %s" % json.dumps(self.audit))
        self.assertEqual(carry[0]["seq"], self.audit[-1]["seq"], "and this is the LAST row of the chain")

    # -- FINDING A: the tail-truncated export is internally SOUND, and it silences the comparison --
    def test_tail_truncated_export_must_not_pass_as_evidence(self):
        v = self.verdict(self.audit[:-1])
        self.assertTrue(v["chain_ok"], "precondition: the truncated chain PASSES self-verification (no forgery)")
        self.assertNotEqual(v["hard"], [], "the shorter export silently whitewashed the lying round")

    # -- FINDING B: the START of the slice is unanchored too (whereas the DB-side audit_verify starts from genesis) --
    def test_chain_verify_must_anchor_the_slice_start(self):
        self.assertTrue(ab.audit_verify("peer", db=self.db)["ok"], "precondition: the DB chain is sound")
        chk = ab.audit_chain_verify(self.audit[1:])
        self.assertFalse(chk["ok"], "a slice starting without genesis cannot be 'ok' BY ITSELF (cf. audit_verify)")

    # -- FINDING C: `from_seq` is the SUPPORTED API -- one call can erase the evidence of an older round --
    def test_supported_from_seq_slice_must_not_hide_an_older_round(self):
        first_head = ab.audit_head("peer", db=self.db)[0]
        self.round(lie=None, mail=2, given=2)                 # second, HONEST round
        later = ab.audit_export("peer", from_seq=first_head + 1, db=self.db)
        # CONTRACT CHANGE (2026-09-16, because of his OTHER probe): `ok` now carries the STRICTER
        # meaning (sound AND anchored), and `chain_ok` states the slice's soundness. This PRECONDITION
        # asks about soundness -- the probe's FINDING (the later slice must not hide an earlier round) is unchanged.
        self.assertTrue(later and ab.audit_chain_verify(later)["chain_ok"], "precondition: the later slice is sound")
        v = self.verdict(later)
        self.assertNotEqual(v["hard"], [], "the `from_seq` slice erased the FIRST round's skip")

    # -- FINDING D: the export's IDENTITY is not checked -- a foreign agent's log gives a green light --
    def test_foreign_agent_export_must_not_count_as_the_second_register(self):
        ab.send("hub", "other", "x", db=self.db, mirror=False)
        ab.recv("other", mark=False, db=self.db)
        ab.ack("other", 1, db=self.db)
        foreign = ab.audit_export("other", db=self.db)
        self.assertTrue(foreign, "precondition: the foreign agent has its own chain")
        v = self.verdict(foreign)
        self.assertNotEqual(v["hard"], [], "a FOREIGN agent's audit export counted as full-value evidence")

    # -- FINDING E: nothing in the log anchors the chain head (audit_head is dead in the product code) --
    def test_round_entry_should_anchor_the_audit_head(self):
        seq, rh = ab.audit_head("peer", db=self.db)
        self.assertTrue(rh, "precondition: there is a chain head")
        rounds = [e for e in bn.export(self.log, 1)
                  if e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict) and "pending" in e["cursor"]]
        self.assertTrue(rounds, "precondition: there is a round entry with machine fields")
        self.assertTrue(any(k in rounds[-1]["cursor"] for k in ("audit_seq", "audit_hash")),
                        "the round entry does not bind the head of the bus audit chain: %s" % json.dumps(rounds[-1]["cursor"]))


class CliVerdictFlipsWithAShorterFile(_Scenario):
    """The same on the CLI rc -- this is the number the operator sees."""

    def setUp(self):
        super().setUp()
        self.out, self.ack_to = self.round()
        t = self.tmp.name
        self.exp, self.rp = os.path.join(t, "exp.jsonl"), os.path.join(t, "r.jsonl")
        with open(self.exp, "w", encoding="utf-8") as f:
            for e in bn.export(self.log, 1):
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        with open(self.rp, "w", encoding="utf-8") as f:
            for r in ({"phase": "request", "sent": [], "ack": self.ack_to, "received": self.out, "round": "r1"},
                      {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}):
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def audit_file(self, rows, name):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w", encoding="utf-8") as f:
            for a in rows:
                f.write(json.dumps(a, ensure_ascii=False) + "\n")
        return p

    def rc(self, audit_path=None):
        args = ["reconcile", self.exp, "--identity", "peer", "--receipts", self.rp, "--pub", self.pub, "--strict"]
        if audit_path:
            args += ["--bus-audit", audit_path]
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = bn.main(args)
        return code, err.getvalue()

    def test_control_full_file_is_red_and_missing_file_is_red(self):
        rows = ab.audit_export("peer", db=self.db)
        self.assertEqual(self.rc(self.audit_file(rows, "full.jsonl"))[0], 1, "full export: rc=1 (contradiction)")
        self.assertEqual(self.rc(None)[0], 1, "without an export: rc=1 (incomplete evidence)")

    def test_shorter_file_must_not_turn_the_light_green(self):
        rows = ab.audit_export("peer", db=self.db)
        code, err = self.rc(self.audit_file(rows[:-1], "short.jsonl"))
        self.assertEqual(code, 1, "an export one row shorter, with a SOUND chain -> rc=%d, stderr=%r" % (code, err.strip()))


class TheDocumentedProducerDoesNotExist(unittest.TestCase):
    """The enforced policy (`rc=1, incomplete evidence`) sends the operator to a command that DOES NOT EXIST."""

    def test_agent_bus_audit_export_subcommand_exists(self):
        self.assertIn("audit-verify", _subcommands(), "control: the probe finds the existing subcommand")
        self.assertIn("audit-export", _subcommands(),
                      "the --bus-audit help and the strict rc=1 message both point to 'agent_bus.py audit-export <agent>'")


def _subcommands():
    import argparse
    seen = []
    real = argparse._SubParsersAction.add_parser

    def spy(self, name, **kw):
        seen.append(name)
        return real(self, name, **kw)
    with mock.patch.object(argparse._SubParsersAction, "add_parser", spy), \
            mock.patch.object(sys, "argv", ["agent_bus.py", "--help"]):
        try:
            ab.main([])
        except SystemExit:
            pass
    return seen


if __name__ == "__main__":
    unittest.main()
