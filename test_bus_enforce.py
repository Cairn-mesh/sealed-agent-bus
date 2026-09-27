"""bus_enforce (v1.4) — product-mode enforcement. Matrix IDs: forged sender,
replay, backdating, attachment forgery, unsigned-downgrade. stdlib unittest + cryptography (if present)."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_bus as ab  # noqa: E402
import bus_enforce as enf  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def _keypair():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv.private_bytes_raw(), pub.hex()


@unittest.skipUnless(ab._A2_HAVE, "cryptography required")
class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.keys = os.path.join(d, "keys"); os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(d, "bus.db")
        self.state = os.path.join(d, "enforce")
        self.seed, pub = _keypair()
        with open(os.path.join(self.keys, "alice.pub"), "w") as f:
            f.write(pub)
        self.seed_path = os.path.join(d, "alice.seed")
        with open(self.seed_path, "w") as f:
            f.write(self.seed.hex())
        self.p = [mock.patch.object(ab, "KEYS_DIR", self.keys),
                  mock.patch.dict(os.environ, {"AGENT_BUS_AUTO_SIGN": "0", "AGENT_BUS_ENFORCE_DIR": self.state,
                                               "AGENT_BUS_DIR": d, "AGENT_BUS_MODE": ""})]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def signed(self, **over):
        msg = {"sender": "alice", "recipient": "bob", "topic": "t", "kind": "msg", "in_reply_to": None,
               "body": "hi", "ts": time.time_ns()}
        msg.update(over)
        rec = ab._a2_sign(self.seed, msg)
        return {**msg, "sig": rec["sig"], "pubkey": rec["pubkey"]}

    def product(self):
        return mock.patch.dict(os.environ, {"AGENT_BUS_MODE": "product"})


class Mode(Base):
    def test_default_is_dev_backcompat(self):
        self.assertEqual(enf.mode(), "dev")
        ab.send("carol", "bob", "unsigned hello", db=self.db, mirror=False)
        rows = ab.recv("bob", db=self.db)
        self.assertEqual([r["body"] for r in rows], ["unsigned hello"])          # dev: untouched

    def test_marker_switches_to_product(self):
        open(os.path.join(os.environ["AGENT_BUS_DIR"], enf.MARKER), "w").close()
        self.assertEqual(enf.mode(), "product")

    def test_doctor_warns_loudly_in_dev(self):
        ok, lines = enf.doctor()
        self.assertFalse(ok)
        self.assertIn("DEV", lines[0])
        with self.product():
            ok, lines = enf.doctor()
            self.assertTrue(ok)


class Check(Base):
    def test_signed_fresh_accepted(self):
        self.assertEqual(enf.check(self.signed(), keys_dir=self.keys), (True, "ok"))

    def test_m6_unsigned_downgrade_rejected(self):
        m = self.signed(); m.pop("sig"); m.pop("pubkey")
        # a bare row under the PINNED name fails with its own reason — the rejection itself is unchanged
        self.assertEqual(enf.check(m, keys_dir=self.keys), (False, "unsigned-pinned"))
        # a bare row of a name NOT known to the registry: the old, anonymous downgrade
        self.assertEqual(enf.check({**m, "sender": "nobody"}, keys_dir=self.keys), (False, "unsigned-downgrade"))

    def test_m1_forged_and_key_mismatch_rejected(self):
        m = self.signed()
        self.assertEqual(enf.check({**m, "body": "EVIL"}, keys_dir=self.keys)[1], "forged")
        self.assertEqual(enf.check({**m, "sender": "mallory"}, keys_dir=self.keys)[1], "forged")

    def test_m3_stale_and_future_ts_rejected(self):
        old = self.signed(ts=time.time_ns() - 8 * 86400 * 10**9)                  # the window is -7 days
        fut = self.signed(ts=time.time_ns() + 3600 * 10**9)
        self.assertEqual(enf.check(old, keys_dir=self.keys)[1], "stale-ts")
        self.assertEqual(enf.check(fut, keys_dir=self.keys)[1], "future-ts")

    def test_m2_replay_within_window_and_after_restart(self):
        m = self.signed()
        s1 = enf.SeenStore("bob", base=self.state)
        self.assertEqual(enf.check(m, seen=s1, record=True, keys_dir=self.keys), (True, "ok"))
        self.assertEqual(enf.check(m, seen=s1, record=True, keys_dir=self.keys)[1], "replay")
        s2 = enf.SeenStore("bob", base=self.state)                                # "restart": a new instance, the same file
        self.assertEqual(enf.check(m, seen=s2, keys_dir=self.keys)[1], "replay")

    def test_peek_does_not_consume(self):
        m = self.signed()
        s = enf.SeenStore("bob", base=self.state)
        self.assertTrue(enf.check(m, seen=s, record=False, keys_dir=self.keys)[0])
        self.assertTrue(enf.check(m, seen=s, record=True, keys_dir=self.keys)[0])

    def test_m5_attachment_descriptor_covered_by_signature(self):
        h = "a" * 64
        desc = json.dumps({"sha256": h, "size": 10, "media_type": "text/plain", "locator": "sha256:" + h})
        m = self.signed(kind="attachment", body=desc)
        self.assertEqual(enf.check(m, keys_dir=self.keys), (True, "ok"))
        tampered = json.dumps({"sha256": "b" * 64, "size": 10, "media_type": "text/plain", "locator": "sha256:" + "b" * 64})
        self.assertEqual(enf.check({**m, "body": tampered}, keys_dir=self.keys)[1], "forged")   # the descriptor is signed
        bad = self.signed(kind="attachment", body=json.dumps({"sha256": h}))
        self.assertEqual(enf.check(bad, keys_dir=self.keys)[1], "attachment-descriptor")

    def test_compact_keeps_in_window_entries(self):
        s = enf.SeenStore("bob", base=self.state, window_past=300)
        now = time.time()
        s.add("fresh", now - 10); s.add("old", now - 10_000)
        self.assertEqual(s.compact(now_s=now), 1)
        self.assertTrue(enf.SeenStore("bob", base=self.state).seen("fresh"))


class RecvIntegration(Base):
    def test_product_recv_filters_and_logs_but_keeps_rows(self):
        ab.send("carol", "bob", "unsigned", db=self.db, mirror=False)                 # unsigned (downgrade)
        ab.send("alice", "bob", "signed", db=self.db, mirror=False, sign_key=self.seed_path)
        with self.product():
            rows = ab.recv("bob", mark=True, db=self.db)
        self.assertEqual([r["body"] for r in rows], ["signed"])
        c = sqlite3.connect(self.db)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM messages WHERE recipient='bob'").fetchone()[0], 2)  # no deletion
        log = [json.loads(x) for x in open(os.path.join(self.state, "rejected.jsonl"))]
        self.assertEqual([r["reason"] for r in log], ["unsigned-downgrade"])

    def test_product_recv_rejects_reinserted_duplicate(self):
        ab.send("alice", "bob", "pay 1", db=self.db, mirror=False, sign_key=self.seed_path)
        with self.product():
            self.assertEqual(len(ab.recv("bob", mark=True, db=self.db)), 1)
        c = sqlite3.connect(self.db)
        with c:                                                                    # attacker: the same signed row inserted again
            c.execute("INSERT INTO messages(ts,sender,recipient,topic,kind,thread_id,in_reply_to,body,sig,pubkey) "
                      "SELECT ts,sender,recipient,topic,kind,thread_id,in_reply_to,body,sig,pubkey FROM messages WHERE id=1")
        with self.product():
            self.assertEqual(ab.recv("bob", mark=True, db=self.db), [])

    def test_restart_new_process_still_rejects_replay(self):
        m = self.signed()
        enf.check(m, seen=enf.SeenStore("bob", base=self.state), record=True, keys_dir=self.keys)
        code = ("import sys,json,os; sys.path.insert(0,%r); import bus_enforce as e; "
                "m=json.loads(sys.argv[1]); print(e.check(m, seen=e.SeenStore('bob', base=%r), keys_dir=%r)[1])"
                % (HERE, self.state, self.keys))
        out = subprocess.run([sys.executable, "-c", code, json.dumps(m)], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), "replay", out.stderr)

    def test_cli_doctor_exit_code(self):
        env = {**os.environ, "AGENT_BUS_MODE": ""}
        r = subprocess.run([sys.executable, os.path.join(HERE, "agent_bus.py"), "doctor"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn("DEV", r.stderr)


class JointReviewPR4(Base):
    """/2,..4,..5, — the measured reproductions as regression tests."""

    def insert_signed(self, body, ts_off_s=0.0, recipient="bob"):
        m = self.signed(body=body, recipient=recipient, ts=time.time_ns() + int(ts_off_s * 1e9))
        ab.init(self.db)
        c = sqlite3.connect(self.db)
        with c:
            cur = c.execute("INSERT INTO messages(ts,sender,recipient,topic,kind,thread_id,in_reply_to,body,sig,pubkey) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)", (m["ts"], m["sender"], recipient, m["topic"], m["kind"], None,
                                                           None, body, m["sig"], m["pubkey"]))
        c.close()
        return cur.lastrowid

    def cursor(self, agent="bob"):
        c = sqlite3.connect(self.db)
        r = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent=?", (agent,)).fetchone()
        c.close()
        return r

    # --- ---
    def test_B1_sleeping_recipient_gets_signed_mail_after_6_minutes(self):
        self.insert_signed("URGENT: the measurement is done", ts_off_s=-360)
        with self.product():
            rows = ab.recv("bob", mark=True, db=self.db)
        self.assertEqual([r["body"] for r in rows], ["URGENT: the measurement is done"])

    def test_B1_rejected_row_does_not_raise_delivered_and_is_reconcilable(self):
        bad = ab.send("carol", "bob", "not signed", db=self.db, mirror=False)
        good = self.insert_signed("signed row")
        with self.product(), mock.patch("sys.stderr"):
            self.assertEqual([r["body"] for r in ab.recv("bob", mark=True, db=self.db)], ["signed row"])
        self.assertEqual(self.cursor(), (good, good))
        self.assertIn(bad, [m["id"] for m in ab.reconcile("bob", db=self.db)])
        self.assertIn(bad, [w["orig"] for w in ab.replay("bob", db=self.db)["would_replay"]])
        c = sqlite3.connect(self.db)
        self.assertIsNone(c.execute("SELECT read_at FROM messages WHERE id=?", (bad,)).fetchone()[0])

    def test_B1_only_rejected_page_keeps_delivered_and_lists_in_reconcile(self):
        bad = ab.send("carol", "bob", "not signed", db=self.db, mirror=False)
        with self.product(), mock.patch("sys.stderr"):
            self.assertEqual(ab.recv("bob", mark=True, db=self.db), [])
        self.assertEqual(self.cursor(), (bad, 0))
        self.assertEqual([m["id"] for m in ab.reconcile("bob", db=self.db)], [bad])

    def test_B1_window_pinned_7_days_and_300_s(self):
        now = time.time()
        ok = lambda off: enf.check(self.signed(ts=int((now + off) * 1e9)), now_s=now, keys_dir=self.keys)[1]
        self.assertEqual(ok(-7 * 86400 + 5), "ok")
        self.assertEqual(ok(-7 * 86400 - 5), "stale-ts")
        self.assertEqual(ok(295), "ok")
        self.assertEqual(ok(305), "future-ts")

    # --- ---
    def test_B2_unsigned_send_not_mirrored_in_product(self):
        inbox = os.path.join(self.tmp.name, "inbox")
        with self.product():
            ab.send("eve", "mirror1", "NOT SIGNED", db=self.db, inbox_root=inbox)
        self.assertFalse(os.path.isdir(os.path.join(inbox, "mirror1")) and os.listdir(os.path.join(inbox, "mirror1")))
        with self.product():
            ab.send("alice", "mirror1", "signed row", db=self.db, inbox_root=inbox, sign_key=self.seed_path)
        files = os.listdir(os.path.join(inbox, "mirror1"))
        self.assertEqual(len(files), 1)
        rec = json.load(open(os.path.join(inbox, "mirror1", files[0])))
        self.assertTrue(rec.get("sig") and rec.get("pubkey"))

    def test_B2_dev_mode_mirror_backcompat(self):
        inbox = os.path.join(self.tmp.name, "inbox")
        ab.send("eve", "m2", "dev", db=self.db, inbox_root=inbox)
        self.assertEqual(len(os.listdir(os.path.join(inbox, "m2"))), 1)

    def test_B2_inbox_watch_refuses_in_product(self):
        env = {**os.environ, "AGENT_BUS_MODE": "product"}
        try:
            r = subprocess.run(["bash", os.path.join(HERE, "tools", "inbox_watch.sh"), "x"], capture_output=True,
                               text=True, env=env, timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("inbox_watch.sh polls the unenforced mirror in product mode too")
        self.assertEqual(r.returncode, 3)

    def test_B2_filtered_watch_refuses_in_product(self):
        """The partner arm's re-measurement: the repo's second, filtered watcher also refuses in product mode (rc=3)."""
        env = {**os.environ, "AGENT_BUS_MODE": "product"}
        try:
            r = subprocess.run(["bash", os.path.join(HERE, "tools", "inbox_watch_filtered_example.sh")], capture_output=True,
                               text=True, env=env, timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("inbox_watch_filtered_example.sh polls the unenforced mirror in product mode too")
        self.assertEqual(r.returncode, 3)

    # --- / ---
    def test_H1_env_cannot_switch_back_to_dev(self):
        open(os.path.join(self.tmp.name, enf.MARKER), "w").close()                 # marker next to the DB
        empty = os.path.join(self.tmp.name, "ures"); os.makedirs(empty)
        ab.send("eve", "bypass1", "ALAIRATLAN PARANCS", db=self.db, mirror=False)
        env = {**os.environ, "AGENT_BRIDGE_DIR": empty, "AGENT_BUS_DIR": empty, "AGENT_BUS_MODE": "dev",
               "AGENT_BUS_DB": self.db}
        r = subprocess.run([sys.executable, os.path.join(HERE, "agent_bus.py"), "recv", "--agent", "bypass1"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertNotIn("ALAIRATLAN PARANCS", r.stdout)
        with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": "dev", "AGENT_BUS_DIR": empty}):
            self.assertEqual(enf.mode(db=self.db), "product")

    def test_H1_window_env_can_only_narrow(self):
        for raw in ("999999999", "-1", "0", "abc"):
            with mock.patch.dict(os.environ, {"X_WIN": raw}):
                self.assertEqual(enf._env_window("X_WIN", 300), 300, raw)
        with mock.patch.dict(os.environ, {"X_WIN": "60"}):
            self.assertEqual(enf._env_window("X_WIN", 300), 60)

    def test_L1_typo_mode_is_product(self):
        for raw in ("production", "prod", "PRODUCT"):
            with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": raw}):
                self.assertEqual(enf.mode(db=self.db), "product", raw)

    # --- / / ---
    def test_H2_deleting_enforce_dir_does_not_reopen_replay(self):
        self.insert_signed("FIZESS 1000 EUR-t")
        with self.product():
            self.assertEqual(len(ab.recv("bob", mark=True, db=self.db)), 1)
        import shutil
        shutil.rmtree(self.state, ignore_errors=True)
        c = sqlite3.connect(self.db)
        with c:
            c.execute("INSERT INTO messages(ts,sender,recipient,topic,kind,thread_id,in_reply_to,body,sig,pubkey) "
                      "SELECT ts,sender,recipient,topic,kind,thread_id,in_reply_to,body,sig,pubkey FROM messages WHERE id=1")
        with self.product(), mock.patch("sys.stderr"):
            self.assertEqual(ab.recv("bob", mark=True, db=self.db), [])

    def test_H3_audit_records_rejection_not_delivery(self):
        bad = ab.send("carol", "bob", "not signed", db=self.db, mirror=False)
        self.insert_signed("signed row")
        with self.product(), mock.patch("sys.stderr"):
            ab.recv("bob", mark=True, db=self.db)
        rows = ab.audit("bob", db=self.db)
        marks = [r for r in rows if r["op"] == "recv_mark"]
        self.assertEqual(marks[0]["skipped_undelivered"], 1)
        rej = [r for r in rows if r["op"].startswith("enforce_reject")]
        self.assertEqual([(r["from_id"], r["skipped_undelivered"]) for r in rej], [(bad, 1)])
        self.assertTrue(ab.audit_verify("bob", db=self.db)["ok"])

    def test_H4_unwritable_enforce_dir_does_not_crash(self):
        blocker = os.path.join(self.tmp.name, "notadir"); open(blocker, "w").close()
        ab.send("carol", "bob", "not signed", db=self.db, mirror=False)
        self.insert_signed("signed row")
        with self.product(), mock.patch.dict(os.environ, {"AGENT_BUS_ENFORCE_DIR": os.path.join(blocker, "x")}), \
                mock.patch("sys.stderr"):
            self.assertEqual([r["body"] for r in ab.recv("bob", mark=True, db=self.db)], ["signed row"])

    # ---..5 ---
    def test_M1_rejection_is_reported_on_stderr_also_for_peek(self):
        import io
        ab.send("carol", "bob", "not signed", db=self.db, mirror=False)
        err = io.StringIO()
        with self.product(), mock.patch("sys.stderr", err):
            self.assertEqual(ab.recv("bob", db=self.db), [])
        self.assertIn("unsigned-downgrade", err.getvalue())

    def test_M2_partial_deploy_without_bus_enforce(self):
        import shutil
        d = os.path.join(self.tmp.name, "partial"); os.makedirs(d)
        shutil.copy(os.path.join(HERE, "agent_bus.py"), d)
        ab.send("claude", "pdep", "partial deploy test", db=self.db, mirror=False)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env.update({"AGENT_BUS_DB": self.db, "AGENT_BUS_MODE": ""})
        r = subprocess.run([sys.executable, os.path.join(d, "agent_bus.py"), "recv", "--agent", "pdep"],
                           capture_output=True, text=True, env=env, timeout=60, cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("partial deploy test", r.stdout)
        env["AGENT_BUS_MODE"] = "product"
        r = subprocess.run([sys.executable, os.path.join(d, "agent_bus.py"), "recv", "--agent", "pdep"],
                           capture_output=True, text=True, env=env, timeout=60, cwd=d)
        self.assertNotIn("partial deploy test", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_M4_peek_via_recv_does_not_consume(self):
        self.insert_signed("peekelt")
        with self.product():
            self.assertEqual(len(ab.recv("bob", db=self.db)), 1)
            self.assertEqual(len(ab.recv("bob", db=self.db)), 1)                  # the watcher poll peeks twice
            self.assertEqual([r["body"] for r in ab.recv("bob", mark=True, db=self.db)], ["peekelt"])

    def test_M5_enforcement_error_is_fail_closed_without_traceback_or_cursor_move(self):
        self.insert_signed("x")
        with self.product(), mock.patch.object(enf, "check", side_effect=RuntimeError("boom")), mock.patch("sys.stderr"):
            self.assertEqual(ab.recv("bob", mark=True, db=self.db), [])
        self.assertIsNone(self.cursor())
        with self.product():
            self.assertEqual(len(ab.recv("bob", mark=True, db=self.db)), 1)


if __name__ == "__main__":
    unittest.main()
