"""(2026-09-16) — attack on the "releasable prefix" watermark of `6115966`.

The fix for the BLOCKER was MY proposal: the `mark_delivered` watermark takes the first id from the
RELEASABLE (passing the `recv` filter) and still-unread rows. In the rationale for my proposal I referred
to ONE case: `stale-ts` — which is FINAL (the 7-day window never reopens). The fix, however, does NOT
distinguish between final and TRANSIENT rejection.

According to `bus_enforce.check` there are at least two transient rejections:
  - `future-ts`  — the sender's clock runs ahead; after `WINDOW_FUTURE_S` (300 s) elapses the row becomes
                   legitimate ON ITS OWN. There is nothing hostile in it: clock skew.
  - `forged`     — unknown sender: the registry key (root-owned) is not registered yet; once the key
                   rollout completes the row becomes legitimate.

This probe measures `future-ts`, because it resolves ON ITS OWN, so it needs no assumed operator
intervention.

The measured chain (the REAL release path, `bus_ssh_exchange.py:161-196`):
  peek -> mark_delivered -> ack_preview -> ack, `AGENT_BUS_STRICT_ACK=1` + product mode.
The question is not whether the cursor moves (it MUST move — that is what I asked for), but whether the
transiently unreleasable row ends up BELOW the cursor, and if so, whether there is still a path out.

stdlib unittest + cryptography. No network, every path under /tmp.
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_enforce as enf  # noqa: E402

SKEW_S = 400          # > WINDOW_FUTURE_S (300) -> future-ts, but legitimate ON ITS OWN after 400 s


@unittest.skipUnless(ab._A2_HAVE, "cryptography required")
@unittest.skipUnless(hasattr(ab, "mark_delivered"), "mark_delivered (52ad412+) required")
class TransientRejectLoss(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.keys = os.path.join(t, "keys")
        os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(t, "bus.db")
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.kp = os.path.join(self.keys, "hub.ed25519.key")
        with open(os.path.join(self.keys, "hub.pub"), "w") as f:
            f.write(pub)
        with open(self.kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        self.p = [
            mock.patch.dict(os.environ, {
                "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
                "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": self.keys,
                "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"),
                "AGENT_BUS_MODE": "product"}, clear=False),
            mock.patch.object(ab, "KEYS_DIR", self.keys),
            # the registry guard checks root ownership; for determinism we bypass it (that is not what we measure)
            mock.patch.object(ab, "_a2_guarded_read",
                              lambda p: (open(p, encoding="utf-8").read().strip() if os.path.exists(p) else None)),
        ]
        for x in self.p:
            x.start()
        os.environ.pop("AGENT_BUS_STRICT_ACK", None)

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def send_future(self):
        """A LEGITIMATE, signed message from a sender whose clock runs ahead -> future-ts now, fine after 400 s."""
        fut = int((time.time() + SKEW_S) * 1e9)
        with mock.patch.object(ab.time, "time_ns", lambda: fut):
            ab.send("hub", "peer", "clock-ahead-but-legit", db=self.db, mirror=False, sign_key=self.kp)

    def send_fresh(self, tag):
        ab.send("hub", "peer", "fresh-%s" % tag, db=self.db, mirror=False, sign_key=self.kp)

    def cursors(self):
        c = ab._conn(self.db)
        try:
            r = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent='peer'").fetchone()
            return (r["last_seen_id"], r["delivered_id"]) if r else (0, 0)
        finally:
            c.close()

    def one_round(self, *, strict):
        """The core of the real release path: peek -> mark_delivered -> ack (strict clamp)."""
        rows = ab.recv("peer", mark=False, limit=200, db=self.db, verify_sds=True)
        ids = [r["id"] for r in rows]
        if ids:
            ab.mark_delivered("peer", ids, db=self.db)
            env = {"AGENT_BUS_STRICT_ACK": "1"} if strict else {}
            with mock.patch.dict(os.environ, env, clear=False):
                if not strict:
                    os.environ.pop("AGENT_BUS_STRICT_ACK", None)
                ab.ack("peer", max(ids), db=self.db)
        return ids

    def after_skew(self):
        """The future window has elapsed: the `future-ts` reason is GONE. What does the bus still see?"""
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            reach = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
            life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
        return reach, life

    # -- control: the precondition holds, and it is TRANSIENT (not final) --------
    def test_control_future_ts_is_rejected_now_and_valid_later(self):
        self.send_future()
        self.assertEqual(enf.mode(db=self.db), "product")
        now_ids = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(now_ids, [], "future-ts now -> not releasable")
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            later_ids = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(later_ids, [1], "after the future window elapses the SAME row is legitimate (TRANSIENT rejection)")

    # -- control: WITHOUT a transient row the honest mailbox advances ------------
    def test_control_honest_mailbox_advances(self):
        self.send_fresh("a")
        self.assertEqual(self.one_round(strict=True), [1])
        self.assertEqual(self.cursors(), (1, 1), "the honest round's cursor and watermark are both 1")

    # -- FINDING: the transiently unreleasable row ends up BELOW the cursor ------
    def test_transient_reject_must_not_be_skipped_by_the_cursor(self):
        self.send_future()
        self.send_fresh("a")
        given = self.one_round(strict=True)
        self.assertEqual(given, [2], "only the fresh row can be released")
        cur, dl = self.cursors()
        self.assertLess(cur, 1,
                        "the cursor jumped to %d, the watermark is %d: the TRANSIENTLY rejected id=1 ended up BELOW "
                        "the cursor, even though after 400 s it would have been legitimate" % (cur, dl))

    # -- FINDING: after the cursor jump the row is NOT reachable on the `recv` path -----
    def test_transient_reject_must_stay_reachable_after_the_window(self):
        self.send_future()
        self.send_fresh("a")
        self.one_round(strict=True)
        reach, life = self.after_skew()
        self.assertIn(1, reach,
                      "after the future window elapses the legitimate id=1 does not come out on the recv path (reach=%s); "
                      "the lifeboat lists %s" % (reach, life))

    # -- ATTRIBUTION control: the product-mode deadness of replay does NOT come from this diff --
    # The same question WITHOUT the new code path of 6115966: a manual (non-strict) cursor jump skips an
    # undelivered row, the lifeboat sees it -> does the replay get out? This is runnable on the BASELINE too.
    def test_control_replay_is_dead_in_product_mode_on_both_trees(self):
        self.send_fresh("a")
        self.send_fresh("b")
        # 2026-09-16: the strict ack clamp became the DEFAULT IN PRODUCT MODE
        # (the operator's "yes go ahead" + your measured opinion). This control reproduces the OLD default's damage
        # scenario, so the escape door must be stated here -- in your words: "the work is in the fixture, not in the
        # product code". The probe's LOGIC is unchanged.
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", 2, db=self.db)             # non-strict: the cursor jumps 0->2 WITHOUT delivery
        life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
        self.assertEqual(life, [1, 2], "precondition: the lifeboat sees the two undelivered rows")
        done = ab.replay("peer", commit=True, db=self.db)
        reach = ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)
        self.assertTrue(reach,
                        "the replay ran (%s), but the product-mode recv releases nothing: enforcement drops the "
                        "`system`-sender, UNSIGNED replay message with `unsigned-downgrade`" % (done,))

    # -- FINDING: the lifeboat NAMES the row, but the replay does not get out in product mode --
    def test_lifeboat_replay_must_actually_deliver(self):
        self.send_future()
        self.send_fresh("a")
        self.one_round(strict=True)
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
            self.assertEqual(life, [1], "precondition: the lifeboat names the lost row")
            done = ab.replay("peer", commit=True, db=self.db)
            reach = ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)
        self.assertTrue(reach,
                        "the lifeboat named %s, the replay ran (%s), but the product-mode recv releases "
                        "NOTHING: the recovery path does not pass enforcement" % (life, done))

    # -- FINDING: the peek-time audit row accuses FOREVER, even after SUCCESSFUL delivery --
    # My complaint was precisely against the FALSE ACCUSATION. The fix removed the `read_at IS NULL` filter
    # from the lifeboat's `extra` branch ("the audit row is the signal"), but the audit row is written AT PEEK,
    # while the rejection still held. If the reason was TRANSIENT and the row later goes out fine,
    # the accusation persists -> the replay would DUPLICATE an already-delivered message.
    def test_delivered_row_must_leave_the_lifeboat(self):
        self.send_future()
        self.send_fresh("a")
        peek = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(peek, [2], "precondition: the peek rejects id=1 (audit row is written)")
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            given = self.one_round(strict=True)          # the future window has elapsed: EVERY row goes out
            self.assertEqual(given, [1, 2], "precondition: the row is now provably RELEASED")
            life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
            would = ab.replay("peer", commit=False, db=self.db)["would_replay"]
        self.assertEqual(life, [],
                         "the lifeboat still accuses the SUCCESSFULLY delivered id=1 (life=%s); the replay "
                         "would duplicate: %s" % (life, would))

    # -- the SECOND transient reason: key rollout (`forged`), with operator intervention --
    def test_key_rollout_reject_must_not_be_skipped_by_the_cursor(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        kp = os.path.join(self.keys, "ops.ed25519.key")
        with open(kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        # the registry entry is NOT there yet (the key store is root-owned, the operator writes it)
        ab.send("ops", "peer", "legit-but-not-yet-registered-key", db=self.db, mirror=False, sign_key=kp)
        self.send_fresh("a")
        peek = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(peek, [2], "precondition: without the entry the row is `forged` -> not releasable")
        self.one_round(strict=True)
        with open(os.path.join(self.keys, "ops.pub"), "w") as f:   # the operator REGISTERS the key
            f.write(pub)
        reach = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertIn(1, reach,
                      "after registering the key the legitimate id=1 does not come out (reach=%s): the cursor is already above it" % reach)

    # -- MEASUREMENT (not an assert): what stays on the lifeboat? ----------------
    def test_report_lifeboat_state(self):
        self.send_future()
        self.send_fresh("a")
        self.one_round(strict=True)
        reach, life = self.after_skew()
        cur, dl = self.cursors()
        c = ab._conn(self.db)
        try:
            aud = [(a["op"], a["from_id"], a["to_id"], a["skipped_undelivered"]) for a in c.execute(
                "SELECT op, from_id, to_id, skipped_undelivered FROM cursor_audit WHERE agent='peer' ORDER BY id")]
            unread = [r[0] for r in c.execute("SELECT id FROM messages WHERE recipient='peer' AND read_at IS NULL")]
        finally:
            c.close()
        sys.stderr.write("\n[MEASUREMENT] cursor=%d watermark=%d after_recv=%s lifeboat=%s unread=%s audit=%s\n"
                         % (cur, dl, reach, life, unread, aud))


if __name__ == "__main__":
    unittest.main()
