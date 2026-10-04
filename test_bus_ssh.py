"""SSH transport: force-command endpoint (identity pin, size ceiling, sds passthrough), restricted authorized_keys line,
a client round with a fake ssh (it does NOT connect to a real host). stdlib unittest."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_attach  # noqa: E402
import bus_ssh_client as cli  # noqa: E402
import bus_ssh_enroll as enr  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402


class _Iso(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "server.db")
        self.env = {"AGENT_BUS_DB": self.db, "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
                    "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"), "AGENT_BUS_AUTO_SIGN": "0",
                    "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att_server")}
        self.p = [mock.patch.dict(os.environ, self.env),
                  mock.patch.object(ab, "INBOX_ROOT", self.env["AGENT_BRIDGE_INBOX"]),
                  mock.patch.object(ab, "KEYS_DIR", self.env["AGENT_BUS_KEYS_DIR"])]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in reversed(self.p):
            x.stop()
        self.tmp.cleanup()


class ExchangeTest(_Iso):
    def test_identity_pinned_spoof_ignored(self):
        raw = json.dumps({"messages": [{"to": "hub", "body": "hi", "from": "boss", "sender": "boss"}]})
        res = ex.exchange("remote1", raw, db=self.db)
        self.assertEqual(len(res["accepted"]), 1)
        row = ab.recv("hub", db=self.db)[0]
        self.assertEqual(row["sender"], "remote1")

    def test_oversize_rejected(self):
        big = b"{" + b" " * (ex.MAX_BYTES + 1) + b"}"
        self.assertEqual(ex.exchange("remote1", big, db=self.db).get("error"), "oversize")
        r = subprocess.run([sys.executable, os.path.join(HERE, "bus_ssh_exchange.py"), "remote1"],
                           input=big, capture_output=True, env=dict(os.environ, **self.env))
        self.assertEqual(r.returncode, 2)
        self.assertIn("oversize", r.stdout.decode())

    def test_unsafe_or_missing_identity_refused(self):
        for argv in ([], ["../etc"], ["a b"]):
            with mock.patch("sys.stdin"):
                self.assertEqual(ex.main(argv), 2)

    def test_bad_messages_rejected_individually(self):
        raw = json.dumps({"messages": [{"to": "hub"}, {"to": "hub", "body": "ok"},
                                       {"to": "hub", "body": "not framed", "kind": "sds-envelope"}]})
        res = ex.exchange("remote1", raw, db=self.db)
        self.assertEqual(len(res["accepted"]), 1)
        self.assertEqual([r["index"] for r in res["rejected"]], [0, 2])

    def test_replies_peek_then_ack(self):
        ab.send("hub", "remote1", "r1", db=self.db)
        ab.send("hub", "remote1", "r2", db=self.db)
        res = ex.exchange("remote1", "{}", db=self.db)
        self.assertEqual([r["body"] for r in res["replies"]], ["r1", "r2"])
        again = ex.exchange("remote1", "{}", db=self.db)         # no ack → it comes out again (at-least-once)
        self.assertEqual(len(again["replies"]), 2)
        top = max(r["id"] for r in res["replies"])
        self.assertEqual(ex.exchange("remote1", json.dumps({"ack": top}), db=self.db)["replies"], [])

    def test_sds_envelope_passes_through_and_is_labelled(self):
        import test_sds_envelope as tse
        k, pub = tse._keypair()
        framed = json.dumps(tse.make_framed([(k, pub, "arm", "OrgA")]))
        res = ex.exchange("remote1", json.dumps({"messages": [{"to": "hub", "body": framed, "kind": "sds-envelope"}]}), db=self.db)
        self.assertEqual(len(res["accepted"]), 1)
        ab.send("hub", "remote1", framed, kind="sds-envelope", db=self.db)
        rep = ex.exchange("remote1", "{}", db=self.db)["replies"]
        self.assertEqual(len(rep), 1)
        self.assertRegex(rep[0]["sds"], r"^(valid|invalid\(|unsigned|unverifiable)")


class EnrollTest(unittest.TestCase):
    PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx1Y2t5ZGF5c2FyZWhlcmVhZ2FpbmZvcnlvdWFuZG1l comment@box"

    def test_line_has_all_restrictions_and_pin(self):
        line = enr.enroll_line("remote1", self.PUB, "/usr/bin/python3 /opt/agent-bus/bus_ssh_exchange.py")
        self.assertTrue(line.startswith('command="/usr/bin/python3 /opt/agent-bus/bus_ssh_exchange.py remote1",'))
        for r in ("restrict", "no-pty", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding", "no-user-rc"):
            self.assertIn(r, line)
        self.assertNotIn("comment@box", line)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            enr.enroll_line("a/b", self.PUB, "/x")
        with self.assertRaises(ValueError):
            enr.enroll_line("remote1", "not a key", "/x")
        with self.assertRaises(ValueError):
            enr.enroll_line("remote1", self.PUB, '/x"; bash; "')

    def test_write_only_given_file_idempotent(self):
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "authorized_keys.bus")
            line = enr.enroll_line("remote1", self.PUB, "/opt/x.py")
            self.assertTrue(enr.write_line(path, line))
            self.assertFalse(enr.write_line(path, line))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with open(path) as f:
                self.assertEqual(f.read().count("\n"), 1)


class ClientRoundTripTest(_Iso):
    def _fake_ssh(self, identity):
        """A fake ssh: it simulates the force-command (IT pins the identity), and drops the target-host argument."""
        path = os.path.join(self.tmp.name, "fake_ssh.py")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""
                import sys
                sys.path.insert(0, %r)
                import bus_ssh_exchange
                sys.exit(bus_ssh_exchange.main([%r]))
            """ % (HERE, identity)))
        return [sys.executable, path]

    def test_round_trip_dedupe_and_ack(self):
        local_db = os.path.join(self.tmp.name, "local.db")
        state = os.path.join(self.tmp.name, "state")
        ab.send("hub", "remote1", "hello remote", db=self.db)
        res = cli.exchange("bus@example.invalid", "me", [{"to": "hub", "body": "hello hub", "from": "boss"}],
                           ssh_cmd=self._fake_ssh("remote1"), state_dir=state, db=local_db)
        self.assertEqual(res["stored_locally"], 1)
        self.assertEqual(ab.recv("hub", db=self.db)[-1]["sender"], "remote1")
        self.assertEqual(ab.recv("me", db=local_db)[0]["body"], "hello remote")
        res2 = cli.exchange("bus@example.invalid", "me", [], ssh_cmd=self._fake_ssh("remote1"), state_dir=state, db=local_db)
        self.assertEqual(res2["stored_locally"], 0)             # the server's cursor stepped with the ack → it does not come again
        self.assertEqual(len(ab.recv("me", db=local_db)), 1)

    def test_attachment_over_ssh(self):
        local_att = bus_attach.Store(os.path.join(self.tmp.name, "att_local"))
        data = b"x" * (700 * 1024)
        d = local_att.put(data, "application/octet-stream")
        res = cli.exchange("bus@example.invalid", "me", [{"to": "hub", "body": json.dumps(d), "kind": "attachment"}],
                           ssh_cmd=self._fake_ssh("remote1"), state_dir=os.path.join(self.tmp.name, "st"),
                           db=os.path.join(self.tmp.name, "l.db"), attach_descs=[d], attach_root=local_att.root)
        # sab-attach/1 (§8.5): the status item is ADDITIVE — it also carries the machine `code` and `next_seq`
        self.assertEqual([{k: a[k] for k in ("sha256", "status")} for a in res["attachments"]],
                         [{"sha256": d["sha256"], "status": "stored"}])
        self.assertEqual(res["attachments"][0]["code"], "stored")
        self.assertEqual(bus_attach.Store(self.env["AGENT_BUS_ATTACH_DIR"]).get(d), data)


if __name__ == "__main__":
    unittest.main()
