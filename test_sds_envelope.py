"""sds_envelope + agent_bus wiring: the partner arm's three additive steps (frame at send, check at recv, governance bridge). stdlib unittest."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_bus as ab  # noqa: E402
import sds_envelope as se  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAVE = True
except Exception:  # pragma: no cover
    HAVE = False

CONFIG = "sha256:" + "ab" * 32


def _keypair():
    k = ed25519.Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return k, pub


def make_framed(signers, *, record=None, epoch=3):
    """signers: [(private_key, pub_hex, role, org)] → a framed pair with valid signatures (SPEC §5 message)."""
    rec = dict(record or {"schema": "capsule-sync/coord/v1", "kind": "endorsement", "tag": "q3",
                          "subject": "sha256:" + "11" * 32, "verdict": "CLAIMED", "prev_record_id": None})
    rec.pop("record_id", None)
    rec["record_id"] = se.record_id_of(rec)
    dom = {"project": "capsule2", "stream": "sync", "repo": "spec"}
    env = {"record_id": rec["record_id"], "config_id": CONFIG, "domain": dom,
           "domain_hash": hashlib.sha256(se.jcs(dom)).hexdigest(), "epoch": epoch, "sigs": []}
    for k, pub, role, org in signers:
        env["sigs"].append({"issuer": pub, "sig": k.sign(se.signed_message(env, role, org)).hex()})
    env["sigs"].sort(key=lambda s: s["issuer"])
    return {"record": rec, "envelope": env}


class Canonical(unittest.TestCase):
    def test_utf16_key_order_and_escaping(self):
        self.assertEqual(se.jcs({"\U0001F600": 1, "￿": 2, "a": "x\n"}),
                         '{"a":"x\\n\\u0001","\U0001F600":1,"￿":2}'.encode("utf-8"))

    def test_float_rejected(self):
        with self.assertRaises(ValueError):
            se.jcs({"pr": 1.5})


class Shape(unittest.TestCase):
    def test_non_framed_rejected(self):
        for body in ("hello", '{"record":{}}', '{"record":{},"envelope":{},"x":1}', "[1]"):
            with self.assertRaises(ValueError):
                se.check_framed_shape(body)

    def test_extra_envelope_member_rejected(self):
        fr = make_framed([]) if HAVE else None
        if fr is None:
            self.skipTest("cryptography missing")
        fr["envelope"]["signed_message_hex"] = "00"
        with self.assertRaises(ValueError):
            se.check_framed_shape(json.dumps(fr))

    def test_float_epoch_rejected(self):
        if not HAVE:
            self.skipTest("cryptography missing")
        fr = make_framed([])
        body = json.dumps(fr).replace('"epoch": 3', '"epoch": 3.0')
        with self.assertRaises(ValueError):
            se.check_framed_shape(body)


@unittest.skipUnless(HAVE, "cryptography missing")
class Verify(unittest.TestCase):
    def setUp(self):
        self.k, self.pub = _keypair()
        self.k2, self.pub2 = _keypair()
        self.adm = {"config_id": CONFIG, "admitted": [
            {"sender": "alice", "issuer": self.pub, "org": "OrgA", "role": "arm"},
            {"sender": "bob", "issuer": self.pub2, "org": "OrgB", "role": "arm"}]}

    def v(self, fr, sender="alice", adm="default", reg=None):
        return se.verify(json.dumps(fr), sender=sender, admission=self.adm if adm == "default" else adm, registry_pubkey=reg)

    def test_valid_single_and_joint(self):
        self.assertEqual(self.v(make_framed([(self.k, self.pub, "arm", "OrgA")]), reg=self.pub), ("valid", ""))
        joint = make_framed([(self.k, self.pub, "arm", "OrgA"), (self.k2, self.pub2, "arm", "OrgB")])
        self.assertEqual(self.v(joint), ("valid", ""))

    def test_tampered_record_invalid(self):
        fr = make_framed([(self.k, self.pub, "arm", "OrgA")])
        fr["record"]["verdict"] = "JOINT_ATTESTED"
        self.assertEqual(self.v(fr), ("invalid", "record-id-mismatch"))

    def test_swapped_domain_invalid(self):
        fr = make_framed([(self.k, self.pub, "arm", "OrgA")])
        fr["envelope"]["domain"]["repo"] = "other"
        self.assertEqual(self.v(fr), ("invalid", "domain-hash-mismatch"))

    def test_wrong_key_signature_invalid(self):
        fr = make_framed([(self.k2, self.pub, "arm", "OrgA")])          # issuer=alice's key, signature=with bob's key
        self.assertEqual(self.v(fr), ("invalid", "bad-signature"))

    def test_wrong_role_binding_invalid(self):
        fr = make_framed([(self.k, self.pub, "root", "OrgA")])          # the admitted role is 'arm'
        self.assertEqual(self.v(fr), ("invalid", "bad-signature"))

    def test_not_admitted_sender(self):
        fr = make_framed([(self.k, self.pub, "arm", "OrgA")])
        self.assertEqual(self.v(fr, sender="mallory"), ("invalid", "not-admitted"))

    def test_sender_did_not_sign(self):
        fr = make_framed([(self.k2, self.pub2, "arm", "OrgB")])
        self.assertEqual(self.v(fr, sender="alice"), ("invalid", "not-admitted"))

    def test_registry_key_mismatch(self):
        fr = make_framed([(self.k, self.pub, "arm", "OrgA")])
        self.assertEqual(self.v(fr, reg=self.pub2), ("invalid", "key-mismatch"))

    def test_config_mismatch(self):
        fr = make_framed([(self.k, self.pub, "arm", "OrgA")])
        adm = dict(self.adm, config_id="sha256:" + "cd" * 32)
        self.assertEqual(self.v(fr, adm=adm), ("invalid", "config-mismatch"))

    def test_unsigned_and_unverifiable(self):
        self.assertEqual(self.v(make_framed([]))[0], "unsigned")
        self.assertEqual(self.v(make_framed([(self.k, self.pub, "arm", "OrgA")]), adm=None), ("unverifiable", "no-admission"))
        with mock.patch.object(se, "HAVE_CRYPTO", False):
            self.assertEqual(self.v(make_framed([(self.k, self.pub, "arm", "OrgA")])), ("unverifiable", "no-crypto"))

    def test_pluggable_validator(self):
        mod = type(sys)("fake_capsule2_validator")
        mod.check = lambda framed, ctx: ("invalid", "EXTERNAL_" + ctx["sender"])
        with mock.patch.dict(sys.modules, {"fake_capsule2_validator": mod}), \
                mock.patch.dict(os.environ, {"CAPSULE2_SDS_VALIDATOR": "fake_capsule2_validator:check"}):
            self.assertEqual(self.v(make_framed([(self.k, self.pub, "arm", "OrgA")])), ("invalid", "EXTERNAL_alice"))


@unittest.skipUnless(HAVE, "cryptography missing")
class BusIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.db = os.path.join(self.tmp.name, "bus.db")
        self.keys = os.path.join(self.tmp.name, "keys")
        os.makedirs(self.keys, mode=0o755)
        self.k, self.pub = _keypair()
        with open(os.path.join(self.keys, "alice.pub"), "w") as f:
            f.write(self.pub)
        self.adm_path = os.path.join(self.tmp.name, "admission.json")
        with open(self.adm_path, "w") as f:
            json.dump({"config_id": CONFIG, "admitted": [{"sender": "alice", "issuer": self.pub, "org": "OrgA", "role": "arm"}]}, f)
        self.p = [mock.patch.object(ab, "KEYS_DIR", self.keys), mock.patch.dict(os.environ, {"AGENT_BUS_AUTO_SIGN": "0"})]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def send(self, sender, body, kind=ab.SDS_KIND):
        return ab.send(sender, "carol", body, kind=kind, db=self.db, mirror=False)

    def test_non_framed_body_rejected_at_send(self):
        with self.assertRaises(ValueError):
            self.send("alice", "free text")
        self.assertEqual(ab.recv("carol", db=self.db), [])

    def test_other_kinds_unaffected(self):
        self.send("alice", "free text", kind="msg")
        rows = ab.recv("carol", db=self.db, verify_sds=True, strict_sds=True)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("sds", rows[0])

    def test_recv_verify_and_strict(self):
        good = make_framed([(self.k, self.pub, "arm", "OrgA")])
        bad = make_framed([(self.k, self.pub, "arm", "OrgA")])
        bad["record"]["tag"] = "q4"
        self.send("alice", json.dumps(good))
        self.send("alice", json.dumps(bad))
        self.send("mallory", json.dumps(good))
        rows = ab.recv("carol", db=self.db, verify_sds=True, sds_admission=self.adm_path)
        self.assertEqual([r["sds"] for r in rows], ["valid", "invalid(record-id-mismatch)", "invalid(not-admitted)"])
        strict = ab.recv("carol", db=self.db, strict_sds=True, sds_admission=self.adm_path)
        self.assertEqual([r["sds"] for r in strict], ["valid"])
        self.assertEqual(len(ab.tail("carol", db=self.db)), 3)          # everything stays in the DB (no-deletion)
        self.assertIn("sds:valid", ab._fmt(rows[0]))

    def test_cli_refuses_non_framed(self):
        with mock.patch.object(ab, "DB", self.db):
            rc = ab.main(["send", "--from", "alice", "--to", "carol", "--kind", ab.SDS_KIND, "--body", "not a frame", "--no-mirror"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
