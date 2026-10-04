"""bus_attach: content-addressed attachments (write-once, dedupe, hash+size check, chunked receiving). stdlib unittest."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_bus as ab  # noqa: E402
import bus_attach as ba  # noqa: E402


class AttachTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ba.Store(os.path.join(self.tmp.name, "att"))
        self.data = json.dumps({"rows": list(range(40000))}).encode()     # > 64 KB: it would not fit through the bus

    def tearDown(self):
        self.tmp.cleanup()

    def test_put_get_roundtrip_and_descriptor(self):
        d = self.store.put(self.data, "application/json")
        self.assertEqual(d["sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(d["locator"], "sha256:" + d["sha256"])
        self.assertEqual(self.store.get(d), self.data)
        self.assertGreater(len(self.data), 64 * 1024)

    def test_dedupe_same_hash(self):
        d1 = self.store.put(self.data, "application/json")
        d2 = self.store.put(self.data, "application/json")
        self.assertEqual(d1, d2)
        files = [f for _, _, fs in os.walk(self.store.root) for f in fs]
        self.assertEqual(len(files), 1)

    def test_tamper_rejected(self):
        d = self.store.put(self.data, "application/json")
        p = self.store._path(d["sha256"])
        os.chmod(p, 0o644)
        with open(p, "r+b") as f:
            f.write(b"X")
        with self.assertRaises(ba.AttachmentError):
            self.store.get(d)

    def test_size_mismatch_rejected(self):
        d = dict(self.store.put(self.data, "application/json"), size=len(self.data) - 1)
        with self.assertRaises(ba.AttachmentError):
            self.store.get(d)

    def test_chunked_transfer_and_order(self):
        src = self.store.put(self.data, "application/json")
        dst = ba.Store(os.path.join(self.tmp.name, "dst"))
        chunks = list(self.store.chunks(src, chunk_bytes=100000))
        self.assertGreater(len(chunks), 2)
        with self.assertRaises(ba.AttachmentError):             # an out-of-order chunk
            dst.receive_chunk(src, chunks[1])
        res = None
        for ch in chunks:
            res = dst.receive_chunk(src, ch)
        self.assertEqual(res, src)
        self.assertEqual(dst.get(src), self.data)

    def test_chunked_tamper_rejected_and_kept(self):
        src = self.store.put(self.data, "application/json")
        dst = ba.Store(os.path.join(self.tmp.name, "dst"))
        chunks = list(self.store.chunks(src, chunk_bytes=100000))
        import base64
        bad = dict(chunks[0], data=base64.b64encode(b"Y" * len(base64.b64decode(chunks[0]["data"]))).decode())
        # sab-attach/1 §8.3: a served chunk carries `chunk_sha256` — the tamper is refused AT THE CHUNK (not written)
        with self.assertRaises(ba.AttachmentError) as cm:
            dst.receive_chunk(src, bad)
        self.assertEqual(cm.exception.code, "chunk_hash_mismatch")
        self.assertEqual(dst.status(src), {"state": "absent", "next_seq": 0})
        # a client WITHOUT chunk hashes (the field is optional): the whole-file hash still catches it at the end
        bad.pop("chunk_sha256")
        chunks = [{k: v for k, v in c.items() if k != "chunk_sha256"} for c in chunks]
        dst.receive_chunk(src, bad)
        with self.assertRaises(ba.AttachmentError):
            for ch in chunks[1:]:
                dst.receive_chunk(src, ch)
        self.assertFalse(dst.has(src))
        kept = [f for _, _, fs in os.walk(dst.root) for f in fs if ".rejected." in f]
        self.assertTrue(kept)                                    # kept for inspection, not deleted

    def test_bus_attachment_kind_requires_descriptor(self):
        tmp = self.tmp.name
        with mock.patch.object(ab, "INBOX_ROOT", os.path.join(tmp, "inbox")), \
             mock.patch.dict(os.environ, {"AGENT_BUS_AUTO_SIGN": "0"}):
            db = os.path.join(tmp, "bus.db")
            d = self.store.put(self.data, "application/json")
            rid = ab.send("a", "b", json.dumps(d), kind="attachment", db=db)
            self.assertGreater(rid, 0)
            with self.assertRaises(ValueError):
                ab.send("a", "b", self.data.decode()[:1000], kind="attachment", db=db)
            with self.assertRaises(ValueError):
                ab.send("a", "b", json.dumps(dict(d, locator="http://x")), kind="attachment", db=db)


if __name__ == "__main__":
    unittest.main()
