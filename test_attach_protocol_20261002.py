"""sab-attach/1 — the attachment exchange protocol (docs/AGENT_BUS_SCHEMA.md §8), measured end to end on the real
exchange(). One test class per question the partner's client raised on the exchange (2026-10-01):

  §8 normative text exists and AGREES with the code      DocAgreesWithCode
  >4 MiB download (ranged fetch)                         RangedFetch
  machine next_seq + codes in the status                 UploadStatus
  chunk hash in the chunk object                         ChunkHash
  ONE companion record, bytes must be stored first       Companion
  where 4096/8192 are normative, what is measured        SpecLimits
  idempotent companion insert by record_id               Idempotent
  which in_reply_to the bus threads on                   InReplyTo

stdlib unittest; every scenario runs on a temp bus, never on a live one."""
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_attach as ba  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402
import sds_envelope as se  # noqa: E402
import test_sds_envelope as tse  # noqa: E402


class _Bus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "server.db")
        self.att = os.path.join(t, "att")
        env = {"AGENT_BUS_DB": self.db, "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
               "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"), "AGENT_BUS_AUTO_SIGN": "0",
               "AGENT_BUS_ATTACH_DIR": self.att}
        self.p = [mock.patch.dict(os.environ, env),
                  mock.patch.object(ab, "INBOX_ROOT", env["AGENT_BRIDGE_INBOX"]),
                  mock.patch.object(ab, "KEYS_DIR", env["AGENT_BUS_KEYS_DIR"])]
        for x in self.p:
            x.start()
        self.k, self.pub = tse._keypair()

    def tearDown(self):
        for x in reversed(self.p):
            x.stop()
        self.tmp.cleanup()

    def x(self, payload, who="remote1"):
        return ex.exchange(who, json.dumps(payload), db=self.db, attach_root=self.att, notary=None)

    def upload(self, data, media="application/x-tar", who="remote1"):
        """Put bytes on the SERVER store the way a client does: chunks over exchange()."""
        src = ba.Store(os.path.join(self.tmp.name, "client"))
        d = src.put(data, media)
        chunks, per_round = list(src.chunks(d)), 8                             # 8 × 256 KiB base64 < the 4 MiB stdin cap
        for i in range(0, len(chunks), per_round):
            res = self.x({"attachments": [{"descriptor": d, "chunks": chunks[i:i + per_round]}]}, who)
        return d, res["attachments"][0]

    def framed(self, record, epoch=3):
        return json.dumps(tse.make_framed([(self.k, self.pub, "arm", "OrgA")], record=record, epoch=epoch))

    def companion(self, d, **extra):
        rec = {"schema": se.ATTACH_SCHEMA, "kind": "capsule", "attachment": d}
        rec.update(extra)
        return rec

    def rows(self, recipient="hub"):
        return [r for r in ab.tail(limit=1000, db=self.db) if r["recipient"] == recipient]


# ── §8 exists, and the code table == the code ───────────────────────────────────────────────────────────
class DocAgreesWithCode(unittest.TestCase):
    DOC = open(os.path.join(HERE, "docs", "AGENT_BUS_SCHEMA.md"), encoding="utf-8").read()

    def test_section_8_is_normative_and_names_the_revision(self):
        self.assertIn("## 8. Attachment exchange protocol `sab-attach/1` (NORMATIVE)", self.DOC)
        self.assertEqual(ex.ATTACH_PROTOCOL, "sab-attach/1")

    def test_every_attachment_code_is_in_the_doc_table_and_back(self):
        sec = self.DOC[self.DOC.index("### 8.6"):self.DOC.index("### 8.7")]
        first_cells = [ln.split("|")[1] for ln in sec.splitlines() if ln.startswith("| `")]
        in_doc = {c for cell in first_cells for c in re.findall(r"`([a-z_]+)`", cell)}
        self.assertEqual(in_doc, set(ba.CODES) | set(ex.COMPANION_CODES) | set(ex.WARNING_CODES))

    def test_the_per_round_upload_bound_the_doc_states_is_measured(self):
        t = tempfile.mkdtemp()
        st = ba.Store(t)
        d = st.put(os.urandom(12 * ba.CHUNK_BYTES), "application/octet-stream")
        ch = list(st.chunks(d))
        size = lambda n: len(json.dumps({"attachments": [{"descriptor": d, "chunks": ch[:n]}]}).encode())  # noqa: E731
        self.assertLessEqual(size(11), ex.MAX_BYTES)
        self.assertGreater(size(12), ex.MAX_BYTES)
        self.assertIn("11 full chunks", self.DOC)

    def test_the_constants_the_doc_states_are_the_code_constants(self):
        self.assertEqual(ba.CHUNK_BYTES, 262144)
        self.assertIn("262144", self.DOC)
        self.assertEqual((se.SPEC_MAX_RAW_BYTES, se.SPEC_MAX_BYTES), (8192, 4096))
        self.assertEqual(ex.MAX_FETCH_ITEMS, 32)


# ── >4 MiB: ranged fetch ────────────────────────────────────────────────────────────────────────────────
class RangedFetch(_Bus):
    def test_a_file_above_the_round_budget_is_pulled_in_ranges_byte_exact(self):
        data = os.urandom(ex.MAX_FETCH_BYTES + 3 * ba.CHUNK_BYTES + 12345)          # > 4 MiB, ragged last chunk
        d, st = self.upload(data)
        self.assertEqual(st["status"], "stored")
        legacy = self.x({"fetch": [d]})["fetched"][0]                                 # the old form: deferred, and says why
        self.assertEqual((legacy["status"], legacy["code"]), ("deferred", "round_fetch_budget"))
        got, nxt, rounds = [], 0, 0
        while True:
            r = self.x({"fetch": [{"descriptor": d, "from_seq": nxt}]})["fetched"][0]
            rounds += 1
            self.assertIn(r["status"], ("partial", "delivered"))
            self.assertEqual(r["from_seq"], nxt)
            for ch in r["chunks"]:
                raw = base64.b64decode(ch["data"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), ch["chunk_sha256"])
                self.assertEqual(ch["seq"], len(got))
                got.append(raw)
            self.assertLessEqual(sum(len(base64.b64decode(c["data"])) for c in r["chunks"]), ex.MAX_FETCH_BYTES)
            nxt = r["next_seq"]
            if r["status"] == "delivered":
                break
            self.assertLess(rounds, 10)
        self.assertEqual(nxt, r["total_chunks"])
        self.assertEqual(b"".join(got), data)
        self.assertEqual(rounds, 2)

    def test_bad_ranges_are_named_not_silent(self):
        d, _ = self.upload(b"x" * 10)
        for item in ({"descriptor": d, "from_seq": 1}, {"descriptor": d, "from_seq": -1},
                     {"descriptor": d, "from_seq": True}, {"descriptor": d, "from_seq": "0"},
                     {"descriptor": d, "from_seq": 0, "extra": 1}):
            r = self.x({"fetch": [item]})["fetched"][0]
            self.assertEqual((r["status"], r["code"]), ("rejected", "bad_range"), item)

    def test_a_stored_file_that_changed_on_disk_is_never_served(self):
        d, _ = self.upload(b"payload-bytes" * 100)
        p = os.path.join(self.att, d["sha256"][:2], d["sha256"])
        os.chmod(p, 0o644)
        with open(p, "r+b") as f:
            f.write(b"X")
        r = self.x({"fetch": [{"descriptor": d, "from_seq": 0}]})["fetched"][0]
        self.assertEqual((r["status"], r["code"]), ("not-found", "hash_mismatch"))
        self.assertNotIn("chunks", r)

    def test_control_small_file_one_round_delivered(self):
        d, _ = self.upload(b"small")
        r = self.x({"fetch": [{"descriptor": d, "from_seq": 0}]})["fetched"][0]
        self.assertEqual((r["status"], r["next_seq"], r["total_chunks"]), ("delivered", 1, 1))


# ── machine next_seq + codes ────────────────────────────────────────────────────────────────────────────
class UploadStatus(_Bus):
    def setUp(self):
        super().setUp()
        self.src = ba.Store(os.path.join(self.tmp.name, "client"))
        self.data = os.urandom(3 * ba.CHUNK_BYTES + 7)
        self.d = self.src.put(self.data, "application/octet-stream")
        self.ch = list(self.src.chunks(self.d))

    def test_partial_round_reports_next_seq_and_resume_completes(self):
        r = self.x({"attachments": [{"descriptor": self.d, "chunks": self.ch[:2]}]})["attachments"][0]
        self.assertEqual((r["status"], r["code"], r["next_seq"]), ("partial", "partial", 2))
        r = self.x({"attachments": [{"descriptor": self.d, "chunks": self.ch[r["next_seq"]:]}]})["attachments"][0]
        self.assertEqual((r["status"], r["next_seq"]), ("stored", 4))

    def test_empty_chunk_list_is_a_status_query_that_writes_nothing(self):
        r = self.x({"attachments": [{"descriptor": self.d, "chunks": []}]})["attachments"][0]
        self.assertEqual((r["status"], r["next_seq"]), ("absent", 0))
        self.assertFalse(os.path.exists(self.att) and any(os.scandir(self.att)))
        self.x({"attachments": [{"descriptor": self.d, "chunks": self.ch[:1]}]})
        r = self.x({"attachments": [{"descriptor": self.d, "chunks": []}]})["attachments"][0]
        self.assertEqual((r["status"], r["next_seq"]), ("partial", 1))

    def test_out_of_order_carries_the_code_and_the_true_next_seq(self):
        self.x({"attachments": [{"descriptor": self.d, "chunks": self.ch[:1]}]})
        r = self.x({"attachments": [{"descriptor": self.d, "chunks": self.ch[2:3]}]})["attachments"][0]
        self.assertEqual((r["status"], r["code"], r["next_seq"], r["state"]), ("rejected", "out_of_order", 1, "partial"))

    def test_quota_refusal_is_a_machine_code(self):
        with mock.patch.object(ba, "MAX_WORK_BYTES", 10):
            r = self.x({"attachments": [{"descriptor": self.d, "chunks": self.ch[:1]}]})["attachments"][0]
        self.assertEqual((r["status"], r["code"], r["next_seq"]), ("rejected", "quota_exceeded", 0))

    def test_every_raised_attachment_error_carries_a_code_from_the_closed_set(self):
        src = open(os.path.join(HERE, "bus_attach.py"), encoding="utf-8").read()
        for m in re.finditer(r"raise AttachmentError\((.*?)\)\n", src, re.S):
            codes = re.findall(r'"([a-z_]+)"\s*$', m.group(1).strip())
            self.assertTrue(codes and codes[-1] in ba.CODES, m.group(0)[:120])


# ── chunk hash in the chunk object ──────────────────────────────────────────────────────────────────────
class ChunkHash(_Bus):
    def test_a_corrupted_chunk_is_refused_at_its_seq_and_the_transfer_resumes(self):
        src = ba.Store(os.path.join(self.tmp.name, "client"))
        d = src.put(os.urandom(2 * ba.CHUNK_BYTES + 1), "application/octet-stream")
        ch = list(src.chunks(d))
        bad = dict(ch[1], data=base64.b64encode(b"\0" * len(base64.b64decode(ch[1]["data"]))).decode())
        r = self.x({"attachments": [{"descriptor": d, "chunks": [ch[0], bad]}]})["attachments"][0]
        self.assertEqual((r["code"], r["next_seq"]), ("chunk_hash_mismatch", 1))
        r = self.x({"attachments": [{"descriptor": d, "chunks": ch[1:]}]})["attachments"][0]
        self.assertEqual(r["status"], "stored")

    def test_malformed_chunk_hash_is_bad_chunk(self):
        src = ba.Store(os.path.join(self.tmp.name, "client"))
        d = src.put(b"abc", "text/plain")
        ch = dict(list(src.chunks(d))[0], chunk_sha256="ABC")
        r = self.x({"attachments": [{"descriptor": d, "chunks": [ch]}]})["attachments"][0]
        self.assertEqual(r["code"], "bad_chunk")

    def test_control_a_client_without_chunk_hashes_still_works(self):
        src = ba.Store(os.path.join(self.tmp.name, "client"))
        d = src.put(b"legacy", "text/plain")
        ch = [{k: v for k, v in c.items() if k != "chunk_sha256"} for c in src.chunks(d)]
        self.assertEqual(self.x({"attachments": [{"descriptor": d, "chunks": ch}]})["attachments"][0]["status"], "stored")


# ── ONE companion record, bytes first ───────────────────────────────────────────────────────────────────
class Companion(_Bus):
    def test_record_in_the_same_round_as_the_last_chunk_is_rejected_order_is_fixed(self):
        src = ba.Store(os.path.join(self.tmp.name, "client"))
        d = src.put(b"tarbytes" * 50, "application/x-tar")
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self.companion(d))}],
                      "attachments": [{"descriptor": d, "chunks": list(src.chunks(d))}]})
        self.assertEqual(res["attachments"][0]["status"], "stored")          # the bytes DID arrive …
        self.assertEqual(res["rejected"][0]["code"], "attachment_not_stored")   # … but after the message (§8.2)
        res2 = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self.companion(d))}]})
        self.assertEqual(len(res2["accepted"]), 1)
        self.assertEqual(len(self.rows()), 1)

    def test_a_reference_without_bytes_is_not_a_hand_over(self):
        d = {"sha256": "ab" * 32, "size": 5, "media_type": "application/x-tar", "locator": "sha256:" + "ab" * 32}
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self.companion(d))}]})
        self.assertEqual(res["rejected"][0]["code"], "attachment_not_stored")
        self.assertEqual(self.rows(), [])

    def test_a_record_claiming_the_schema_without_a_valid_descriptor_is_rejected(self):
        rec = {"schema": se.ATTACH_SCHEMA, "kind": "capsule", "attachment": {"sha256": "nope"}}
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(rec)}]})
        self.assertEqual(res["rejected"][0]["code"], "bad_descriptor")

    def test_the_partner_clients_record_shape_is_accepted(self):
        """The shape the first partner client already sends (agent-bus#7, question 6), verbatim in its member names."""
        d, _ = self.upload(b"tarbytes" * 40)
        rec = {"schema": se.ATTACH_SCHEMA, "kind": "capsule", "attachment": d, "package_sha256": d["sha256"],
               "binding_sha256": "ab" * 32, "subject": "hbb2-113",
               "chunks": {"bytes": d["size"], "count": 1, "manifest_sha256": "cd" * 32, "sha256": [d["sha256"]]}}
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(rec)}]})
        self.assertEqual((len(res["accepted"]), res["rejected"]), (1, []))

    def test_one_member_name_only(self):
        """`descriptor` instead of `attachment` under the schema is refused, not silently read: two names = two rules."""
        d, _ = self.upload(b"tarbytes" * 40)
        rec = {"schema": se.ATTACH_SCHEMA, "kind": "capsule", "descriptor": d}
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(rec)}]})
        self.assertEqual(res["rejected"][0]["code"], "bad_descriptor")

    def test_any_authenticated_identity_can_fetch_by_descriptor(self):
        d, _ = self.upload(b"for-the-receiver" * 30, who="remote1")
        r = self.x({"fetch": [{"descriptor": d, "from_seq": 0}]}, who="polaris")["fetched"][0]
        self.assertEqual(r["status"], "delivered")

    def test_control_other_sds_records_are_untouched_by_the_companion_rules(self):
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(None)}]})
        self.assertEqual(len(res["accepted"]), 1)


# ── 4096 / 8192 ─────────────────────────────────────────────────────────────────────────────────────────
class SpecLimits(_Bus):
    def _fill_to(self, d, canon_target):
        rec = self.companion(d, note="")
        base = len(se.jcs({k: v for k, v in rec.items() if k != "record_id"}))
        rec["note"] = "n" * (canon_target - base)
        return rec

    def test_4096_counts_the_canonical_body_not_the_record_id(self):
        d, _ = self.upload(b"z" * 100)
        rec = self._fill_to(d, 4096)
        body = self.framed(rec)
        lim = se.spec_limits(body)
        self.assertEqual(lim["canonical_body_bytes"], 4096)
        full = json.loads(body)["record"]
        self.assertGreater(len(se.jcs(full)), 4096)                         # WITH record_id it is above 4096 …
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]})
        self.assertEqual(len(res["accepted"]), 1, res["rejected"])           # … and still inside the normative cap

    def test_one_byte_over_the_canonical_cap_is_limit_bytes(self):
        d, _ = self.upload(b"z" * 100)
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self._fill_to(d, 4097))}]})
        self.assertEqual(res["rejected"][0]["code"], "limit_bytes")

    def test_frame_over_8192_is_limit_raw_bytes(self):
        d, _ = self.upload(b"z" * 100)
        body = self.framed(self._fill_to(d, 4000))
        body = body + " " * (8193 - len(body.encode("utf-8")))              # insignificant whitespace: the RAW frame grows
        self.assertEqual(len(body.encode("utf-8")), 8193)
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]})
        self.assertEqual(res["rejected"][0]["code"], "limit_raw_bytes")

    def test_non_companion_records_are_measured_not_refused(self):
        rec = {"schema": "capsule-sync/note/v1", "kind": "note", "body": "x" * 6000}
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(rec)}]})
        self.assertEqual(len(res["accepted"]), 1)
        self.assertEqual(res["sds"][0]["within_spec_limits"], False)
        self.assertGreater(res["sds"][0]["canonical_body_bytes"], 4096)


# ── idempotent insert ───────────────────────────────────────────────────────────────────────────────────
class Idempotent(_Bus):
    def test_resend_after_a_lost_reply_returns_the_same_id_and_adds_no_row(self):
        d, _ = self.upload(b"q" * 64)
        body = self.framed(self.companion(d))
        first = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]})
        again = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]})
        self.assertEqual(again["accepted"], first["accepted"])
        self.assertEqual(again["duplicates"][0]["id"], first["accepted"][0])
        self.assertEqual(len(self.rows()), 1)

    def test_same_record_new_envelope_epoch_is_still_the_same_record(self):
        d, _ = self.upload(b"q" * 64)
        a = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self.companion(d), epoch=3)}]})
        b = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self.companion(d), epoch=9)}]})
        self.assertEqual(a["accepted"], b["accepted"])
        self.assertEqual(len(self.rows()), 1)

    def test_control_another_recipient_is_another_key(self):
        d, _ = self.upload(b"q" * 64)
        body = self.framed(self.companion(d))
        self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]})
        self.x({"messages": [{"to": "peer2", "kind": "sds-envelope", "body": body}]})
        self.assertEqual((len(self.rows("hub")), len(self.rows("peer2"))), (1, 1))

    def test_a_record_id_quoted_inside_another_record_is_not_a_match(self):
        d, _ = self.upload(b"q" * 64)
        body = self.framed(self.companion(d))
        rid = json.loads(body)["envelope"]["record_id"]
        quoting = self.framed({"schema": "capsule-sync/note/v1", "kind": "note", "body": "see " + rid})
        self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": quoting}]})
        res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]})
        self.assertEqual(res["duplicates"], [])
        self.assertEqual(len(self.rows()), 2)

    def test_concurrent_rounds_of_the_same_record_insert_once(self):
        d, _ = self.upload(b"q" * 64)
        body = self.framed(self.companion(d))
        out = []
        real = ab.find_sds_record

        def slow(*a, **kw):                                  # widen the lookup->insert window DETERMINISTICALLY: without
            r = real(*a, **kw)                               # the lock every thread sees "no row" before any inserts
            time.sleep(0.15)
            return r
        with mock.patch.object(ab, "find_sds_record", slow):
            ts = [threading.Thread(target=lambda: out.append(
                self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]}))) for _ in range(4)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(len({o["accepted"][0] for o in out}), 1)

    def test_lookup_failure_is_fail_closed(self):
        d, _ = self.upload(b"q" * 64)
        with mock.patch.object(ab, "find_sds_record", side_effect=RuntimeError("db gone")):
            res = self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self.companion(d))}]})
        self.assertEqual(res["rejected"][0]["code"], "idem_unknown")
        self.assertEqual(self.rows(), [])


# ── in_reply_to ─────────────────────────────────────────────────────────────────────────────────────────
class InReplyTo(_Bus):
    def setUp(self):
        super().setUp()
        self.parent = ab.send("hub", "remote1", "please hand over", db=self.db)

    def send(self, outer, inner):
        rec = {"schema": "capsule-sync/note/v1", "kind": "note", "body": "x"}
        if inner is not None:
            rec["in_reply_to"] = inner
        m = {"to": "hub", "kind": "sds-envelope", "body": self.framed(rec)}
        if outer is not None:
            m["in_reply_to"] = outer
        return self.x({"messages": [m]})

    def test_mismatch_is_rejected_with_a_code(self):
        res = self.send(self.parent, self.parent + 1)
        self.assertEqual(res["rejected"][0]["code"], "in_reply_to_mismatch")

    def test_inner_only_is_accepted_but_warned_and_not_threaded(self):
        res = self.send(None, self.parent)
        self.assertEqual(res["warnings"][0]["code"], "in_reply_to_inner_only")
        row = ab.tail(limit=1, db=self.db)[-1]
        self.assertIsNone(row["in_reply_to"])

    def test_outer_is_what_the_bus_threads_on(self):
        res = self.send(self.parent, self.parent)
        self.assertEqual((res["warnings"], res["rejected"]), ([], []))
        row = [r for r in ab.tail(limit=5, db=self.db) if r["id"] == res["accepted"][0]][0]
        self.assertEqual(row["in_reply_to"], self.parent)

    def test_outer_as_numeric_string_is_the_same_number(self):
        res = self.send(str(self.parent), self.parent)
        self.assertEqual(res["rejected"], [])


# ── the companion gate checks the stored BYTES, not the existence of a file ─────────────────────────────
class CompanionGateChecksBytes(_Bus):
    def send(self, d):
        return self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": self.framed(self.companion(d))}]})

    def stored_path(self, d):
        return os.path.join(self.att, d["sha256"][:2], d["sha256"])

    def test_a_descriptor_claiming_one_byte_more_than_is_stored_is_not_a_hand_over(self):
        d, _ = self.upload(b"x" * 23)
        res = self.send(dict(d, size=24))
        self.assertEqual([r["code"] for r in res["rejected"]], ["attachment_not_stored"])
        self.assertIn("size_mismatch", res["rejected"][0]["reason"])
        self.assertEqual((res["accepted"], self.rows()), ([], []))

    def test_a_descriptor_claiming_one_byte_less_is_not_a_hand_over_either(self):
        d, _ = self.upload(b"x" * 23)
        res = self.send(dict(d, size=22))
        self.assertEqual([r["code"] for r in res["rejected"]], ["attachment_not_stored"])
        self.assertEqual(self.rows(), [])

    def test_a_stored_file_corrupted_on_disk_is_not_a_hand_over(self):
        d, _ = self.upload(b"payload-bytes" * 100)
        p = self.stored_path(d)
        os.chmod(p, 0o644)
        with open(p, "r+b") as f:                              # same length, one byte changed
            f.write(b"X")
        res = self.send(d)
        self.assertEqual([r["code"] for r in res["rejected"]], ["attachment_not_stored"])
        self.assertIn("hash_mismatch", res["rejected"][0]["reason"])
        self.assertEqual(self.rows(), [])

    def test_a_stored_file_truncated_on_disk_is_not_a_hand_over(self):
        d, _ = self.upload(b"payload-bytes" * 100)
        p = self.stored_path(d)
        os.chmod(p, 0o644)
        with open(p, "r+b") as f:
            f.truncate(d["size"] - 1)
        res = self.send(d)
        self.assertEqual([r["code"] for r in res["rejected"]], ["attachment_not_stored"])
        self.assertEqual(self.rows(), [])

    def test_the_upload_status_never_says_stored_for_a_size_the_store_does_not_hold(self):
        d, _ = self.upload(b"x" * 23)
        wrong = dict(d, size=24)
        r = self.x({"attachments": [{"descriptor": wrong, "chunks": []}]})["attachments"][0]       # status query
        self.assertEqual((r["status"], r["code"]), ("rejected", "size_mismatch"))
        ch = {"sha256": d["sha256"], "seq": 0, "last": True, "data": base64.b64encode(b"x" * 24).decode()}
        r = self.x({"attachments": [{"descriptor": wrong, "chunks": [ch]}]})["attachments"][0]     # the dedupe path
        self.assertEqual((r["status"], r["code"]), ("rejected", "size_mismatch"))

    def test_the_store_itself_refuses_a_chunk_for_a_size_it_does_not_hold(self):
        d, _ = self.upload(b"x" * 23)
        ch = {"sha256": d["sha256"], "seq": 0, "last": True, "data": base64.b64encode(b"x" * 24).decode()}
        with self.assertRaises(ba.AttachmentError) as cm:
            ba.Store(self.att).receive_chunk(dict(d, size=24), ch)
        self.assertEqual(cm.exception.code, "size_mismatch")
        self.assertEqual(ba.Store(self.att).receive_chunk(d, dict(ch, data=base64.b64encode(b"x" * 23).decode())), d)

    def test_verify_names_what_is_wrong_with_the_stored_bytes(self):
        d, _ = self.upload(b"x" * 23)
        st = ba.Store(self.att)
        self.assertEqual(st.verify(d), d)
        for desc, code in ((dict(d, size=24), "size_mismatch"),
                           (dict(d, sha256="ab" * 32, locator="sha256:" + "ab" * 32), "not_found")):
            with self.assertRaises(ba.AttachmentError) as cm:
                st.verify(desc)
            self.assertEqual(cm.exception.code, code)

    def test_control_the_true_descriptor_of_intact_bytes_is_accepted(self):
        d, st = self.upload(b"x" * 23)
        self.assertEqual((st["status"], st["next_seq"]), ("stored", 1))
        r = self.x({"attachments": [{"descriptor": d, "chunks": []}]})["attachments"][0]
        self.assertEqual((r["status"], r["code"], r["next_seq"]), ("stored", "stored", 1))
        res = self.send(d)
        self.assertEqual((len(res["accepted"]), res["rejected"], len(self.rows())), (1, [], 1))


# ── idempotency is decided on the PARSED record_id, whatever the JSON text looks like ───────────────────
class IdempotentWhateverTheJsonSpelling(_Bus):
    def bodies(self):
        d, _ = self.upload(b"q" * 64)
        plain = self.framed(self.companion(d))
        rid = json.loads(plain)["envelope"]["record_id"]
        spell = {"plain": plain,
                 "escaped_s": plain.replace('"sha256:', '"\\u0073ha256:'),              # the reported counterexample
                 "escaped_hex": plain.replace(rid, "sha256:" + "".join("\\u%04x" % ord(c) for c in rid[7:])),
                 "escaped_colon": plain.replace('"sha256:', '"sha256\\u003a'),
                 "respaced": json.dumps(json.loads(plain), indent=1)}
        for name, b in spell.items():                           # every spelling is the SAME valid signed frame
            rec, env = se.parse_framed(b)
            self.assertEqual((env["record_id"], rec["record_id"]), (rid, rid), name)
            self.assertTrue(name == "plain" or b != plain, name)
        self.assertNotIn(rid, spell["escaped_s"])
        return spell, rid

    def send(self, body):
        return self.x({"messages": [{"to": "hub", "kind": "sds-envelope", "body": body}]})

    def test_an_identical_resend_of_an_escaped_frame_adds_no_row(self):
        spell, rid = self.bodies()
        first = self.send(spell["escaped_s"])
        again = self.send(spell["escaped_s"])
        self.assertEqual(len(first["accepted"]), 1, first)
        self.assertEqual(again["accepted"], first["accepted"])
        self.assertEqual([(x["id"], x["record_id"]) for x in again["duplicates"]], [(first["accepted"][0], rid)])
        self.assertEqual(len(self.rows()), 1)

    def test_every_spelling_of_the_same_record_is_the_same_key_in_any_order(self):
        spell, _rid = self.bodies()
        names = sorted(spell)
        for stored in names:
            with self.subTest(stored=stored):
                self.tearDown()
                self.setUp()
                spell, _rid = self.bodies()
                first = self.send(spell[stored])
                self.assertEqual(len(first["accepted"]), 1, first)
                for resent in names:
                    again = self.send(spell[resent])
                    self.assertEqual(again["accepted"], first["accepted"], (stored, resent))
                    self.assertEqual(len(again["duplicates"]), 1, (stored, resent))
                self.assertEqual(len(self.rows()), 1)

    def test_control_a_different_record_is_still_a_second_row(self):
        spell, _rid = self.bodies()
        d2, _ = self.upload(b"another" * 9)
        other = self.framed(self.companion(d2)).replace('"sha256:', '"\\u0073ha256:')
        a, b = self.send(spell["escaped_s"]), self.send(other)
        self.assertNotEqual(a["accepted"], b["accepted"])
        self.assertEqual((b["duplicates"], len(self.rows())), ([], 2))


# ── §8.6 is closed: the doc table and the code sets are the same set ────────────────────────────────────
class CodeSetIsClosed(_Bus):
    def doc_codes(self):
        doc = DocAgreesWithCode.DOC
        sec = doc[doc.index("### 8.6"):doc.index("### 8.7")]
        cells = [ln.split("|")[1] for ln in sec.splitlines() if ln.startswith("| `")]
        return {c for cell in cells for c in re.findall(r"`([a-z_]+)`", cell)}

    def test_the_doc_table_is_exactly_the_code_sets_nothing_left_out(self):
        self.assertEqual(self.doc_codes(), set(ba.CODES) | set(ex.COMPANION_CODES) | set(ex.WARNING_CODES))

    def test_every_code_literal_the_exchange_emits_is_in_a_declared_set(self):
        src = open(os.path.join(HERE, "bus_ssh_exchange.py"), encoding="utf-8").read()
        body = src[src.index("def exchange("):]
        lits = set(re.findall(r'"code": "([a-z_-]+)"', body)) | set(re.findall(r'bad = \("([a-z_-]+)"', body)) \
            | set(re.findall(r'getattr\(\w+, "code", "([a-z_-]+)"\)', body)) \
            | set(re.findall(r'AttachmentError\([^\n]*?, "([a-z_-]+)"\)', body))
        self.assertGreaterEqual(len(lits), 10)
        self.assertEqual(lits - (set(ba.CODES) | set(ex.COMPANION_CODES) | set(ex.WARNING_CODES)), set())

    def test_a_store_failure_that_is_no_protocol_error_is_reported_as_attachment_error(self):
        src = ba.Store(os.path.join(self.tmp.name, "client"))
        d = src.put(b"abc", "text/plain")
        with mock.patch.object(ba.Store, "receive_chunk", side_effect=OSError("disk gone")):
            r = self.x({"attachments": [{"descriptor": d, "chunks": list(src.chunks(d))}]})["attachments"][0]
        self.assertEqual((r["status"], r["code"], r["state"], r["next_seq"]), ("rejected", "attachment_error", "absent", 0))
        self.assertIn("attachment_error", self.doc_codes())


# ── §8.3 chunk member types are enforced ────────────────────────────────────────────────────────────────
class ChunkShapeIsEnforced(_Bus):
    def setUp(self):
        super().setUp()
        self.src = ba.Store(os.path.join(self.tmp.name, "client"))
        self.d = self.src.put(b"chunk-shape", "text/plain")
        self.good = list(self.src.chunks(self.d))[0]

    BAD = (("chunk_sha256 null", {"chunk_sha256": None}), ("chunk_sha256 number", {"chunk_sha256": 7}),
           ("seq false", {"seq": False}), ("seq float", {"seq": 0.0}), ("seq string", {"seq": "0"}),
           ("seq null", {"seq": None}), ("seq negative", {"seq": -1}),
           ("last string", {"last": "false"}), ("last number", {"last": 1}), ("last null", {"last": None}),
           ("data null", {"data": None}), ("data number", {"data": 5}), ("data list", {"data": []}))

    def test_a_malformed_member_is_bad_chunk_and_nothing_is_stored(self):
        for name, patch in self.BAD:
            with self.subTest(name):
                r = self.x({"attachments": [{"descriptor": self.d, "chunks": [dict(self.good, **patch)]}]})["attachments"][0]
                self.assertEqual((r["status"], r["code"], r["state"], r["next_seq"]), ("rejected", "bad_chunk", "absent", 0), name)

    def test_a_missing_required_member_is_bad_chunk(self):
        for k in ("sha256", "seq", "last", "data"):
            with self.subTest(k):
                ch = {a: b for a, b in self.good.items() if a != k}
                r = self.x({"attachments": [{"descriptor": self.d, "chunks": [ch]}]})["attachments"][0]
                self.assertEqual((r["status"], r["code"], r["state"]), ("rejected", "bad_chunk", "absent"), k)

    def test_a_chunk_that_is_not_an_object_is_bad_chunk(self):
        for ch in ("x", 3, None, [self.good]):
            r = self.x({"attachments": [{"descriptor": self.d, "chunks": [ch]}]})["attachments"][0]
            self.assertEqual((r["status"], r["code"]), ("rejected", "bad_chunk"), ch)

    def test_a_malformed_chunk_is_refused_even_when_the_content_is_already_stored(self):
        self.assertEqual(self.x({"attachments": [{"descriptor": self.d, "chunks": [self.good]}]})["attachments"][0]["status"],
                         "stored")
        for name, patch in self.BAD:
            with self.subTest(name):
                r = self.x({"attachments": [{"descriptor": self.d, "chunks": [dict(self.good, **patch)]}]})["attachments"][0]
                self.assertEqual((r["status"], r["code"], r["state"]), ("rejected", "bad_chunk", "stored"), name)

    def test_control_the_well_formed_chunk_with_and_without_its_hash_and_with_an_unknown_member(self):
        for i, ch in enumerate((self.good, {k: v for k, v in self.good.items() if k != "chunk_sha256"},
                                dict(self.good, note="ignored"))):
            d = self.src.put(b"chunk-shape-%d" % i, "text/plain")
            c = dict(ch, sha256=d["sha256"], data=base64.b64encode(b"chunk-shape-%d" % i).decode())
            if "chunk_sha256" in c:
                c["chunk_sha256"] = hashlib.sha256(b"chunk-shape-%d" % i).hexdigest()
            r = self.x({"attachments": [{"descriptor": d, "chunks": [c]}]})["attachments"][0]
            self.assertEqual((r["status"], r["next_seq"]), ("stored", 1), i)


# ── §8.4 a ranged request is EXACTLY {descriptor, from_seq} ─────────────────────────────────────────────
class RangedRequestIsClosed(_Bus):
    def test_a_ranged_request_without_from_seq_is_bad_range(self):
        d, _ = self.upload(b"x" * 10)
        r = self.x({"fetch": [{"descriptor": d}]})["fetched"][0]
        self.assertEqual((r["status"], r["code"]), ("rejected", "bad_range"))
        self.assertNotIn("chunks", r)

    def test_a_ranged_request_with_any_other_member_set_is_bad_range(self):
        d, _ = self.upload(b"x" * 10)
        for item in ({"descriptor": d, "from_seq": 0, "extra": 1}, {"descriptor": d, "max_chunks": 1},
                     {"descriptor": d, "from_seq": None}, {"descriptor": d, "from_seq": 0.0}):
            r = self.x({"fetch": [item]})["fetched"][0]
            self.assertEqual((r["status"], r["code"]), ("rejected", "bad_range"), item)
            self.assertNotIn("chunks", r)

    def test_control_the_two_documented_forms_deliver(self):
        d, _ = self.upload(b"x" * 10)
        for item in (d, {"descriptor": d, "from_seq": 0}):
            r = self.x({"fetch": [item]})["fetched"][0]
            self.assertEqual((r["status"], base64.b64decode(r["chunks"][0]["data"])), ("delivered", b"x" * 10))


if __name__ == "__main__":
    unittest.main()
