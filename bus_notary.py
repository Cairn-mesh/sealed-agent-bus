#!/usr/bin/env python3
"""bus_notary — NOTARY LOG at the transport boundary (AgentBus v1.5).

Why: of v1.4's residual risks, two are not closed by the bus's own tools:
  (a) backdating WITHIN THE WINDOW (the signer chooses ts — the partner arm's B2 finding; the enforcement window
      protects delivery, it does not prove the time), and
  (b) whoever can write the bus DB can also rewrite the replay trace — the hash chain only makes that visible.
The notary log records the FACT of receipt at the boundary (bus_ssh_exchange, bus_relay), on the receiver's clock, in a hash chain,
with a periodic checkpoint signed by the notary's Ed25519 key — and BOTH parties can download and compare it.
It does not prove the message is true, but WHEN and FROM WHOM (authenticated identity) WHAT (hash) ARRIVED.

Entry (one JSONL line, `type: "entry"`):
    {seq, prev_hash, received_at_ms, envelope_sha256, sender_identity, sender_auth, recipient, kind,
     decision: "accepted"|"rejected"|"delivered", reason, claimed_ts_ms}
  - OUTBOUND direction at the SSH boundary: `kind="ack"` (reason "cursor A->B (ack U)"), `kind="pickup"`
    round entry (decision accepted, reason "cursor=C replies=N") and per reply `kind="pickup"`, decision `delivered`
    (envelope_sha256 = the JCS hash of the delivered reply dict). All written BEFORE the side effect.
    entry_hash = sha256(JCS(entry without entry_hash))
  - `sender_auth`: "ssh-key" (force-command identity) · "pickup-sig" (signed pickup) · "unauthenticated-claim"
    (the relay /deliver `from` field — not authenticated, hence labelled so)
  - NEVER contains the plaintext of an encrypted envelope: only hash + metadata.
Checkpoint (`type: "checkpoint"`): {seq, head_hash, ts_ms, notary_pub, sig} — sig = Ed25519(JCS(the part without sig)).

Offline verification (either party): `verify` recomputes the chain (rewrite → wrong entry_hash at that seq;
deletion → seq gap; reordering → non-increasing seq / prev_hash break), checks the checkpoint signatures and whether the
head_hash matches; it measures `claimed_ts_ms` (the sender's claimed time, normalized to ms) against `received_at_ms`: anything older than the window is `backdated-claim`
(EVIDENCE, not a silent drop). `compare A B` compares two parties' exports over the shared seq range, byte for byte.
IMPORTANT: a seq gap only proves deletion of an ALREADY WRITTEN entry; an entry never written leaves no gap. Protection against
omission is the sender-side comparison: `reconcile` (the remote party's receipt list — messages sent, replies
received, acks sent — vs. the log).

Mode: in product mode (bus_enforce.mode()) ON by default, and fail-closed: without cryptography or a notary key the
logger does not start → the boundary rejects. In dev mode OFF by default (back-compat); `AGENT_BUS_NOTARY=on|off` overrides
(it CANNOT be switched off in product mode). stdlib (+cryptography for signing)."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sds_envelope  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except Exception:                                           # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False

GENESIS = "0" * 64
DEFAULT_CHECKPOINT_EVERY = 50
DEFAULT_BACKDATE_WINDOW_S = 300
ENTRY_KEYS = ("seq", "prev_hash", "received_at_ms", "envelope_sha256", "sender_identity", "sender_auth",
              "recipient", "kind", "decision", "reason", "claimed_ts_ms")
SENDER_AUTH = ("ssh-key", "pickup-sig", "unauthenticated-claim")
DECISIONS = ("accepted", "rejected", "delivered")


class NotaryError(RuntimeError):
    pass


def jcs(v) -> bytes:
    return sds_envelope.jcs(v)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def envelope_hash(obj) -> str:
    """Hash of the canonical bytes (JCS). Not JCS-able (e.g. float) → hash of the JSON-serialized text, marked."""
    try:
        return sha256_hex(jcs(obj))
    except ValueError:
        return "json:" + sha256_hex(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def to_ms(ts: int) -> int:
    """The unit of the client ts from its magnitude: s (relay) · ms · µs · ns (the bus's time.time_ns)."""
    a = abs(ts)
    if a < 10 ** 11:
        return ts * 1000
    if a < 10 ** 14:
        return ts
    if a < 10 ** 17:
        return ts // 1000
    return ts // 1_000_000


def claimed_ts_of(msg) -> int | None:
    """The time claimed by the sender: the message's `ts`, or the `ts` of an SDS frame's record (if any)."""
    if not isinstance(msg, dict):
        return None
    for cand in (msg.get("ts"),):
        if isinstance(cand, int) and not isinstance(cand, bool):
            return cand
    if msg.get("kind") == "sds-envelope" and isinstance(msg.get("body"), str):
        try:
            rec, _ = sds_envelope.parse_framed(msg["body"])
            ts = rec.get("ts")
            return ts if isinstance(ts, int) and not isinstance(ts, bool) else None
        except ValueError:
            return None
    return None


def entry_hash(entry: dict) -> str:
    d = {k: entry[k] for k in ENTRY_KEYS}
    if entry.get("cursor") is not None:                  # the cursor numbers also in a MACHINE-readable, hashed field
        d["cursor"] = entry["cursor"]
    return sha256_hex(jcs(d))


def _ckpt_payload(c: dict) -> bytes:
    return jcs({"type": "checkpoint", "seq": c["seq"], "head_hash": c["head_hash"], "ts_ms": c["ts_ms"],
                "notary_pub": c["notary_pub"]})


# ── key ─────────────────────────────────────────────────────────────────────
def keypair():
    """-> (32-byte seed, public hex). The seed stays on the notary's machine."""
    if not HAVE_CRYPTO:
        raise NotaryError("cryptography missing")
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return seed, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def load_seed(path: str) -> bytes:
    raw = open(path, "rb").read().strip()
    try:
        b = bytes.fromhex(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        b = raw
    if len(b) != 32:
        raise NotaryError("notary key must be a 32-byte ed25519 seed (raw or hex)")
    return b


# ── mode ────────────────────────────────────────────────────────────────────
def is_product(db=None) -> bool:
    try:
        import bus_enforce
        return bus_enforce.mode(db=db) == "product"
    except Exception:                                        # the mode cannot be decided → the safe side
        return True


def enabled(db=None) -> bool:
    if is_product(db):
        return True                                          # cannot be switched off in product mode
    return (os.environ.get("AGENT_BUS_NOTARY") or "").strip().lower() in ("1", "on", "true", "yes")


def default_log_path() -> str:
    base = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))
    return os.environ.get("AGENT_BUS_NOTARY_LOG") or os.path.join(base, "notary", "notary.jsonl")


# ── logger ──────────────────────────────────────────────────────────────────
class Notary:
    """Append-only, hash-chained log. Serialized across processes with flock; the head comes from the file's last entry."""

    def __init__(self, path: str, seed: bytes | None = None, checkpoint_every: int = DEFAULT_CHECKPOINT_EVERY,
                 require_signing: bool = False, clock=None, db=None):
        if require_signing and (not HAVE_CRYPTO or seed is None):
            raise NotaryError("product mode: notary needs cryptography and a signing key (fail-closed)")
        self.path, self.seed, self.every, self.db = path, seed, max(1, int(checkpoint_every)), db
        self.clock = clock or (lambda: int(time.time() * 1000))
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            os.close(fd)
        self._priv = Ed25519PrivateKey.from_private_bytes(seed) if (seed is not None and HAVE_CRYPTO) else None
        self.pub = (self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
                    if self._priv else None)

    @classmethod
    def from_env(cls, db=None):
        """Entry point for the boundary integration: None if disabled; in product mode NotaryError without key/crypto."""
        if not enabled(db):
            return None
        kp = os.environ.get("AGENT_BUS_NOTARY_KEY")
        seed = load_seed(kp) if kp and os.path.exists(kp) else None
        return cls(default_log_path(), seed=seed, require_signing=is_product(db),
                   checkpoint_every=int(os.environ.get("AGENT_BUS_NOTARY_EVERY", DEFAULT_CHECKPOINT_EVERY)), db=db)

    def _tail(self, f):
        """(last seq, last entry_hash, number of entries since the last checkpoint) — from the file, not from memory."""
        seq, head, since = 0, GENESIS, 0
        f.seek(0)
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("type") == "entry":
                seq, head, since = rec["seq"], rec["entry_hash"], since + 1
            elif rec.get("type") == "checkpoint":
                since = 0
        return seq, head, since

    def last_round_cursor(self, identity: str) -> int:
        """The cursor of the most recently logged SSH delivery round for this identity (0 if none yet) — from the file."""
        cur = 0
        try:
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if (rec.get("type") == "entry" and rec.get("kind") == "pickup" and rec.get("decision") == "accepted"
                            and rec.get("recipient") == identity):
                        cc = rec.get("cursor")                 # the machine field first, only then the reason
                        if isinstance(cc, dict) and isinstance(cc.get("at"), int) and not isinstance(cc.get("at"), bool):
                            cur = cc["at"]
                        else:
                            c = _parse_round(rec.get("reason", ""))
                            if c is not None:
                                cur = c[0]
        except FileNotFoundError:
            pass
        return cur

    def record(self, *, envelope, sender_identity: str, sender_auth: str, recipient: str, kind: str,
               decision: str, reason: str = "", claimed_ts=None, cursor: dict | None = None) -> dict:
        if sender_auth not in SENDER_AUTH:
            raise NotaryError("unknown sender_auth")
        if decision not in DECISIONS:
            raise NotaryError("decision must be accepted|rejected|delivered")
        env_sha = envelope if (isinstance(envelope, str) and len(envelope) == 64) else envelope_hash(envelope)
        with open(self.path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                seq, head, since = self._tail(f)
                e = {"seq": seq + 1, "prev_hash": head, "received_at_ms": int(self.clock()), "envelope_sha256": env_sha,
                     "sender_identity": str(sender_identity or ""), "sender_auth": sender_auth,
                     "recipient": str(recipient or ""), "kind": str(kind or ""), "decision": decision,
                     "reason": str(reason or "")[:200],
                     "claimed_ts_ms": to_ms(claimed_ts) if (isinstance(claimed_ts, int) and not isinstance(claimed_ts, bool)) else None}
                # the round entry COMMITS ITSELF to the head of the bus's audit chain.
                # The NOTARY does this, not the writer: so no writer can "forget" it (`audit_head()` used to be
                # dead code). The anchor travels in `cursor`, so `entry_hash` binds it.
                # The anchor BELONGS TO THE NOTARY: it OVERWRITES one written by the writer too. (Measured 2026-09-16: the real
                # writer computed it itself, so the notary branch never ran — and with it the `closes`
                # commitment was never added. The anchor's value was thus the writer's word, not the notary's.)
                if (isinstance(cursor, dict) and kind == "pickup" and decision == "accepted"
                        and ("pending" in cursor or "pending_unknown" in cursor)):
                    try:
                        import agent_bus as _ab
                        _aseq, _ahash = _ab.audit_head(recipient, db=self.db)
                        # empty chain: the anchor is GENESIS — "when I wrote this, the bus chain had no rows yet".
                        # That is a claim too, and the comparison can hold it to account (row 0 must be in the export).
                        # `closes: 1` — the round COMMITS to the closing anchor (2.7). The NOTARY writes this too, not the
                        # writer: otherwise the bus machine would simply "not commit", and the unclosed round would stay
                        # silent (the non-Claude arm measured this escape hatch after wrongly believing
                        # it was already here — its mistake was the finding). Old logs have no `closes`, so
                        # nothing is demanded of them; the commitment is a property of the log's VERSION.
                        cursor = dict(cursor, audit_seq=int(_aseq or 0), audit_hash=_ahash or _ab._GENESIS,
                                      closes=1)
                    except Exception:
                        pass                              # a missing anchor does not fail the logging (fail-open ONLY here:
                                                          # the entry itself matters more; reconcile sees its absence)
                # ATTACK MATRIX 2.7 (open row, 2026-09-16): the OPENING anchor is written at the START of the round, so it
                # does not bind the round's OWN ack/delivery rows — on a single-round slice the second record could be
                # consistently re-chained. The CLOSING anchor is written AFTER the side effects, and the NOTARY computes it too:
                # the writer cannot forge it and cannot "forget" it (its absence shows in reconcile).
                if (isinstance(cursor, dict) and kind == "round_close" and decision == "accepted"
                        and "audit_end_seq" not in cursor):
                    try:
                        import agent_bus as _ab
                        _eseq, _ehash = _ab.audit_head(recipient, db=self.db)
                        cursor = dict(cursor, audit_end_seq=int(_eseq or 0), audit_end_hash=_ehash or _ab._GENESIS)
                    except Exception:
                        pass
                if cursor is not None:                    # A4: strict type, no int() laundering
                    # (1a): the ONLY non-numeric field is the head of the bus's audit chain (`audit_hash`,
                    # 64 hex) — the anchor the log commits to. Every other value stays a non-negative int.
                    if not isinstance(cursor, dict):
                        raise NotaryError("cursor must be a dict")
                    for _k, _v in cursor.items():
                        if _k in ("audit_hash", "audit_end_hash"):
                            if not (isinstance(_v, str) and re.fullmatch(r"[0-9a-f]{64}", _v)):
                                raise NotaryError("cursor audit_hash must be 64 hex characters")
                            continue
                        if not (isinstance(_v, int) and not isinstance(_v, bool) and _v >= 0):
                            raise NotaryError("cursor values must be non-negative int")
                    e["cursor"] = dict(cursor)
                e["entry_hash"] = entry_hash(e)
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(dict(type="entry", **e), ensure_ascii=False, sort_keys=True) + "\n")
                if self._priv is not None and since + 1 >= self.every:
                    f.write(json.dumps(self._checkpoint(e["seq"], e["entry_hash"]), sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
                return e
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def _checkpoint(self, seq: int, head: str) -> dict:
        c = {"type": "checkpoint", "seq": seq, "head_hash": head, "ts_ms": int(self.clock()), "notary_pub": self.pub}
        c["sig"] = self._priv.sign(_ckpt_payload(c)).hex()
        return c

    def checkpoint(self) -> dict:
        if self._priv is None:
            raise NotaryError("no signing key")
        with open(self.path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                seq, head, _ = self._tail(f)
                c = self._checkpoint(seq, head)
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(c, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
                return c
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


# ── export / verify / compare (offline, either party) ───────────────────────
def _no_evidence(recs):
    """The log is EMPTY if it contains no EVIDENCE — not if it contains no LINES.

    today's `if not _recs:` condition was about the number of LINES from `read_lines`.
    A single valid JSON object (`{}` or `{"kind": "something"}`) makes the list non-empty, but the number of ENTRIES
    stays zero — and `verify()` silently skips a non-`entry`/non-`checkpoint` record. So a
    GREEN certificate over zero entries, an hour after we had turned this same state into a named
    rejection. No malice needed: an unknown record type from a rolling version upgrade looks
    exactly like this. -> (is empty, number of entries, number of checkpoints)
    """
    n_e = sum(1 for r in recs if isinstance(r, dict) and r.get("type") == "entry")
    n_c = sum(1 for r in recs if isinstance(r, dict) and r.get("type") == "checkpoint")
    return (n_e == 0 and n_c == 0), n_e, n_c


def _reject_no_evidence(recs, cmd):
    """-> True if we rejected (the caller then stops with rc=1)."""
    empty, n_e, n_c = _no_evidence(recs)
    if not empty:
        return False
    print(json.dumps({"ok": False, "reason": "empty_log", "records": len(recs),
                      "entries": n_e, "checkpoints": n_c}, ensure_ascii=False, indent=1))
    print("bus_notary %s: REJECT — the log contains %d record(s), but 0 entries and 0 checkpoints among them. "
          "This is not a clean log but ZERO EVIDENCE: there is nothing to check, so nothing to attest."
          % (cmd, len(recs)), file=sys.stderr)
    return True


def read_lines(path: str) -> list:
    """The OTHER party's export AS A FILE — untrusted input, with a named rejection.

    Measured 2026-09-16 (I closed the same class on the capsule2 side, then checked here too):
      * `5` on one line  -> `AttributeError: 'int' object has no attribute 'get'` — RAW TRACEBACK
      * `[1,2,3]`        -> `AttributeError: 'list' object …`                     — RAW TRACEBACK
      * EMPTY file       -> **rc=0, GREEN** — the emptiest possible input passed `verify`
    The `type: garbage` line was a good idea (a non-JSON line does not blow up), but it only covered the JSON error: what
    is valid as JSON but not an OBJECT ran straight into `.get()`. And the empty file is not
    a "clean log" but ZERO EVIDENCE — absence of measurement is not green.
    """
    out = []
    with open(path, encoding="utf-8-sig") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                out.append({"type": "garbage", "line": n})
                continue
            if not isinstance(rec, dict):
                # valid JSON, but not an entry: the same class, named
                out.append({"type": "garbage", "line": n, "parsed_as": type(rec).__name__})
                continue
            out.append(rec)
    return out


def export(path: str, from_seq: int = 1) -> list:
    """The entries from from_seq on + the LATEST signed checkpoint (order preserved)."""
    recs = read_lines(path)
    entries = [r for r in recs if r.get("type") == "entry" and r.get("seq", 0) >= from_seq]
    ckpts = [r for r in recs if r.get("type") == "checkpoint"]
    return entries + ([ckpts[-1]] if ckpts else [])


def verify(records: list, trusted_pub: str | None = None, backdate_window_s: int = DEFAULT_BACKDATE_WINDOW_S,
           start_prev_hash: str | None = None) -> dict:
    """-> {ok, errors:[{seq, error}], checkpoints:[{seq, ok, error?}], backdated:[{seq, claimed_ts, received_at_ms}], head}.
    An export can also be verified from from_seq: it accepts the first entry's prev_hash (or binds it to start_prev_hash)."""
    errors, ckpts, backdated = [], [], []
    computed = {}
    last_seq, last_hash = None, None
    for r in records:
        t = r.get("type")
        if t == "garbage":
            errors.append({"seq": None, "error": "unparseable line %s" % r.get("line")})
            continue
        if t == "entry":
            try:
                h = entry_hash(r)
            except (KeyError, ValueError, TypeError):
                errors.append({"seq": r.get("seq"), "error": "malformed entry"})
                continue
            seq = r.get("seq")
            if h != r.get("entry_hash"):
                errors.append({"seq": seq, "error": "entry rewritten (hash mismatch)"})
            if last_seq is None:
                if start_prev_hash is not None and r.get("prev_hash") != start_prev_hash:
                    errors.append({"seq": seq, "error": "chain does not continue from the given prev_hash"})
                if seq == 1 and r.get("prev_hash") != GENESIS:
                    errors.append({"seq": seq, "error": "first entry must start at genesis"})
            else:
                if not isinstance(seq, int) or seq <= last_seq:
                    errors.append({"seq": seq, "error": "reordered (seq %s after %s)" % (seq, last_seq)})
                elif seq != last_seq + 1:
                    errors.append({"seq": seq, "error": "gap: entries %d..%d missing" % (last_seq + 1, seq - 1)})
                if r.get("prev_hash") != last_hash:
                    errors.append({"seq": seq, "error": "chain broken (prev_hash does not match previous entry)"})
            ct = r.get("claimed_ts_ms")
            if isinstance(ct, int) and not isinstance(ct, bool):
                if ct < r.get("received_at_ms", 0) - backdate_window_s * 1000:
                    backdated.append({"seq": seq, "claimed_ts_ms": ct, "received_at_ms": r.get("received_at_ms")})
            computed[seq] = r.get("entry_hash")
            if isinstance(seq, int) and (last_seq is None or seq > last_seq):
                last_seq, last_hash = seq, r.get("entry_hash")
        elif t == "checkpoint":
            # the report shows WHICH key signed it; "trusted" only with a --pub fixed out of band
            c = {"seq": r.get("seq"), "ok": True, "notary_pub": r.get("notary_pub"),
                 "trusted": bool(trusted_pub) and r.get("notary_pub") == trusted_pub}
            if not HAVE_CRYPTO:
                c.update(ok=False, error="cannot verify signature: cryptography missing")
            elif trusted_pub and r.get("notary_pub") != trusted_pub:
                c.update(ok=False, error="checkpoint signed by an untrusted key")
            else:
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(r["notary_pub"])).verify(bytes.fromhex(r["sig"]),
                                                                                                _ckpt_payload(r))
                except (InvalidSignature, KeyError, ValueError, TypeError):
                    c.update(ok=False, error="forged checkpoint signature")
            if c["ok"] and r.get("seq") in computed and computed[r["seq"]] != r.get("head_hash"):
                c.update(ok=False, error="checkpoint head_hash does not match the chain")
            if c["ok"] and r.get("seq") not in computed and r.get("seq", 0) > (last_seq or 0):
                c.update(ok=False, error="checkpoint points beyond the exported chain")
            if not c["ok"]:
                c["trusted"] = False
                errors.append({"seq": r.get("seq"), "error": c["error"]})
            ckpts.append(c)
    # `ok` = internal consistency of the chain and signatures; `trusted` = AND at least one checkpoint in the slice ACTUALLY
    # verified with the given, trusted key and binds to the head_hash of an exported entry.
    # Without --pub, a made-up chain signed with a key anyone generated is also `ok` — so there `trusted` is never true.
    # a slice without a checkpoint (<N entries of a fresh log, or an export before the next checkpoint)
    # is not "trusted" even with the correct --pub: no signature was verified there, only the hash chain.
    verified = [c for c in ckpts if c["ok"] and c["trusted"] and c["seq"] in computed]
    covered_to = max((c["seq"] for c in verified), default=None)
    entry_seqs = [s for s in computed if isinstance(s, int)]
    unverified_tail = len([s for s in entry_seqs if covered_to is None or s > covered_to])
    # `trusted` is a claim about the SLICE — true only if EVERY entry of the slice
    # is covered by a verified checkpoint (unverified_tail == 0). The tail after the last checkpoint
    # (rewritten or made-up, re-chained entries) stands only on the hash chain, no signature binds it → trusted:false.
    trusted = (not errors) and bool(trusted_pub) and bool(verified) and unverified_tail == 0
    # the internal consistency of the "cursor F->T (ack U)" entry can be checked from the log, even without the party
    # — the honest clamp is T = max(F, min(U, cap)), so T <= max(F, U). A separate field (not a chain error: the
    # slice can be intact and signed and still lie); the CLI signals it with rc=1.
    ack_violations = []
    for r in records:
        if r.get("type") == "entry" and r.get("kind") == "ack" and r.get("decision") == "accepted":
            c = r.get("cursor")                                # verify also reads the MACHINE field first
            if isinstance(c, dict) and all(isinstance(c.get(k), int) and not isinstance(c.get(k), bool) for k in ("from", "to", "ack")):
                frm, to, up = c["from"], c["to"], c["ack"]
            else:
                m = _ACK_RE.match(r.get("reason", "") or "")
                frm, to, up = (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (None, None, None)
            if to is not None and to > max(frm, up):
                ack_violations.append({"seq": r.get("seq"), "recipient": r.get("recipient"), "reason": r.get("reason"),
                                       "cursor_from": frm, "cursor_to": to, "ack": up})
    # `trusted` used to measure ONLY the tail of the slice. The START of the slice is a claim too:
    # an `export --from-seq 11` slice can be internally intact and signed while entries 1..10 are missing. The log
    # alone does not show the gap — so the report states where the slice starts and whether it is ANCHORED
    # (starts from genesis, or the caller gave a `start_prev_hash` known out of band).
    slice_start = min(entry_seqs) if entry_seqs else None
    anchored = bool(start_prev_hash) or slice_start == 1
    return {"ok": not errors, "trusted": trusted and anchored, "signer_unverified": not verified,
            "slice_start_seq": slice_start, "anchored": anchored,
            "ack_target_violations": ack_violations,
            "checkpoint_count": len(ckpts), "verified_checkpoint_count": len(verified),
            "no_checkpoint_in_range": not verified, "covered_to_seq": covered_to, "unverified_tail": unverified_tail,
            "signers": sorted({c["notary_pub"] for c in ckpts if c.get("notary_pub")}),
            "errors": errors, "checkpoints": ckpts, "backdated": backdated,
            "head": {"seq": last_seq, "hash": last_hash}}


def compare(a: list, b: list) -> dict:
    """Whether two parties' exports are about the same chain. -> {same, fork, reason, overlap, compared, first_diff}.

    37Z): the earlier version compared ONLY entries with a shared seq, and
    with no shared seq it returned same:true — two branches of a fork exported side by side were thus "the same", and the checkpoints
    were not even evaluated. Now everything COMPARABLE between the two exports is compared:
      1. canonical bytes of entries with the same seq;
      2. head_hash of checkpoints with the same seq (mismatch = fork);
      3. a checkpoint on one side, an entry on the other at the same seq (head_hash != entry_hash = fork);
      4. boundary chaining: after entry s on one side, the prev_hash of entry s+1 on the other side (mismatch = fork).
    If NOTHING was comparable: same=None, reason="no_overlap" — that is NOT "fine"."""
    def entries(x):
        return {r["seq"]: r for r in x if r.get("type") == "entry" and isinstance(r.get("seq"), int)}

    def ckpts(x):
        return {r["seq"]: r.get("head_hash") for r in x if r.get("type") == "checkpoint" and isinstance(r.get("seq"), int)}
    ea, eb, ca, cb = entries(a), entries(b), ckpts(a), ckpts(b)
    compared, seqs = 0, set()

    def verdict(same, reason, s=None):
        rng = [min(seqs), max(seqs)] if seqs else None
        return {"same": same, "fork": same is False, "reason": reason, "overlap": rng, "compared": compared,
                "first_diff": s}

    checks = []
    for s in sorted(set(ea) & set(eb)):
        checks.append((s, "entry_differs", jcs(ea[s]) == jcs(eb[s])))
    for s in sorted(set(ca) & set(cb)):
        checks.append((s, "checkpoint_head_differs", ca[s] == cb[s]))
    for side_c, side_e in ((ca, eb), (cb, ea)):
        for s in sorted(set(side_c) & set(side_e)):
            checks.append((s, "checkpoint_vs_entry_differs", side_c[s] == side_e[s].get("entry_hash")))
    for left, right in ((ea, eb), (eb, ea)):
        for s in sorted(left):
            if s + 1 in right and s + 1 not in left:
                checks.append((s + 1, "chain_link_differs", right[s + 1].get("prev_hash") == left[s].get("entry_hash")))
    for s, reason, ok in sorted(checks, key=lambda c: c[0]):
        compared += 1
        seqs.add(s)
        if not ok:
            return verdict(False, reason, s)
    if not compared:
        return verdict(None, "no_overlap")
    return verdict(True, "consistent")


# ── reconcile: the remote party's receipts vs. the log ──────────────────────
_ROUND_RE = re.compile(r"^cursor=(\d+) replies=(\d+)$")
_ACK_RE = re.compile(r"^cursor (\d+)->(\d+) \(ack (\d+)\)$")


def _parse_round(reason):
    m = _ROUND_RE.match(reason or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


PROVEN_ARRIVED = ("delivered", "reached")   # the client outcome that proves the request arrived


_GENESIS_HASH = "0" * 64                                   # anchor of an empty chain (agent_bus._GENESIS)


def _audit_cross(entries, identity, bus_audit, entries_all=None):
    """54Z's open item: we measure the SELF-REPORTED numbers of the round entry against the bus's OWN, hash-chained
    cursor_audit export. The log alone does not refute a lying `pending`/`next_id` — but a contradiction between the two
    records is evidence. -> list of discrepancies (hard)."""
    out = []
    # there is no good reason to accept `agent: None` (today it is only reachable by forgery),
    # and an export for a FOREIGN agent used to narrow SILENTLY to 0 rows to examine — the file was not empty, so it
    # also passed the "incomplete evidence" gate. Both now stated.
    given = [r for r in (bus_audit or []) if isinstance(r, dict)]
    rows = [r for r in given if r.get("agent") == identity]
    # the anchors of the round entries: the log COMMITTED to how far the export must reach
    anchored_rounds = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "pickup"
                       and e.get("decision") == "accepted" and isinstance(e.get("cursor"), dict)
                       and ("pending" in e["cursor"] or "pending_unknown" in e["cursor"])]
    # THE CONSISTENT WRITER (MEDIUM (b), measured): whoever writes the log also computes the chain,
    # so the hash guard does NOT protect against its fields. A sweep of the `cursor` sub-fields shows this numerically: in your
    # slice (WITHOUT a signed checkpoint) 42 of 68 forgeries stay silent; THE SAME sweep on an
    # export that contains a SIGNED checkpoint gives 0 silent. The difference is not that anyone READS
    # those fields, but the SIGNATURE: the writer can re-chain, but cannot re-sign the notary's checkpoint.
    # Over a slice WITHOUT a checkpoint, the writer's word is thus the only backing — and until now
    # nothing said so. (Third channel: stated, not a verdict — putting it in `soft` would turn every test
    # that works with sparse checkpoints red.)
    if anchored_rounds and not any(r.get("type") == "checkpoint" for r in entries_all or []):
        out.append({"type": "slice_without_signed_checkpoint", "rounds": [e.get("seq") for e in anchored_rounds][:4],
                    "note_only": True,
                    "why": "this slice has NO signed checkpoint, so the self-reported numbers in it "
                           "rest only on the WRITER's word: whoever writes the log can also recompute "
                           "the hash chain"})
    if bus_audit is None and anchored_rounds:
        # The FOURTH attempt at the same item (one arm's two open `test_joint_delivery_outcome`
        # probes), now MEASURED, not from memory. Put into the `soft` (= `unresolved`) channel, the signal gives `ok:false` in strict
        # mode, and that turns THREE honest CONTROL tests red — two of them are theirs:
        #   test_joint_clamp_optout::test_control_honest_round_is_not_accused
        #   test_joint_cursor_skips_undelivered::test_control_honest_full_round_is_not_accused
        #   test_log_shape_20260916::test_control_the_untouched_export_is_green
        # These pin that the HONEST round is not accused — and they are right. But the missing second record
        # cannot stay SILENT either: WITHOUT A SECOND RECORD `reconcile` cannot measure whether the cursor
        # stepped over undelivered mail, so the "I skipped nothing" claim is UNVERIFIED here.
        # So it goes to the THIRD channel introduced today (`notes` + counter): stated, but not a verdict.
        out.append({"type": "audit_register_absent", "rounds": [e.get("seq") for e in anchored_rounds][:4],
                    "note_only": True,
                    "why": "without the `bus_audit` second record the round's self-reported numbers are "
                           "UNVERIFIED — this is neither an accusation nor a green tick, but a missing measurement"})
    if bus_audit is not None and not given and anchored_rounds:
        # 9/4: an export passed EMPTY used to narrow silently to 0 rows to examine on the library path
        out.append({"type": "audit_evidence_absent", "rounds": [e.get("seq") for e in anchored_rounds]})
        return out
    if given and not rows:
        out.append({"type": "audit_identity_mismatch", "identity": identity,
                    "export_agents": sorted({str(r.get("agent")) for r in given})})
        return out
    if not rows:
        return out
    # 9/2: the library path used NOT to run the chain self-check (only the CLI did), so an export with a seq gap
    # ("0..5 and 10..12") passed. The gap is exactly how the evidence can be extinguished.
    try:
        import agent_bus as _ab
        _chk = _ab.audit_chain_verify(rows)
        # the question here is the CHAIN's integrity; the anchor is bound by the round entries' `audit_seq`/`audit_hash` field
        # (`audit_head_not_covered` / `audit_head_hash_mismatch`), so we read `chain_ok`, not `ok`
        if not _chk.get("chain_ok", _chk.get("ok")):
            out.append({"type": "audit_chain_broken", "errors": _chk.get("errors", [])[:4]})
            return out
    except Exception as _e:
        # Our own routine survey (2026-09-16): this branch was `except Exception: pass`, so if the
        # chain self-check throws FOR ANY REASON (missing field, wrong type in the other party's export),
        # `audit_chain_broken` vanished SILENTLY — the ABSENCE of measurement looked green. This is the same class that
        # the B arm stated three times on the corpus side: a missing measurement is a THIRD STATE, not green.
        out.append({"type": "audit_chain_unverifiable", "error": _e.__class__.__name__, "soft": True})
    acks = [r for r in rows if str(r.get("op", "")).startswith("ack")]
    # 1) the cursor steps of the logged acks must match the bus's audit rows (from_id -> to_id)
    logged = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "ack"
              and e.get("decision") == "accepted"]
    # (2026-09-17): the two records were paired BY POSITION (`zip`), so after one missing log ack
    # every further pair SLID, and the accusation pointed at an HONEST entry (measured: the 3rd log ack is 20→30 and the 3rd audit
    # row says the same, yet mismatch, because zip paired it with the 2nd audit row). Now we pair BY KEY: the audit row's
    # (from_id, to_id) step ↔ the log ack's (cursor.from, cursor.to) step, in log order, each row at most once.
    def _step_a(a):
        return (a.get("from_id"), a.get("to_id"))

    def _step_e(e):
        c = e.get("cursor") if isinstance(e.get("cursor"), dict) else {}
        return (c.get("from"), c.get("to"))

    _free = list(range(len(logged)))
    _pair = {}                                                   # audit index -> log-ack index
    for _ai, _a in enumerate(acks):
        for _li in _free:
            if _step_e(logged[_li]) == _step_a(_a):
                _pair[_ai] = _li
                _free.remove(_li)
                break
    _unpaired_audit = [a for _ai, a in enumerate(acks) if _ai not in _pair]
    for _li in _free:
        # a logged ack with NO audit row of the same step: the accusation points at the log entry, and shows the unpaired
        # audit steps beside it (not a row picked by position, possibly an honest one)
        e = logged[_li]
        frm, to = _step_e(e)
        if isinstance(frm, int) and isinstance(to, int):
            out.append({"type": "audit_cursor_mismatch", "seq": e.get("seq"), "log": [frm, to],
                        "bus_audit": [[a.get("from_id"), a.get("to_id")] for a in _unpaired_audit][:4],
                        "audit_seq": [a.get("seq") for a in _unpaired_audit][:4]})
    # SECOND pass, in order: what did not pair by key (e.g. a log ack WITHOUT `to` — per the quantifier-commitment test
    # a missing ack target cannot buy silence) is paired by position for the ACCUSATION ATTRIBUTION. The discrepancy report
    # (above) and coverage (`audit_row_unlogged`, below) stand on the key pass's result — the slide cannot reach them.
    for _ai, _li in zip([ai for ai in range(len(acks)) if ai not in _pair], list(_free)):
        _pair[_ai] = _li
    # 2) the bus audit row knows how many undelivered rows the cursor stepped over (skipped_undelivered) — the log's "no
    #    undelivered" (next_id=0 / pending==replies) claim contradicts it
    skipped = sum(int(a.get("skipped_undelivered") or 0) for a in acks)
    rounds = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "pickup"
              and e.get("decision") == "accepted" and isinstance(e.get("cursor"), dict)]
    # the highest target of the log's acks: the cursor moved this far according to the log
    ack_top = max([c.get("to") for c in (e.get("cursor") for e in logged)
                   if isinstance(c, dict) and isinstance(c.get("to"), int)] or [0])

    def _claims_no_skip(cur, ack_top=ack_top):
        """Does the round entry claim that NOTHING undelivered remained below the ack?

        `ack_top` is now the ack target of THE round in question,
        not the log's global maximum: the accusation must be attributed to a round, otherwise ANOTHER round's data decides it.
        """
        if cur.get("pending") == cur.get("replies"):
            return True                                        # "I delivered as many as there were"
        nid = cur.get("next_id")
        if not nid:
            return True                                        # "there is no first undelivered"
        # later round: a lying `next_id` can be pushed ABOVE the ack TARGET — that is equally an "I skipped
        # nothing below the ack" claim, so it contradicts the bus's skipped_undelivered row.
        # 8/3: ONLY if we actually SAW a logged ack target. With `ack_top == 0` (old/foreign
        # format, missing `to`) this fallback would accuse every honest truncated round —
        # silence is not evidence, and a missing ack target is incomplete evidence, not an accusation.
        return bool(ack_top) and isinstance(nid, int) and nid > ack_top
    # BLOCKER (measured, reproduced): the accusation rested on a GLOBAL AND —
    #   `claimed_all = all(_claims_no_skip(r["cursor"]) for r in rounds)`
    # — `skipped` summed over the WHOLE log, but the quantifier over EVERY round entry. One more
    # round, HONEST ON ITS OWN (one that admits an undelivered row below its ack target), was enough, and the accusation was RETROACTIVELY
    # dropped from ALL rounds — including the one that lied, while the bus's hash-chained audit row
    # still knew that 4 messages were permanently lost. The bypass needs no cryptography, does not break
    # the chain, forges nothing: it appends one regular row, the kind normal operation produces anyway.
    # Fixed by building on the EXISTING pairing (`zip(logged, acks)`): the skip belongs to the round whose
    # ACK produced `skipped_undelivered > 0`, and the claim is measured on THAT round's entry.
    _accused, _unattributable = [], []
    for _i, _a in enumerate(acks):
        _sk = int(_a.get("skipped_undelivered") or 0)
        if _sk <= 0:
            continue
        _li = _pair.get(_i)                                      # the log ack paired by key, not by position
        _e = logged[_li] if _li is not None else None
        if _e is None:
            # The audit row knows of a skip for which the log has NO ack. Not an accusation (coverage is
            # measured by `audit_row_missing` in the other direction), but not green either: the measurement is MISSING.
            _unattributable.append({"type": "audit_skip_unattributable", "audit_seq": _a.get("seq"),
                                    "skipped_undelivered": _sk, "soft": True})
            continue
        _c = _e.get("cursor") if isinstance(_e.get("cursor"), dict) else {}
        _ack_to = _c.get("to") if isinstance(_c.get("to"), int) and not isinstance(_c.get("to"), bool) else 0
        _eseq = _e.get("seq") if isinstance(_e.get("seq"), int) and not isinstance(_e.get("seq"), bool) else None
        # BLOCKER (measured, reproduced with their probe: 2 red / 3 green controls).
        # The responsible round used to be the LAST `pickup` BEFORE the ack (`_cand[-1]`) — except the log is written BY
        # the party we check, so the attacker COULD CHOOSE who answers for it: it was enough to write one more `pickup` BETWEEN the lying
        # round and ITS OWN ack that OMITS `pending` from its `cursor`. Such an entry claims
        # nothing ("I never said I skipped nothing"), yet the accusation landed on it — and vanished.
        # In dev mode (the CLI default) this gave rc=0, ok:true over FOUR permanently lost messages.
        # This is our own "optional machine field = silent opt-out" class, at a third degree of freedom: first the
        # QUANTIFIER (b66bac3), then the ORDER (40396fc), now WHO ANSWERS.
        #
        # The fix is their proposal, measured: the responsible party is not a selectable entry but the ACK WINDOW —
        # EVERY round opened between the previous logged ack and THIS ack —, and within the window the one answers
        # who CLAIMS it skipped nothing. Whoever stays silent does not answer, but does not ACQUIT anyone else either.
        _pseq = None
        if _li > 0:                                              # the ack window's boundary: the previous ack IN THE LOG (paired by key)
            _p = logged[_li - 1].get("seq")
            _pseq = _p if isinstance(_p, int) and not isinstance(_p, bool) else None
        _cand = [r for r in rounds if isinstance(r.get("seq"), int)
                 and (_eseq is None or r["seq"] < _eseq)
                 and (_pseq is None or r["seq"] > _pseq)]
        _claimers = [r for r in _cand if _claims_no_skip(r["cursor"], _ack_to)]
        _gov = _claimers[-1] if _claimers else (_cand[-1] if _cand else None)
        if _gov is None:
            # The non-Claude arm's round on the quantifier fix (and TRUE): if the round entry stands
            # AFTER the ack in the log, there is no round "before", and the HARD accusation silently weakened to SOFT — so the attacker
            # downgrades evidence merely by ORDER. But the order itself is a protocol violation:
            # the `pickup` opening the round cannot stand behind its own ack. So we bind the accusation to the first round
            # AFTER the ack, and we STATE the abnormal order.
            _after = [r for r in rounds if isinstance(r.get("seq"), int)
                      and _eseq is not None and r["seq"] > _eseq]
            if _after:
                _gov = _after[0]
                out.append({"type": "round_entry_after_its_ack", "round_seq": _gov.get("seq"),
                            "ack_seq": _e.get("seq"),
                            "note": "the entry opening the round stands BEHIND its own ack in the log"})
        if _gov is None:
            # OUR OWN ROUND: the partner found three
            # degrees of freedom (quantifier, order, who answers), and each got a gate. I
            # claimed the root is not the lack of gates, but that THE CHECKED PARTY WRITES THE
            # EVIDENCE IN FREE FORM — and I have to measure that, not just claim it. Measured:
            #
            #   the `rounds` filter rests on FOUR fields (`recipient`, `kind`, `decision`, type of `cursor`),
            #   and ALL FOUR are in the attacker's hands. Spoiling any one of them, the lying round DROPS OUT of the
            #   filter, and the HARD accusation silently weakens to `audit_skip_unattributable` (soft) —
            #   in dev mode `ok=true` over FOUR permanently lost messages.
            #
            # So the fix is NOT a fifth gate. The distinction is the point:
            #   * there is NO entry AT ALL in the window  -> really not measurable (soft, stays)
            #   * there ARE entries in the window, but none FITS the round's shape -> this is not the ABSENCE
            #     of evidence, but EVASION of evidence: the log has rows exactly at the place
            #     where it should answer, just in a shape the filter does not pick up. That is an ACCUSATION.
            # BLOCKER — THE FIFTH degree of freedom, exactly where my point 3 predicted:
            # this window filtered on the `kind != "ack"` LABEL, and the label is written by the party under examination. The lying round,
            # relabelled to `kind="ack"`, dropped out of `rounds` (no one to accuse), of `logged` (no
            # audit_row_missing) AND of this window -> the silent soft remained, in dev mode rc=0 over SIX permanently
            # lost messages. Whitelisting `kind` does NOT help (they measured it): "ack" is a regular value.
            # The fix is their proposal, measured: the exclusion should rest not on the LABEL, but on the set that gives
            # the window's BOUNDARY — the seqs of the logged acks. Whoever is not a boundary is inside the window.
            _ack_seqs = {e.get("seq") for e in logged}
            _win = [e for e in entries
                    if isinstance(e.get("seq"), int) and not isinstance(e.get("seq"), bool)
                    and (_eseq is None or e["seq"] < _eseq) and (_pseq is None or e["seq"] > _pseq)
                    and e.get("seq") not in _ack_seqs]
            if _win:
                out.append({"type": "round_shape_dodges_attribution", "audit_seq": _a.get("seq"),
                            "skipped_undelivered": _sk, "ack_seq": _e.get("seq"),
                            "entries_in_window": [e.get("seq") for e in _win][:4],
                            "note": "the bus audit row reports a skip, there ARE entries in the ack window, "
                                    "but none in the shape of a round — the responsible party is not missing but evading"})
            else:
                _unattributable.append({"type": "audit_skip_unattributable", "audit_seq": _a.get("seq"),
                                        "skipped_undelivered": _sk, "ack_seq": _e.get("seq"), "soft": True})
            continue
        if _claims_no_skip(_gov["cursor"], _ack_to):
            _accused.append({"round_seq": _gov.get("seq"), "audit_seq": _a.get("seq"),
                             "skipped_undelivered": _sk})
    if _accused:
        out.append({"type": "audit_skipped_contradicts_log",
                    "skipped_undelivered": sum(x["skipped_undelivered"] for x in _accused),
                    "rounds": [x["round_seq"] for x in _accused], "per_round": _accused[:4]})
    out.extend(_unattributable[:4])
    # 3) COVERAGE (BLOCKER): a SHORTER but internally intact export is neither a lie nor a forgery — yet it
    #    extinguishes the evidence. Two bindings close it: (a) every ack in the log needs an audit row; (b) if the
    #    round entry committed to the chain head (audit_seq), the export MUST REACH that far.
    if len(logged) > len(acks):
        out.append({"type": "audit_row_missing", "logged_acks": len(logged), "audit_ack_rows": len(acks)})
    if len(acks) > len(logged):
        # (a): the gate was ONE-WAY — it only looked at the log saying MORE than the bus audit. The reverse
        # direction is exactly the direction of HIDING (the independent record knows more than the self-report): 2 log acks / 3 audit
        # rows, even 0 / 3, were SILENT. Now it has its own name and names WHICH audit row has no log ack.
        out.append({"type": "audit_row_unlogged", "logged_acks": len(logged), "audit_ack_rows": len(acks),
                    "audit_seq": [a.get("seq") for a in _unpaired_audit][:8],
                    "steps": [[a.get("from_id"), a.get("to_id")] for a in _unpaired_audit][:8]})
    for r in anchored_rounds:
        if r["cursor"].get("strict_ack_unknown") == 1:
            # The round could NOT measure whether the clamp's escape hatch was open. This is a third state: not
            # an accusation (the measurement may throw for a legitimate reason), but not green either — exactly the fact that would
            # qualify the round as strict is missing.
            out.append({"type": "strict_ack_unknown", "round_seq": r.get("seq"), "soft": True})
        if r["cursor"].get("strict_ack") == 0:
            # The round STATED that the clamp was off: not an accusation (it may be a legitimate operator decision), but
            # not green in strict/product mode — the cursor could then step over undelivered mail.
            out.append({"type": "strict_ack_disabled", "round_seq": r.get("seq"), "soft": True})
    top = max([r.get("seq") for r in rows if isinstance(r.get("seq"), int)] or [-1])
    by_seq = {r.get("seq"): r for r in rows if isinstance(r.get("seq"), int)}
    for r in anchored_rounds:
        want = r["cursor"].get("audit_seq")
        want_hash = r["cursor"].get("audit_hash")
        if not (isinstance(want, int) and not isinstance(want, bool)):
            # 9/1: OMITTING the anchor was the escape hatch (the write is fail-open). The absence is a third
            # state: not an accusation, but not green either — ok:false in strict/product mode.
            out.append({"type": "audit_anchor_absent", "round_seq": r.get("seq"), "soft": True})
            continue
        if top < want:
            out.append({"type": "audit_head_not_covered", "round_seq": r.get("seq"),
                        "committed_audit_seq": want, "export_top_seq": top})
            continue
        # 9/3: until now we asked ONLY for the seq number, not the HASH — the content could be swapped while the
        # chain stays internally intact. The anchor binds to the row's row_hash; a GENESIS anchor (empty chain) means that
        # the export must start from row 0.
        if want_hash == _GENESIS_HASH:
            if by_seq and min(by_seq) != 0:
                out.append({"type": "audit_head_hash_mismatch", "round_seq": r.get("seq"),
                            "committed": "genesis", "export_start_seq": min(by_seq)})
        elif isinstance(want_hash, str) and want in by_seq and by_seq[want].get("row_hash") != want_hash:
            out.append({"type": "audit_head_hash_mismatch", "round_seq": r.get("seq"), "committed_audit_seq": want,
                        "committed": want_hash[:12], "export": str(by_seq[want].get("row_hash"))[:12]})
    # ATTACK MATRIX 2.7: the OPENING anchor does not bind the round's own rows. The CLOSING anchor (the `round_close`
    # written after the side effects) does — if present. Its absence is a THIRD STATE: not an accusation (the closing write may have been interrupted),
    # but not green either; ok:false in strict/product mode, because exactly the slice under examination stays unbound.
    closes = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "round_close"
              and e.get("decision") == "accepted" and isinstance(e.get("cursor"), dict)
              and isinstance(e["cursor"].get("audit_end_seq"), int)]
    # HIGH (measured with the REAL 40bb502 log, not constructed): holding to account is switched off by the
    # CHECKED party OMITTING its own field. `closes` travels in the log, so it is the word of the party
    # under examination — and the report said so NOWHERE until now: between the morning (no commitment) and
    # the evening log ONLY a counter differed (`rounds_pledged` 0 vs 2), and nothing qualified it.
    # For the sibling field (`audit_seq`, the opening anchor) the same omission already gives a third state — the code
    # knew the pattern, it just did not apply it here. No malice needed: an old notary on a partner machine that was not
    # upgraded writes an internally perfect, SIGNED chain. The hash chain protects against FORGERY, not against
    # VERSION MISMATCH.
    # NOT an accusation, and NOT per round (their probe does not ask for an accusation either, and our own `test_old_round_without_the_pledge_
    # is_not_accused` test pins that an old round must not get `audit_close_missing`): the signal is about the
    # LOG as a whole, and only if NOT A SINGLE round commits — a mixed log (rolling upgrade)
    # only gets a counter.
    _unpledged = [r for r in anchored_rounds if r["cursor"].get("closes") != 1]
    if _unpledged and len(_unpledged) == len(anchored_rounds):
        out.append({"type": "audit_close_pledge_absent", "rounds_unpledged": len(_unpledged),
                    "note": "NOT A SINGLE round of the log commits to the closing anchor (`closes`), so the "
                            "round-close check has nothing to hold it to — this is not an accusation, but not green either",
                    "soft": True})
    for r in anchored_rounds:
        if r["cursor"].get("closes") != 1:
            continue                                  # an old round that did NOT commit to closing: nothing to hold it to
        rseq = r.get("seq")
        # Pairing goes by ORDER, not by matching the cursor value: the cursor may move during the round
        # (ack), and that would spoil a value-based pairing — besides, between two rounds with the same `at`
        # an OLD close could make an unclosed round look "closed". The close belongs to the round that
        # DIRECTLY precedes it: the first `round_close` before the next round entry.
        nxt = min([x.get("seq") for x in anchored_rounds
                   if isinstance(x.get("seq"), int) and isinstance(rseq, int) and x["seq"] > rseq] or [None]) \
            if isinstance(rseq, int) else None
        mine = [c for c in closes if isinstance(c.get("seq"), int) and isinstance(rseq, int)
                and c["seq"] > rseq and (nxt is None or c["seq"] < nxt)]
        # …and if the close NAMES its round (`round_seq`), it must match: order only restrains,
        # the name binds. (Old closes have no `round_seq` — order remains for them.)
        named = [c for c in mine if isinstance(c["cursor"].get("round_seq"), int)]
        if named:
            mine = [c for c in named if c["cursor"]["round_seq"] == rseq]
        if not mine:
            # The round COMMITTED to closing in its hash-chained entry, yet there is no closing anchor: either the
            # round was interrupted (the response said `round_close: "failed"`), or someone cut off the end of the log. Both
            # mean that EXACTLY THIS slice stays unbound -> not green.
            # THIRD STATE (soft): an interrupted round may also be LEGITIMATE (the closing write is fail-open), so this is not
            # an accusation — but not green either, because the end of the slice under examination stays unbound. So the existing hard
            # discrepancy lists stay unchanged, while strict/product mode
            # gives ok:false.
            out.append({"type": "audit_close_missing", "round_seq": rseq, "soft": True})
            continue
        c = min(mine, key=lambda x: x["seq"])
        end = c["cursor"]["audit_end_seq"]
        end_hash = c["cursor"].get("audit_end_hash")
        # The non-Claude arm (1): the closing anchor would point to an OLD chain head if the close were written
        # BEFORE the side effects. The anchor is MONOTONIC: the chain head at the end of the round cannot be before the one at the start.
        open_seq = r["cursor"].get("audit_seq")            # from THIS round, not from the previous cycle's leftover
        if isinstance(open_seq, int) and not isinstance(open_seq, bool) and end < open_seq:
            out.append({"type": "audit_close_before_open", "round_seq": rseq, "open_audit_seq": open_seq,
                        "close_audit_seq": end})
            continue
        if top < end:
            out.append({"type": "audit_close_not_covered", "round_seq": rseq, "close_seq": c.get("seq"),
                        "committed_audit_seq": end, "export_top_seq": top})
            continue
        if end_hash == _GENESIS_HASH:
            if by_seq and min(by_seq) != 0:
                out.append({"type": "audit_close_hash_mismatch", "round_seq": rseq, "committed": "genesis",
                            "export_start_seq": min(by_seq)})
        elif isinstance(end_hash, str) and end in by_seq and by_seq[end].get("row_hash") != end_hash:
            out.append({"type": "audit_close_hash_mismatch", "round_seq": rseq, "committed_audit_seq": end,
                        "committed": end_hash[:12], "export": str(by_seq[end].get("row_hash"))[:12]})
    return out


def reconcile(records: list, identity: str, receipts: list, start_cursor: int = 0, trusted_pub: str | None = None,
              strict: bool | None = None, bus_audit: list | None = None) -> dict:
    """Protection against omission (a seq gap only proves deletion): the remote party's OWN receipt list vs. an export.
    receipts: per round {"sent": [sent message dicts], "ack": ack sent (0 = none), "received": [received reply dicts]}.
    -> {ok, verify_ok, trusted, discrepancies: [...], unconfirmed_deliveries: [...], counts}.
    Discrepancy types:
      sent_not_logged            — I sent it, the log does not know about it (omitted inbound entry)
      received_not_logged        — I received it, the log did not record the delivery
      ack_sent_not_logged        — I sent an ack, there is no entry for it
      cursor_moved_without_logged_ack — the logged cursor moved without a logged ack for it
                                    (a cursor advanced on the bus machine without logging = swallowed mail)
      ack_logged_not_sent        — the log claims an ack the party did not send (a made-up ack could cover swallowing)
      cursor_target_exceeds_ack  — "cursor F->T (ack U)" T > max(F, U): the honest clamp only moves down, so this is
                                   a false cursor target even from the log alone, without the party (verify flags it as an error too)
      delivered_not_received     — the log claims a delivery the party did not receive (over-logging OR a lying delivery; it
                                   cannot be decided without the party's receipt) — on the CLI rc=1 in product mode / with --strict
    unconfirmed_deliveries: the same items as a list (compatibility). The two reverse directions rely on the COMPLETENESS
    of the receipts: the receipt file must cover the same period as the export.
    Round outcome: the client's request line carries a `round` id, and at the end of the round a `phase:
    "outcome"` line says: `delivered` (can accuse), `unknown` (may have gone out, the reply did not come -> `unresolved` list,
    ok:false only in strict/product mode), `not-sent` (not an accusation, and its ack does not cover either), `reached` (a valid JSON reply came, even an error message: the request provably arrived -> accuses like `delivered`). A line without a round id = old format = delivered.
    `strict=None` -> strict in product mode."""
    from collections import Counter
    entries = [r for r in records if r.get("type") == "entry"]
    # SHAPE GATE ON THE LOG (our own sweep, 2026-09-16): the OTHER party's export is untrusted input. A missing
    # `envelope_sha256` used to blow up with KeyError in the middle of the comparison — a traceback is not a diagnosis, and a
    # crashed `reconcile` says nothing about whether the log lied. The same principle we applied at the type gate
    # on the conformance-corpus side: a bad shape is a NAMED rejection.
    _ENTRY_SHAPE = {"seq": int, "prev_hash": str, "received_at_ms": int, "envelope_sha256": str,
                    "sender_identity": str, "sender_auth": str, "recipient": str, "kind": str,
                    "decision": str, "reason": str, "entry_hash": str}
    # The NAME dimension (2026-09-16, our own round with the non-Claude arm): the shape gate used to bind the
    # PRESENCE and TYPE of the required fields, not a WHITELIST. Measured: an `operator_note` field added to eight entries gave
    # ok=true, 0 discrepancies — and `entry_hash(e) == entry_hash(e + unknown field)`, because the hash covers the FIXED
    # `ENTRY_KEYS`. I.e. content carried in a hash-CHAINED log that the chain does NOT authenticate.
    # The same holds for the SIGNED `checkpoint` row, on which no shape gate ran until now.
    _CKPT_SHAPE = {"seq": int, "head_hash": str, "ts_ms": int, "notary_pub": str, "sig": str}
    _SHAPES = {"entry": _ENTRY_SHAPE, "checkpoint": _CKPT_SHAPE}
    # What the chain/the signature ACTUALLY covers (every key outside these is unauthenticated)
    _COVERED = {"entry": set(ENTRY_KEYS) | {"cursor", "type", "entry_hash"},
                "checkpoint": {"type", "seq", "head_hash", "ts_ms", "notary_pub", "sig"}}

    def _norm(k):
        """A key name "flattened": lowercase, letters/digits only. `entry_hash ` and `Entry_hash` become the same."""
        return "".join(ch for ch in str(k).lower() if ch.isalnum())

    _unauth, _shadow, _rowtype = [], [], []
    for _r in records:
        if not isinstance(_r, dict):
            _rowtype.append({"type": "malformed_row", "problem": "not an object",
                             "row": repr(_r)[:48]})
            continue
        _ty = _r.get("type")
        # THE ROW'S TYPE is itself a field, and no one bound it until now. My own sweep measured it (2026-09-16):
        #   * `type` DELETED / `null` / `0` on a checkpoint row -> the row stops looking like a checkpoint,
        #     i.e. THE NOTARY'S SIGNED ANCHOR silently disappears from the report, and `ok` stays green;
        #   * `type: []` -> `TypeError` in the type lookup (introduced by exactly this code of mine) — and a
        #     traceback is not a diagnosis.
        # Every row MUST state what it is. An UNKNOWN but well-formed type name, however, may be a row from a
        # newer notary version: not an accusation, just unauthenticated.
        if not isinstance(_ty, str) or not _ty:
            _rowtype.append({"type": "row_type_missing", "seq": repr(_r.get("seq"))[:32],
                             "declared": repr(_ty)[:32],
                             "note": "the row does not say what it is — a row without a type can make the signed anchor "
                                     "disappear from the report"})
            continue
        if _ty not in _COVERED:
            _unauth.append({"type": "unknown_row_type", "row_type": _ty[:32],
                            "seq": repr(_r.get("seq"))[:32]})
            continue
        _ok_names = {_norm(k): k for k in _COVERED[_ty]}
        for _k in _r:
            if _k in _COVERED[_ty]:
                continue
            _n = _norm(_k)
            if _n in _ok_names:
                # A key that differs from a CHAINED key only in case, whitespace or punctuation
                # is not forward compatibility: it is aimed at the reader's eye. It is accusation-grade, so HARD.
                _shadow.append({"type": "shadowing_field", "row_type": _ty, "seq": repr(_r.get("seq"))[:32],
                                "field": repr(_k)[:48], "shadows": _ok_names[_n]})
            else:
                # A genuinely new name: a NEWER notary version may legitimately add a field. The problem is not the field, but
                # that NO ONE said until now that the chain does not cover it. So NAMED, but NOT a verdict:
                # the non-Claude arm's round rightly pointed out that with whitelist rejection an upgraded
                # partner's log would turn red AS A WHOLE, and no one would dare raise a version.
                _unauth.append({"type": "unauthenticated_field", "row_type": _ty,
                                "seq": repr(_r.get("seq"))[:32], "field": repr(_k)[:48]})
    _malformed, _bad_entries = [], []
    for _r in records:                       # no shape gate at all ran on the SIGNED checkpoint row until now
        if _r.get("type") != "checkpoint":
            continue
        for _k, _ty2 in _CKPT_SHAPE.items():
            if _k not in _r:
                _malformed.append({"row_type": "checkpoint", "seq": repr(_r.get("seq"))[:32], "field": _k,
                                   "problem": "missing"})
            elif not isinstance(_r[_k], _ty2) or isinstance(_r[_k], bool):
                _malformed.append({"row_type": "checkpoint", "seq": repr(_r.get("seq"))[:32], "field": _k,
                                   "problem": "not %s" % _ty2.__name__})
    for _e in entries:
        _hit = False
        for _k, _ty in _ENTRY_SHAPE.items():
            if _k not in _e:
                _malformed.append({"seq": repr(_e.get("seq"))[:32], "field": _k, "problem": "missing"})
                _hit = True
            elif not isinstance(_e[_k], _ty) or isinstance(_e[_k], bool):
                _malformed.append({"seq": repr(_e.get("seq"))[:32], "field": _k,
                                   "problem": "not %s" % _ty.__name__})
                _hit = True
        if _hit:
            _bad_entries.append(id(_e))       # by OBJECT, not by the (possibly mistyped) `seq`
    # The non-Claude arm's round ON THIS fix (2026-09-16, accepted): the early `return` turned the shape gate into a
    # "don't look here" button — with deliberate `seq: []` garbage the DEEPER check (signature, backdate, hash chain)
    # NEVER ran, and the answer looked like an innocent formatting error. So from now on BOTH run: we state the
    # malformed entries, AND run `verify` on the rest — the pollution cannot hide a
    # chain break. (We still avoid the traceback: malformed rows are filtered out before verify.)
    if _malformed:
        _clean = [r for r in records if id(r) not in set(_bad_entries)]
        rep = verify(_clean, trusted_pub=trusted_pub)
        _chain = [e for e in rep.get("errors", []) if "chain" in str(e.get("error", ""))
                  or "gap" in str(e.get("error", "")) or "rewritten" in str(e.get("error", ""))]
        return {"ok": False, "verify_ok": False, "verify_partial_ok": rep["ok"],
                "trusted": rep.get("trusted", False),
                "discrepancies": [{"type": "malformed_entry", **m} for m in _malformed[:8]]
                                 + [{"type": "chain_error_behind_the_malformed", **e} for e in _chain[:4]]
                                 + _shadow[:4] + _rowtype[:4],
                "unresolved": [], "unconfirmed_deliveries": [], "notes": _unauth[:8],
                "counts": {"entries": len(entries), "malformed": len(_malformed),
                           "shadowing_fields": len(_shadow), "unauthenticated_fields": len(_unauth),
                           "rows_without_type": len(_rowtype),
                           "verified_without_the_malformed": len(_clean)}}
    rep = verify(records, trusted_pub=trusted_pub)
    mine_in = Counter(e["envelope_sha256"] for e in entries
                      if e.get("sender_identity") == identity and e.get("kind") not in ("ack", "pickup")
                      and not (e.get("decision") == "rejected" and e.get("reason") in ("send_failed", "store_failed")))
    delivered = Counter(e["envelope_sha256"] for e in entries
                        if e.get("kind") == "pickup" and e.get("decision") == "delivered" and e.get("recipient") == identity)
    disc, unresolved = [], []
    strict = is_product() if strict is None else strict
    claimed_rounds = {r["round"] for r in receipts if r.get("phase") == "outcome" and r.get("round") and r.get("peer_claimed_unprocessed")}
    outcomes, outcome_conflicts = {}, []                          # C2: the FIRST outcome line counts (append-only);
    for r in receipts:                                            # a differing second line for a round = a flagged conflict, not a silent overwrite
        if r.get("phase") == "outcome" and r.get("round"):
            if r["round"] not in outcomes:
                o = r.get("outcome")
                # not-sent is RULED OUT only on OSError (a line without rc); a not-sent with rc 255
                # may have come after the request was written -> presumed, treated as unknown in reconcile
                outcomes[r["round"]] = "unknown" if (o == "not-sent" and r.get("rc") is not None) else o
            elif outcomes[r["round"]] != r.get("outcome") and not (r.get("outcome") == "not-sent" and outcomes[r["round"]] == "unknown"):
                outcome_conflicts.append({"type": "outcome_conflict", "round": r["round"],
                                          "first": outcomes[r["round"]], "later": r.get("outcome")})

    def outcome(rc):
        if rc.get("phase") == "outcome":
            return "outcome-row"
        if rc.get("phase") == "request" and rc.get("round"):
            return outcomes.get(rc["round"]) or "unknown"          # the end of the round was not written -> unknown
        return "delivered"                                         # old line without a round id
    rows = [(outcome(rc), rc) for rc in receipts]
    sent = Counter(envelope_hash(m) for o, rc in rows if o in PROVEN_ARRIVED for m in (rc.get("sent") or []))
    for h, n in sent.items():
        if mine_in[h] < n:
            disc.append({"type": "sent_not_logged", "envelope_sha256": h, "sent": n, "logged": mine_in[h]})
    left = Counter({h: max(0, mine_in[h] - sent[h]) for h in mine_in})
    for o, rc in rows:
        if o == "unknown":
            for m in rc.get("sent") or []:
                h = envelope_hash(m)
                if left[h] > 0:
                    left[h] -= 1
                else:
                    unresolved.append({"type": "peer_claimed_unprocessed" if rc.get("round") in claimed_rounds else "sent_outcome_unknown",
                                       "round": rc.get("round"), "envelope_sha256": h})
    got = Counter(envelope_hash(m) for rc in receipts for m in (rc.get("received") or []))
    for h, n in got.items():
        if delivered[h] < n:
            disc.append({"type": "received_not_logged", "envelope_sha256": h, "received": n, "logged": delivered[h]})
    unconfirmed = [{"envelope_sha256": h, "logged": n, "received": got[h]} for h, n in delivered.items() if got[h] < n]
    # TWO-WAY: the log's claims are also measured against the party's receipt — the unsigned `delivered`/`ack`
    # written by the notary is NOT evidence ON ITS OWN, the client's receipt is the party's truth.
    # the three-level model on the DELIVERY side too. If the slice has a round with a PRESUMED outcome
    # (unknown / not-sent: the reply was lost, the party retries, the notary correctly delivers the same again), then
    # surplus delivery is NOT a hard accusation but unresolved. Hard only where every round is closed by a proven outcome.
    # the downgrade must NOT be slice-global, and must not be switchable on by OMITTING an
    # outcome line. Only a RETRIED delivery is softened: an envelope the party ALREADY received ONCE
    # (it is in its receipt), and there is a round with a presumed outcome. What it never received -> hard accusation.
    presumed_round = any(o in ("unknown", "not-sent") for o, rc in rows if o != "outcome-row")
    for u in unconfirmed:
        if presumed_round and got[u["envelope_sha256"]] > 0:
            unresolved.append(dict(u, type="delivery_outcome_unknown"))
        else:
            disc.append(dict(u, type="delivered_not_received"))
    logged_acks = []
    expected = start_cursor
    ack_from = None                                              # the starting cursor of the last accepted ack
    round_open = False                                           # delivered can only stand behind a parseable round entry
    round_seq, round_replies, round_delivered = None, 0, 0
    round_pending, round_max_id, round_next_id, last_round = 0, None, None, None
    round_pending_unknown, round_next_zero_conflict, any_round = False, False, False      # the cursor cannot jump above the remainder of a truncated round

    def flag(item):                                              # at least unresolved, hard in strict/product mode
        (disc if strict else unresolved).append(item)

    def close_round():
        nonlocal last_round
        if round_seq is not None:
            if round_delivered != round_replies:                 # the round's reply count is bound
                item = {"type": "round_replies_mismatch", "seq": round_seq, "replies": round_replies,
                        "delivered": round_delivered}
                if presumed_round:                               # the same root cause: a retried round
                    unresolved.append(dict(item, type="round_replies_outcome_unknown"))
                else:
                    flag(item)
            if round_next_zero_conflict:                          # "nothing undelivered", yet pending > replies -> contradiction
                disc.append({"type": "round_next_id_contradicts_pending", "seq": round_seq,
                             "pending": round_pending, "replies": round_replies})
            r = {"seq": round_seq, "pending": round_pending, "replies": round_replies, "max_id": round_max_id,
                 "next_id": round_next_id, "unknown": round_pending_unknown}
            if last_round is None:                                # rounds do NOT overwrite each other until the ack
                last_round = r
            else:                                                 # the strictest bound stays: the smallest next_id
                last_round = {"seq": last_round["seq"], "pending": last_round["pending"] + r["pending"],
                              "replies": last_round["replies"] + r["replies"],
                              "max_id": max([x for x in (last_round["max_id"], r["max_id"]) if x is not None], default=None),
                              "next_id": min([x for x in (last_round["next_id"], r["next_id"]) if x], default=None),
                              "unknown": last_round["unknown"] or r["unknown"]}

    def _ints(c, keys):                                          # written by the accused -> non-negative int, like record()
        return isinstance(c, dict) and all(isinstance(c.get(k), int) and not isinstance(c.get(k), bool) and c[k] >= 0
                                           for k in keys)

    for e in entries:
        if e.get("recipient") != identity:
            continue
        if e.get("kind") == "ack" and e.get("decision") == "accepted":
            close_round()                                        # the round closes before the ack moves the cursor
            round_open, round_seq = False, None
            c = e.get("cursor")
            if _ints(c, ("from", "to", "ack")):
                frm, to, up = c["from"], c["to"], c["ack"]
            else:
                m = _ACK_RE.match(e.get("reason", ""))
                if not m:                                        # one arm: unparseable = an item, not an omission
                    flag({"type": "unparsable_cursor_entry", "seq": e.get("seq"), "kind": "ack"})
                    close_round(); round_open, round_seq = False, None
                    continue
                frm, to, up = int(m.group(1)), int(m.group(2)), int(m.group(3))
            mr = _ACK_RE.match(e.get("reason", ""))
            if c is not None and mr and (int(mr.group(1)), int(mr.group(2)), int(mr.group(3))) != (frm, to, up):
                disc.append({"type": "cursor_reason_mismatch", "seq": e.get("seq"), "kind": "ack"})   # 
            logged_acks.append(up)
            if to > max(frm, up):                                # the cursor TARGET is bound too
                disc.append({"type": "cursor_target_exceeds_ack", "seq": e["seq"], "cursor_from": frm, "cursor_to": to,
                             "ack": up})
            if frm != expected:
                disc.append({"type": "cursor_moved_without_logged_ack", "seq": e["seq"], "cursor": frm, "expected": expected})
            # for a truncated round (pending > replies) the cursor may go ONLY up to the delivered mail;
            # the remainder stays ABOVE the cursor. If it jumps above it, the undelivered mail is permanently lost.
            if last_round and last_round.get("unknown") and to > frm:   # + measured/missing field -> not silent
                unresolved.append({"type": "round_pending_unknown", "seq": last_round["seq"], "cursor_to": to})
            if not any_round and to > frm:                        # a cursor moving without a round entry — the slice
                unresolved.append({"type": "cursor_moved_without_round", "seq": e["seq"],   # may start with an ack, so not hard
                                   "cursor_from": frm, "cursor_to": to})
            if last_round and last_round["pending"] > last_round["replies"]:
                # the cursor may go ONLY below the first UNDELIVERED message (next_id); for an old entry the delivered maximum is the bound
                limit = (last_round["next_id"] - 1) if last_round.get("next_id") else (
                    last_round["max_id"] if last_round["max_id"] is not None else frm)
                if to > limit:
                    disc.append({"type": "cursor_skips_undelivered", "seq": e["seq"], "round_seq": last_round["seq"],
                                 "cursor_to": to, "limit": limit, "next_undelivered_id": last_round.get("next_id"),
                                 "pending": last_round["pending"], "replies": last_round["replies"]})
            last_round, any_round = None, False
            expected, ack_from = to, frm
        elif e.get("kind") == "ack" and e.get("decision") == "rejected":
            if ack_from is not None:                             # ack_failed / ack_refused: the cursor did NOT move
                expected, ack_from = ack_from, None
            close_round(); round_open, round_seq = False, None
        elif e.get("kind") == "pickup" and e.get("decision") == "accepted":
            c = e.get("cursor")
            close_round()
            if _ints(c, ("at", "replies")):
                at, nrep = c["at"], c["replies"]
                r = _parse_round(e.get("reason", ""))
                if r is not None and r != (at, nrep):
                    disc.append({"type": "cursor_reason_mismatch", "seq": e.get("seq"), "kind": "pickup"})   # 
            else:
                r = _parse_round(e.get("reason", ""))
                if r is None:
                    flag({"type": "unparsable_cursor_entry", "seq": e.get("seq"), "kind": "pickup"})
                    round_open, round_seq = False, None
                    continue
                at, nrep = r
            round_open, round_seq, round_replies, round_delivered = True, e.get("seq"), nrep, 0
            round_pending = c["pending"] if (_ints(c, ("pending",))) else nrep
            round_next_id = c["next_id"] if _ints(c, ("next_id",)) and c["next_id"] > 0 else None
            # a missing field is a THIRD state (not a silent fallback to the old bound)
            # The TRUNCATED measurement (`pending_truncated`) is the same third state as the missing one
            round_pending_unknown = bool(isinstance(c, dict) and (c.get("pending_unknown") or c.get("pending_truncated"))) \
                or not _ints(c, ("pending",)) \
                or (not _ints(c, ("next_id",)) if _ints(c, ("pending", "replies")) and c["pending"] > c["replies"] else False)
            round_next_zero_conflict = bool(_ints(c, ("pending", "replies", "next_id")) and c["pending"] > c["replies"]
                                            and c["next_id"] == 0)
            round_max_id = None
            any_round = True
            if at != expected:
                disc.append({"type": "cursor_moved_without_logged_ack", "seq": e["seq"], "cursor": at, "expected": expected})
                expected = at
        elif e.get("kind") == "pickup" and e.get("decision") == "delivered":
            if not round_open:                                   # omitting the round entry is not silent either
                flag({"type": "delivered_without_round", "seq": e.get("seq")})
            else:
                round_delivered += 1
                cid = e.get("cursor")
                if _ints(cid, ("id",)):
                    round_max_id = cid["id"] if round_max_id is None else max(round_max_id, cid["id"])
    close_round()
    def acks(which):
        return Counter(int(rc["ack"]) for o, rc in rows if o in which and isinstance(rc.get("ack"), int) and rc["ack"] > 0)
    # the ack of a `not-sent` round does NOT cover (the party certainly could not have received it)
    sent_acks, unknown_acks = acks(PROVEN_ARRIVED), acks(("unknown",))
    claimed_acks = Counter(int(rc["ack"]) for o, rc in rows if o == "unknown" and rc.get("round") in claimed_rounds
                           and isinstance(rc.get("ack"), int) and rc["ack"] > 0)
    any_acks = sent_acks                                         # only a PROVEN round covers without silence
    have = Counter(logged_acks)
    for a, n in sent_acks.items():
        if have[a] < n:
            disc.append({"type": "ack_sent_not_logged", "ack": a, "sent": n, "logged": have[a]})
    for a, n in unknown_acks.items():
        if have[a] - sent_acks[a] < n:
            unresolved.append({"type": "ack_outcome_unknown", "ack": a})
    for a, n in have.items():                                    # the reverse direction: a logged ack the party did not send
        if sent_acks[a] >= n:
            continue
        if sent_acks[a] + unknown_acks[a] >= n:                  # presumed cover: neither a hard accusation nor silence
            unresolved.append({"type": "ack_cover_unknown", "ack": a, "logged": n, "proven": sent_acks[a],
                               "claimed": claimed_acks[a] > 0})   # visible if it rests on the accused's word
        else:                                                    # ruled out (OSError not-sent) or nothing: hard accusation
            disc.append({"type": "ack_logged_not_sent", "ack": a, "logged": n, "sent": sent_acks[a]})
    unresolved.extend(outcome_conflicts)
    _cross = _audit_cross(entries, identity, bus_audit, entries_all=records)
    # `soft: True` items are THIRD STATES (not accusations): a missing anchor proves no lie, but is not green either
    disc.extend([d for d in _cross if not d.get("soft") and not d.get("note_only")])
    unresolved.extend([dict(d) for d in _cross if d.get("soft") and not d.get("note_only")])
    # THIRD CHANNEL: stated, but NOT a verdict. The flag's name is deliberately `note_only`, not `note`: the
    # explanatory field of `audit_close_pledge_absent` happened to be `note`, and my filter read the TEXT as the
    # channel flag — I silenced my own item with it. (The same NAME dimension I closed today.)
    _unauth.extend([dict(d) for d in _cross if d.get("note_only")])
    # NAME COLLISION: accusation-grade, so it goes into the verdict (see `_shadow` above).
    disc.extend(_shadow[:4])
    disc.extend(_rowtype[:4])
    # SILENT RED VERDICT (measured 2026-09-16): deleting the `seq` or the SIGNATURE of a `checkpoint` row gave the report
    # `ok=false, verify_ok=false, trusted=false`, but `discrepancies: []` and `errors: null` — a red verdict
    # WITHOUT A NAMED REASON, exactly on the row that carries the notary's signature. `verify()` knew the reason,
    # but `reconcile` dropped it. The verdict does NOT change (`ok` already depended on `rep["ok"]`) — we just
    # SAY WHY from now on.
    if not rep["ok"]:
        disc.extend([{"type": "verify_error", **e} for e in (rep.get("errors") or [])[:6]])
    return {"ok": not disc and rep["ok"] and not (unresolved and strict), "verify_ok": rep["ok"],
            "trusted": rep.get("trusted", False), "discrepancies": disc, "unresolved": unresolved,
            "unconfirmed_deliveries": unconfirmed,
            # UNAUTHENTICATED FIELDS are not a verdict but a REPORT COLUMN: a whitelist rejection would turn an upgraded
            # partner's log red AS A WHOLE (forward compatibility, rolling version upgrades, external
            # correlation ids), and no one would dare raise a version. But it cannot stay silent either: the chain does not cover it.
            "notes": _unauth[:8],
            # The non-Claude arm (3): if EVERY round stays unclosed, the many `soft` items may look like "normal noise". So
            # soft does not stand without a number: the unclosed/committed ratio is a MEASURABLE signal — ~0 in healthy operation, a persistently
            # high value means the closing write is regularly skipped (code swap or persistent interruption).
            "counts": {"entries": len(entries), "sent": sum(sent.values()), "received": sum(got.values()),
                       "acks_sent": sum(any_acks.values()), "delivered_logged": sum(delivered.values()),
                       "unauthenticated_fields": len(_unauth), "shadowing_fields": len(_shadow),
                       "rows_without_type": len(_rowtype),
                       "rounds_pledged": sum(1 for e in entries
                                             if e.get("recipient") == identity and e.get("kind") == "pickup"
                                             and e.get("decision") == "accepted"
                                             and isinstance(e.get("cursor"), dict)
                                             and e["cursor"].get("closes") == 1),
                       "rounds_unclosed": sum(1 for d in _cross if d.get("type") == "audit_close_missing"),
                       # the absence of the COMMITMENT was not visible anywhere in the report until now.
                       "rounds_unpledged": sum(1 for e in entries
                                               if e.get("recipient") == identity and e.get("kind") == "pickup"
                                               and e.get("decision") == "accepted"
                                               and isinstance(e.get("cursor"), dict)
                                               and e["cursor"].get("closes") != 1),
                       "skips_unattributable": sum(1 for d in _cross
                                                   if d.get("type") == "audit_skip_unattributable"),
                       # the non-Claude arm (1)/(2): as individual events the third states look like "noise" —
                       # the NUMBER is what reveals a persistent, deliberate pattern
                       "strict_ack_unknown": sum(1 for d in _cross if d.get("type") == "strict_ack_unknown"),
                       "chain_unverifiable": sum(1 for d in _cross
                                                 if d.get("type") == "audit_chain_unverifiable")}}


def _pub_misuse(pub, cmd) -> bool:
    """--pub is the key's VALUE (64 hex), not a file path — otherwise a silent verify_ok:false."""
    if pub and not re.fullmatch(r"[0-9a-f]{64}", pub):
        print("bus_notary %s: --pub is the VALUE of the notary's public key (64 hex characters), not a file path: %r" % (cmd, pub),
              file=sys.stderr)
        return True
    return False


# ── CLI ──────────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bus_notary", description="AgentBus notary log")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export"); e.add_argument("--log", default=None); e.add_argument("--from", dest="from_seq", type=int, default=1)
    v = sub.add_parser("verify"); v.add_argument("file"); v.add_argument("--pub"); v.add_argument("--window", type=int, default=DEFAULT_BACKDATE_WINDOW_S)
    v.add_argument("--start-prev-hash", dest="start_prev_hash", default=None,
                   help="the slice's first entry must chain to this (the previous slice's head.hash) — fork check")
    c = sub.add_parser("compare"); c.add_argument("a"); c.add_argument("b")
    k = sub.add_parser("checkpoint"); k.add_argument("--log", default=None); k.add_argument("--key", required=True)
    g = sub.add_parser("keygen"); g.add_argument("--out", required=True)
    r = sub.add_parser("reconcile", help="the remote party's receipt list (JSONL, per round sent/ack/received) vs. an export")
    r.add_argument("--bus-audit", help="the bus's cursor_audit export (JSONL, agent_bus.audit_export) — the log's SELF-REPORTED "
                                       "pending/next_id numbers are compared against it")
    r.add_argument("file"); r.add_argument("--identity", required=True); r.add_argument("--receipts", required=True)
    r.add_argument("--pub"); r.add_argument("--start-cursor", dest="start_cursor", type=int, default=0)
    r.add_argument("--bus-audit-anchor", dest="bus_audit_anchor", default=None,
                   help="anchor of a --bus-audit partial slice: the preceding audit row's row_hash (known out of band)")
    r.add_argument("--strict", action="store_true", help="rc=1 for delivered_not_received in dev mode too (always in product mode)")
    args = p.parse_args(argv)
    if args.cmd == "export":
        # From a NIT, `export` used to give rc=0 for EVERY broken log, with empty output —
        # they did not rate it a finding ("a transformation, not a verdict"), but OUR OWN rule applies:
        # no entry point may say rc=0 for a broken file. The consequence is concrete: an all-garbage
        # log becomes an EMPTY export, which on the other machine reads as "0 entries" — and whoever receives it cannot tell
        # the source was garbage. Our own class sentinel (`test_belepo_pont_osztaly_20260916.py`) caught it,
        # after it actually ran the sub-commands following the NIT.
        _src = read_lines(args.log or default_log_path())
        _garbage = [r for r in _src if isinstance(r, dict) and r.get("type") == "garbage"]
        if _reject_no_evidence(_src, "export"):
            return 1
        if _garbage:
            print("bus_notary export: REJECT — the SOURCE log contains %d unparseable line(s) (first: line %s). "
                  "A slice silently made from such a log would look clean on the other machine."
                  % (len(_garbage), _garbage[0].get("line")), file=sys.stderr)
            return 1
        recs = export(args.log or default_log_path(), args.from_seq)
        first = next((r for r in recs if r.get("type") == "entry"), None)
        if first is not None:                                   # for chaining: the next slice binds to this
            print("bus_notary export: from_seq=%s prev_hash=%s (for chaining: verify --start-prev-hash %s)"
                  % (first.get("seq"), first.get("prev_hash"), first.get("prev_hash")), file=sys.stderr)
        for r in recs:
            print(json.dumps(r, sort_keys=True, ensure_ascii=False))
        return 0
    if args.cmd == "verify":
        if _pub_misuse(args.pub, "verify"):
            return 2
        if not args.pub:
            if is_product():
                print("bus_notary verify: product mode — --pub (the notary key fixed out of band) is required",
                      file=sys.stderr)
                return 2
            print("bus_notary verify: WARNING — without --pub the signing key is NOT checked; a made-up chain signed "
                  "with a key anyone generated is also ok:true. So the report's `trusted` field is false.",
                  file=sys.stderr)
        _recs = read_lines(args.file)
        # Rejecting the EMPTY log. For an empty file `verify` once gave rc=0: the emptiest possible
        # input got a GREEN certificate. Zero entries hold no lie, but no evidence either — the ABSENCE of
        # measurement is not green. (The same class as the missing anchor and the missing second record,
        # just at the earliest point.) An earlier, narrower version of the fix sat here for a long time behind an always-false branch,
        # as dead code: this broader guard worked in its place, but whoever AUDITS the source saw a disabled
        # security block in a security-critical file. For a source-available product that is
        # a finding in itself, so the dead branch was deleted and its explanation moved here, next to the LIVE guard.
        if _reject_no_evidence(_recs, "verify"):
            return 1
        rep = verify(_recs, trusted_pub=args.pub, backdate_window_s=args.window,
                     start_prev_hash=args.start_prev_hash)
        print(json.dumps(rep, ensure_ascii=False, indent=1))
        if rep["ok"] and not rep["anchored"]:
            msg = ("the slice starts at entry %s, WITHOUT an anchor — the absence of the entries before it does not show "
                   "in the slice. Give the --start-prev-hash value known out of band, or export from seq=1."
                   % rep["slice_start_seq"])
            if is_product():
                print("bus_notary verify: product mode — megtagadva: " + msg, file=sys.stderr)
                return 3
            print("bus_notary verify: WARNING — " + msg + " So the report's `trusted` field is false.", file=sys.stderr)
        if args.pub and rep["ok"] and rep["no_checkpoint_in_range"]:
            msg = ("the slice has NO checkpoint verified with the trusted key — only the hash chain is consistent, "
                   "no signature covers it (%d entries). Wait for the next checkpoint, or export from an earlier seq."
                   % rep["unverified_tail"])
            if is_product():
                print("bus_notary verify: product mode — megtagadva: " + msg, file=sys.stderr)
                return 3
            print("bus_notary verify: WARNING — " + msg + " So the report's `trusted` field is false.", file=sys.stderr)
        elif rep["ok"] and rep["unverified_tail"]:
            msg = ("after the last verified checkpoint (seq %s) the %d entries are bound only by the hash chain, not by a signature "
                   "— the slice is NOT trusted (trusted:false). Wait for the next checkpoint, or make one "
                   "(bus_notary checkpoint), and export again." % (rep["covered_to_seq"], rep["unverified_tail"]))
            if args.pub and is_product():                       # round closing in product mode regardless of its size
                print("bus_notary verify: product mode — refused: " + msg, file=sys.stderr)
                return 3
            print("bus_notary verify: WARNING — " + msg, file=sys.stderr)
        if rep["ack_target_violations"]:
            print("bus_notary verify: %d ack entr(y/ies) with a cursor target greater than max(starting cursor, ack) — the honest "
                  "clamp cannot write this (false cursor target, swallowed mail)" % len(rep["ack_target_violations"]), file=sys.stderr)
            return 1
        return 0 if rep["ok"] else 1
    if args.cmd == "compare":
        rep = compare(read_lines(args.a), read_lines(args.b))
        print(json.dumps(rep))
        if rep["same"] is None:                                 # nothing to compare ≠ fine
            print("bus_notary compare: the two exports have NO comparable point (no shared seq, no checkpoint, no "
                  "adjacent chain link) — this is not a match. Export an overlapping range.", file=sys.stderr)
            return 3
        return 0 if rep["same"] else 1
    if args.cmd == "checkpoint":
        n = Notary(args.log or default_log_path(), seed=load_seed(args.key))
        print(json.dumps(n.checkpoint(), sort_keys=True))
        return 0
    if args.cmd == "reconcile":
        # the sibling sub-command had NO such rejection — although it is exactly the one
        # that compares against the SECOND RECORD, so the v1.5 promise rests on it.
        #
        # BUT: taken over in the shape of `verify`, this fails our own `test_unknown_outcome_is_unresolved_not_an_
        # accusation` control — the one that binds THEIR CLASS (unknown outcome = third state,
        # not an accusation). There the log is empty, but the receipt claims `outcome: unknown`, and the correct answer
        # is EXACTLY the soft `sent_outcome_unknown`, rc=0 in dev mode. So `reconcile` is not the same case
        # as `verify`: there the log is THE ONLY evidence, here the receipt is the other side.
        # So: REJECTION in strict/product mode (their request), NAMED on the third channel in dev mode.
        # I raise the contract question in the PR, I do not decide it unilaterally.
        _rec_src = read_lines(args.file)
        _rec_garbage = [r for r in _rec_src if isinstance(r, dict) and r.get("type") == "garbage"]
        if _rec_garbage:
            # A BROKEN FILE and an EMPTY FILE are two different cases: the first is a fault of the other party's export,
            # and it gets a named rejection in every mode.
            print("bus_notary reconcile: REJECT — the log contains %d unparseable line(s) (first: line %s)."
                  % (len(_rec_garbage), _rec_garbage[0].get("line")), file=sys.stderr)
            return 1
        _rec_empty, _rec_ne, _rec_nc = _no_evidence(_rec_src)
        if _rec_empty:
            _strict_mode = bool(getattr(args, "strict", False)) or is_product()
            if _strict_mode:
                _reject_no_evidence(_rec_src, "reconcile")
                return 1
            print("bus_notary reconcile: STATED (not an accusation, not a green tick) — the log contains %d record(s), "
                  "but 0 entries and 0 checkpoints: the comparison rests on the ONE-SIDED claims of the receipts. "
                  "In strict/product mode this is rc=1." % len(_rec_src), file=sys.stderr)
        rcpts = [x for x in read_lines(args.receipts) if x.get("type") != "garbage"]
        if _pub_misuse(args.pub, "reconcile"):
            return 2
        audit = read_lines(args.bus_audit) if getattr(args, "bus_audit", None) else None
        if audit is not None:                                  # the bus's own hash-chained log: SELF-CHECK first
            try:
                import agent_bus as _ab
                chk = _ab.audit_chain_verify(audit, start_row_hash=getattr(args, "bus_audit_anchor", None))
            except Exception as e:
                chk = {"ok": False, "errors": [{"error": str(e)[:120]}]}
            if not chk["ok"]:
                print(json.dumps({"bus_audit_chain": chk}, ensure_ascii=False, indent=1))
                print("bus_notary reconcile: the bus audit chain is DAMAGED — the comparison is not trustworthy", file=sys.stderr)
                return 1
            # an UNANCHORED export (not starting from genesis, passed without an anchor)
            # may be internally intact, yet it is not a claim about the full chain — the same shape as for the log slice.
            if not chk.get("anchored"):
                msg = ("the bus audit export starts at row %s, WITHOUT an anchor — the absence of the rows before it "
                       "does not show in it. Full chain: `agent_bus.py audit-export --agent <agent>` (--from-seq 0), "
                       "or give the --bus-audit-anchor <row_hash> value." % chk.get("slice_start_seq"))
                if bool(args.strict or is_product()):
                    print("bus_notary reconcile: REFUSED — " + msg, file=sys.stderr)
                    return 1
                print("bus_notary reconcile: WARNING — " + msg, file=sys.stderr)
        strict = bool(args.strict or is_product())
        entries = read_lines(args.file)                    # 8/4: we read ONCE (a file swapped between two
        rep = reconcile(entries, args.identity, rcpts, start_cursor=args.start_cursor, trusted_pub=args.pub,
                        strict=strict, bus_audit=audit)    # reads would give a desynced rc)
        print(json.dumps(rep, ensure_ascii=False, indent=1))
        # The stated limit of ClampLiedFields turned into POLICY: the round entry's `pending`/`next_id` field is the accused's
        # self-report. A round is NOT accused just because the other record is not beside it (that would be a false accusation) —
        # but in strict/product mode the CLI gives no GREEN light without the bus's own hash-chained log: incomplete evidence.
        if strict and not audit and any(
                e.get("recipient") == args.identity and e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict)
                and any(k in e["cursor"] for k in ("pending", "next_id")) for e in entries):
            print("bus_notary reconcile: INCOMPLETE EVIDENCE — the slice contains self-reported cursor numbers (pending/next_id) "
                  "without the bus's own audit export. In product mode this is not green: give "
                  "--bus-audit <file> (agent_bus.py audit-export <agent>).", file=sys.stderr)
            return 1
        if rep["ok"] and not rep["trusted"]:
            print("bus_notary reconcile: WARNING — no discrepancy, but the slice is not trusted (trusted:false; without --pub "
                  "or with an unverified tail)", file=sys.stderr)
        hard = [d for d in rep["discrepancies"] if d["type"] != "delivered_not_received"]
        soft = len(rep["discrepancies"]) - len(hard) + len(rep["unresolved"])
        # The non-Claude arm's round on the THIRD CHANNEL (2026-09-16), and they are right about what matters: a signal
        # that changes no verdict is only worth something if it reaches a HUMAN. The consumer (CI, monitor)
        # filters on `ok`, and `notes` stays deep in the JSON — "silent green under another name". The same rule
        # one arm stated this morning about `state_dir_warnings()`: a verdict no one asks for
        # is not a signal. So on the command line the NOTES go to the OPERATOR (stderr), even when rc=0.
        for _n in (rep.get("notes") or [])[:8]:
            print("bus_notary reconcile: STATED (not an accusation, not a green tick) — %s: %s"
                  % (_n.get("type"), _n.get("why") or _n.get("note") or ""), file=sys.stderr)
        if hard or not rep["verify_ok"]:
            return 1
        if soft:
            if args.strict or is_product():
                return 1
            print("bus_notary reconcile: WARNING — %d item(s) cannot be decided (delivered_not_received / unresolved: the round's "
                  "outcome is unknown). In product mode or with --strict rc=1." % soft, file=sys.stderr)
        return 0
    if args.cmd == "keygen":
        seed, pub = keypair()
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(seed.hex())
        print(pub)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
