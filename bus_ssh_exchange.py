#!/usr/bin/env python3
"""bus_ssh_exchange — SSH TRANSPORT between machines: the force-command endpoint of the RECEIVING machine (v1.2).

Model (the July SSH bridge, generalized): the remote agent SSHes OUTWARD to the bus machine (client-initiated,
through NAT, NO port opened on the remote machine). SSH provides encryption + client-key authentication; on the bus machine
the authorized_keys line is `command="… bus_ssh_exchange.py <identity>",restrict,…` → this script runs, NOTHING ELSE
(no shell, pty, port forward). See bus_ssh_enroll.py.

One SSH call = one atomic exchange round (stdin JSON → stdout JSON):

    in:  {"ack": <last stored reply id | 0>,
          "messages": [{"to", "body", "topic"?, "kind"?, "thread_id"?, "in_reply_to"?}, …],
          "attachments": [{"descriptor": {…}, "chunks": [{"sha256","seq","last","data"}, …]}, …]}
    out: {"identity", "protocol", "accepted": [bus-id…], "rejected": [{"index", "reason"}…],
          "attachments": [{"sha256", "status": "stored|partial|rejected", "reason"?}…],
          "replies": [{"id","ts","sender","topic","kind","thread_id","in_reply_to","body","sds"?}…]}

Security boundary:
- **The identity comes from the force-command ARGUMENT** (bound to the key), NEVER from the payload: the
  `from`/`sender` fields are ignored (anti-spoof).
- **Size ceilings:** the whole stdin ≤ MAX_BYTES; messages/round ≤ MAX_MESSAGES; the body gets the bus's own 64 KB cap.
- **sds-envelope passes:** the bus `send` checks the frame; the envelope's SIGNATURE is checked on the receiving side by the v1.1
  `recv --verify-sds` path — the `sds` field in the replies gives this label.
- **This endpoint does NOT sign the bus row** with the bus machine's key (AUTO-SIGN off): the remote sender's authenticity comes from
  the SSH key, the content's from the sds-envelope's own signature.
- **v1.5.2 — client-signed row:** a message may carry `ts`/`sig`/`pubkey` (with the sender's OWN Ed25519 key, in the bus's
  `sign_for_send` shape); the endpoint checks it against the registry key and stores exactly that → the recipient
  sees it as `signed` in product mode. A bare row under a name PINNED in the registry in product mode: `rejected` with a reason
  (`unsigned-pinned`) — it is not stored only to be silently dropped on read.
- **At-least-once delivery:** replies go out with PEEK; the cursor steps only on the client's `ack` in the NEXT
  round (if SSH breaks, nothing is lost). stdlib-only."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAX_BYTES = int(os.environ.get("AGENT_BUS_SSH_MAX_BYTES", str(4 * 1024 * 1024)))
MAX_MESSAGES = 200
MAX_REPLIES = 200
# DOWNLOAD (fetch) ceilings: one exchange round returns this many attachment bytes; a larger one must be requested in a separate,
# dedicated round. The download comes from the content-addressed store (the sha256 is the capability: whoever received the
# descriptor in a message addressed to them can pull it). The env can only NARROW (as with bus_enforce).
MAX_FETCH_ITEMS = 32
MAX_FETCH_BYTES = min(4 * 1024 * 1024, int(os.environ.get("AGENT_BUS_SSH_FETCH_MAX_BYTES", str(4 * 1024 * 1024))))
_REPLY_KEYS = ("id", "ts", "sender", "topic", "kind", "thread_id", "in_reply_to", "body", "sds")


_FROM_ENV = object()


def exchange(identity: str, raw: bytes | str, *, db=None, attach_root=None, notary=_FROM_ENV) -> dict:
    try:
        return _exchange(identity, raw, db=db, attach_root=attach_root, notary=notary)
    except _NotaryWriteFailed as e:                            # fail-closed: the remaining items do not go through, no traceback
        return dict(e.args[0], error="notary write failed (fail-closed)")


class _NotaryWriteFailed(Exception):
    pass


def _exchange(identity, raw, *, db, attach_root, notary):
    import agent_bus as ab
    import bus_attach
    import bus_notary

    if notary is _FROM_ENV:                                    # v1.5: notary log — mandatory in product mode (fail-closed)
        try:
            notary = bus_notary.Notary.from_env(db=db)
        except (bus_notary.NotaryError, OSError, ValueError):
            return {"identity": identity, "error": "notary unavailable (fail-closed)", "processed": False}

    def note(**kw):                                            # only hash + metadata; the plaintext body never enters the log
        # raises → _NotaryWriteFailed; the call sites call it BEFORE the side effect (send / store write / ack / delivery)
        if notary is not None:
            try:
                e = notary.record(sender_identity=identity, sender_auth="ssh-key", **kw)
            except Exception:
                raise _NotaryWriteFailed(out)
            if isinstance(e, dict) and "seq" in e:             # log anchor in the response: the round's last entry
                out["notary"] = {"seq": e["seq"], "head_hash": e["entry_hash"]}

    # (2026-09-17): AGENT_BUS_AUTO_SIGN=0 used to be set here PROCESS-GLOBALLY, and never restored. In the force-command's
    # short-lived process this was invisible; in a longer-lived caller (the CI sweep_log_probe sentinel calls it in the same
    # process) every LATER send also stayed unsigned, which product mode dropped. The principle stays — the
    # bus machine's key does NOT sign the remote party's message —, but PER CALL: `ab.send(..., sign_key=False)` also disables auto-sign
    # for that one row, and touches no other process state.
    if isinstance(raw, bytes):
        if len(raw) > MAX_BYTES:
            return {"identity": identity, "error": "oversize", "processed": False}
        raw = raw.decode("utf-8", "replace")
    elif len(raw.encode("utf-8", "surrogatepass")) > MAX_BYTES:
        return {"identity": identity, "error": "oversize", "processed": False}
    out = {"identity": identity, "protocol": ab.PROTOCOL_VERSION, "accepted": [], "rejected": [],
           "attachments": [], "fetched": [], "replies": []}
    payload = {}
    if raw.strip():
        try:
            payload = json.loads(raw)
        except ValueError:
            return dict(out, error="payload is not JSON")
        if not isinstance(payload, dict):
            return dict(out, error="payload must be a JSON object")
    msgs = payload.get("messages") or []
    if not isinstance(msgs, list) or len(msgs) > MAX_MESSAGES:
        return dict(out, error="messages must be a list of at most %d" % MAX_MESSAGES)

    ack_to = payload.get("ack")
    if isinstance(ack_to, int) and not isinstance(ack_to, bool) and ack_to > 0:
        # OUTBOUND DIRECTION, LOG-FIRST: the ack permanently consumes the mail (forward-only
        # cursor), so the cursor's old->new value goes into the log BEFORE the move; a log error -> no cursor move.
        base, tgt = ab.ack_preview(identity, ack_to, db=db)
        note(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, recipient=identity, kind="ack",
             decision="accepted", reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to),
             cursor={"from": base, "to": tgt, "ack": ack_to})
        try:
            ab.ack(identity, ack_to, db=db)                    # ack is forward-only and clamps to real messages (the bus's rule)
        except Exception:                                      # noqa: BLE001 — the cursor did not move: a correcting entry
            note(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, recipient=identity, kind="ack",
                 decision="rejected", reason="ack_failed")

    for i, m in enumerate(msgs):
        if not isinstance(m, dict) or not isinstance(m.get("to"), str) or not isinstance(m.get("body"), str):
            out["rejected"].append({"index": i, "reason": "message needs string 'to' and 'body'"})
            note(envelope=m, recipient=(m.get("to") if isinstance(m, dict) else ""), kind="msg", decision="rejected",
                 reason="malformed")
            continue
        claimed = bus_notary.claimed_ts_of(m)
        # THE INBOUND PATH DOES NOT NORMALIZE ON ITS OWN. It used to say `m.get("kind","msg") or "msg"` here,
        # which turned an omitted, an EMPTY and a `null` kind into `"msg"` — while the signed byte image
        # counts all three as `""`. So a row from a partner signing per spec failed with `presigned: signature
        # does not verify (forged or tampered)`: not a silent rejection but a FORGERY ACCUSATION.
        kind = ab.canonical_text_field(m.get("kind"))
        # LOG-FIRST: the fact of receipt goes into the log BEFORE the bus insert. If the log write
        # raises, ab.send is never called (true fail-closed, no unlogged copy on resend either). If send raises
        # after logging, a second, rejected entry corrects it: over-logging is allowed, under-logging is not.
        # v1.5.2 (2026-09-21): a CLIENT-SIGNED row. The remote party signed it with ITS OWN key (`sig`/`pubkey`/`ts` on the
        # message), the bus machine checks it against the registry and stores EXACTLY that — so the recipient's product-mode
        # read sees it as `signed`. A bare row under a PINNED name in product mode: the reader would drop it anyway
        # (`unsigned-pinned`), so we reject it HERE, WITH A REASON, so the sender sees it (09-19..21: 25+7064 rows vanished silently).
        presigned = None
        if m.get("sig") is not None or m.get("pubkey") is not None:
            presigned = {"ts": m.get("ts"), "sig": m.get("sig"), "pubkey": m.get("pubkey")}
        elif ab._is_product(db) and ab._a2_load_registry_pubkey(identity, ab.KEYS_DIR) is not None:
            reason = "unsigned-pinned: '%s' has a registry key; sign client-side (keys/%s.ed25519.key)" % (identity, identity)
            out["rejected"].append({"index": i, "reason": reason})
            note(envelope=m, recipient=m["to"], kind=kind, decision="rejected", reason="unsigned-pinned",
                 claimed_ts=claimed)
            continue
        note(envelope=m, recipient=m["to"], kind=kind, decision="accepted", claimed_ts=claimed)
        try:                                                   # ANTI-SPOOF: the sender is ALWAYS the pinned identity
            rid = ab.send(identity, m["to"], m["body"], topic=ab.canonical_text_field(m.get("topic")),
                          kind=kind, thread_id=m.get("thread_id"),
                          in_reply_to=m.get("in_reply_to"), db=db, sign_key=False,   # False = NO auto-sign either
                          presigned=presigned)
        except Exception as e:                                 # noqa: BLE001 — any send error: not delivered, and that shows
            out["rejected"].append({"index": i, "reason": str(e)[:200]})
            note(envelope=m, recipient=m["to"], kind=kind, decision="rejected", reason="send_failed",
                 claimed_ts=claimed)
            continue
        out["accepted"].append(rid)

    store = bus_attach.Store(attach_root)
    for a in payload.get("attachments") or []:
        desc = (a or {}).get("descriptor") if isinstance(a, dict) else None
        sha = desc.get("sha256") if isinstance(desc, dict) else None
        env = desc if isinstance(desc, dict) else {}
        try:                                                   # a purely formal check, does not touch the store yet
            bus_attach.check_descriptor(desc)
            chunks = a.get("chunks") or []
            if not isinstance(chunks, list):
                raise TypeError("chunks must be a list")
        except (bus_attach.AttachmentError, AttributeError, TypeError) as e:
            out["attachments"].append({"sha256": sha, "status": "rejected", "reason": str(e)[:200]})
            note(envelope=env, recipient="", kind="attachment", decision="rejected", reason=str(e)[:200])
            continue
        # LOG-FIRST on the attachment branch too: writing to the store (partial or complete) happens only after the entry.
        note(envelope=env, recipient="", kind="attachment", decision="accepted", reason="received")
        try:
            done = None
            for ch in chunks:
                done = store.receive_chunk(desc, ch)
        except Exception as e:                                 # noqa: BLE001 — not stored: a second, correcting entry
            out["attachments"].append({"sha256": sha, "status": "rejected", "reason": str(e)[:200]})
            note(envelope=env, recipient="", kind="attachment", decision="rejected", reason="store_failed")
            continue
        out["attachments"].append({"sha256": sha, "status": "stored" if done else "partial"})

    # DOWNLOAD (fetch): the client requests descriptors, we return the chunks from the content-addressed store.
    # This is the missing receiving side + the download direction of "the bus also carries packages". get() checks byte-exactly
    # (size+sha256, fail-closed). Per-round ceiling: MAX_FETCH_ITEMS items and MAX_FETCH_BYTES total bytes; a large one in a separate round.
    fetched_bytes = 0
    for desc in (payload.get("fetch") or [])[:MAX_FETCH_ITEMS]:
        sha = desc.get("sha256") if isinstance(desc, dict) else None
        env = desc if isinstance(desc, dict) else {}
        try:
            bus_attach.check_descriptor(desc)                  # purely structural
        except (bus_attach.AttachmentError, AttributeError, TypeError) as e:
            out["fetched"].append({"sha256": sha, "status": "rejected", "reason": str(e)[:200]})
            note(envelope=env, recipient=identity, kind="fetch", decision="rejected", reason=str(e)[:200])
            continue
        size = desc.get("size") if isinstance(desc.get("size"), int) else 0
        if fetched_bytes + size > MAX_FETCH_BYTES:             # a large one must be requested in a dedicated round (not silent truncation)
            out["fetched"].append({"sha256": sha, "status": "deferred", "reason": "round-fetch-budget"})
            note(envelope=env, recipient=identity, kind="fetch", decision="rejected", reason="round-budget")
            continue
        note(envelope=env, recipient=identity, kind="fetch", decision="accepted", reason="requested")
        try:
            chunks = list(store.chunks(desc))                  # get() checks byte-exactly (size+sha256) -> not stored = AttachmentError
        except bus_attach.AttachmentError as e:                # not in the store / differs -> not found (fail-closed)
            out["fetched"].append({"sha256": sha, "status": "not-found", "reason": str(e)[:200]})
            note(envelope=env, recipient=identity, kind="fetch", decision="rejected", reason="not-found")
            continue
        fetched_bytes += size
        out["fetched"].append({"sha256": sha, "descriptor": desc, "chunks": chunks, "status": "delivered"})

    rows = ab.recv(identity, mark=False, limit=MAX_REPLIES, db=db, verify_sds=True)
    _PEND_LIMIT = MAX_REPLIES * 50
    try:        # the number AWAITING DELIVERY and the first UNDELIVERED id also go into the evidence
        pend_rows = ab.recv(identity, mark=False, limit=_PEND_LIMIT + 1, db=db, verify_sds=True)   # +1 = truncation detector
        pend_ok = True
    except Exception:
        pend_rows, pend_ok = rows, False          # the ABSENCE of measurement must be stated, not look like a "clean round"
    # No one read the +1 detector until now — a measurement hitting the limit is TRUNCATED, and a
    # truncated `pending` would have looked like a "clean round". Truncation is the same third state as missing measurement.
    pend_truncated = pend_ok and len(pend_rows) > _PEND_LIMIT
    pending = len(pend_rows)
    given_ids = {r.get("id") for r in rows}
    left_ids = [r.get("id") for r in pend_rows if r.get("id") not in given_ids and isinstance(r.get("id"), int)]
    next_id = min(left_ids) if left_ids else 0        # 0 = nothing undelivered: the cursor may go freely up to the delivered ones
    replies = [{k: r.get(k) for k in _REPLY_KEYS if k in r} for r in rows]
    # OUTBOUND DIRECTION, LOG-FIRST: before delivery (1) a round entry with the cursor — if there is a delivered reply, OR the cursor
    # differs from the last logged round's (so a cursor advanced without logging on the bus machine shows in the next round),
    # and (2) one `delivered` entry per reply; envelope_sha256 is the JCS hash of the delivered dict, the remote party
    # recomputes it (bus_notary reconcile). Any log error -> the replies do NOT go out.
    if notary is not None:
        cur = ab.cursor_of(identity, db=db)
        # the round entry COMMITS ITSELF to the head of the bus's audit chain —
        # so at comparison time it can be stated how far the OTHER record's export must reach. `audit_head()`
        # was made exactly for this, and until now had no caller: it was dead code, now it is a live anchor.
        # The anchor (audit_seq/audit_hash) and the `closes` commitment are written in by the NOTARY (bus_notary.record):
        # the writer's word cannot be the evidence about itself. Only the strict-ack state travels here.
        _anchor = {}
        # 2026-09-16: the strict ack clamp is the default IN PRODUCT MODE. Using the escape hatch
        # (AGENT_BUS_STRICT_ACK=0) must NOT be silent — the round entry states that it is off.
        try:
            _sa_active, _sa_off = ab.strict_ack_state(db)
            if _sa_off:
                _anchor = dict(_anchor, strict_ack=0)
        except Exception:
            # (measured): this was the ONLY mechanism that writes into the round entry
            # that the clamp's escape hatch was open — and with `pass` the fact was SILENTLY lost, and the round
            # became indistinguishable from a STRICT round. Our own comment above it said
            # "the escape hatch must NOT be silent". Missing measurement is a third state, just like `pending_unknown`.
            _anchor = dict(_anchor, strict_ack_unknown=1)
        _round_logged = bool(replies) or cur != notary.last_round_cursor(identity)
        _round_seq = None
        if _round_logged:
            note(envelope={"identity": identity, "cursor": cur,
                           "reply_sha256": [bus_notary.envelope_hash(x) for x in replies]},
                 recipient=identity, kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(replies)),
                 # The `closes: 1` commitment is written in by the NOTARY (bus_notary.record) — the writer cannot omit it.
                 cursor=(dict({"at": cur, "replies": len(replies), "pending": pending, "next_id": next_id},
                              **({"pending_truncated": 1} if pend_truncated else {}), **_anchor) if pend_ok
                         else dict({"at": cur, "replies": len(replies), "pending_unknown": 1}, **_anchor)))
            _round_seq = (out.get("notary") or {}).get("seq")      # the opening entry's seq: the close NAMES this
        for x in replies:
            rid = x.get("id")
            note(envelope=x, recipient=identity, kind="pickup", decision="delivered", reason="id=%s" % rid,
                 cursor=({"id": int(rid)} if isinstance(rid, int) and not isinstance(rid, bool) and rid >= 0 else None))
    if replies:                                                # the delivered mail is DELIVERED (the cursor does not move)
        try:
            ab.mark_delivered(identity, [x.get("id") for x in replies], db=db)
        except Exception as e:                                 # a write error is NOT silent (as on the ack branch)
            note(envelope={"identity": identity, "mark_delivered": "failed"}, recipient=identity, kind="pickup",
                 decision="rejected", reason="mark_delivered_failed: %s" % str(e)[:120])
            # A: if the signal cannot be written EITHER, _NotaryWriteFailed propagates -> a FAIL-CLOSED response,
            # the mail does NOT go out (the client asks for it again in the next round). No silent double failure may remain.
    # ATTACK MATRIX 2.7 (open row, now closed): the round's OPENING anchor is written at the START of the round, so it does not bind
    # the round's own ack/delivery rows — on a single-round slice the bus audit chain could be consistently re-chained.
    # The CLOSING entry goes out after EVERY side effect, and the NOTARY computes the anchor into it.
    # Fail-open STATED: it can no longer be fail-closed here (the mail is delivered, `mark_delivered` happened) — if the
    # closing write fails, (a) the response's `round_close: "failed"` field states it to the remote party, (b)
    # reconcile sees it as the soft discrepancy `audit_round_unclosed`. It does not stay silent.
    # …and ONLY if there was an OPENING round entry: the closing anchor pairs with it, it is not standalone noise.
    if notary is not None and locals().get("_round_logged"):
        try:
            note(envelope={"identity": identity, "round_close": 1, "cursor": ab.cursor_of(identity, db=db)},
                 recipient=identity, kind="round_close", decision="accepted",
                 reason="close replies=%d" % len(replies),
                 # `round_seq`: the close NAMES which round it closes (the non-Claude arm's round: with mere order
                 # a close from elsewhere could make an unclosed round look "closed"). If the writer
                 # lies about it, the pairing does not form -> a missing close, not a false green.
                 cursor=dict({"at": ab.cursor_of(identity, db=db), "replies": len(replies)},
                             **({"round_seq": int(_round_seq)} if isinstance(_round_seq, int) else {})))
        except Exception:
            out["round_close"] = "failed"
    out["replies"] = replies
    return out


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    import agent_bus as ab
    identity = argv[0] if argv else ""
    if not identity or ab._safe_name(identity) != identity:   # the identity comes from the force-command and is filename-safe
        print(json.dumps({"error": "no or unsafe identity (must come from the force-command argument)", "processed": False}))
        return 2
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    res = exchange(identity, raw)
    print(json.dumps(res, ensure_ascii=False))
    return 2 if "error" in res else 0


if __name__ == "__main__":
    sys.exit(main())
