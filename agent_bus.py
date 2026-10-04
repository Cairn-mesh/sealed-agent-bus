#!/usr/bin/env python3
"""agent_bus — AgentBus P0: append-only, ordered, audited message bus between agents (SQLite WAL).

The transport layer for the file-inbox late-delivery problem (see docs/architecture/AGENT_BUS_DESIGN.md).
ONE `bus.db` (WAL): ordered (monotonic id), atomic, searchable — the 'chat' = messages after your own cursor.
NO DELETION: never DELETE; 'read' = read_at; the cursor marks where the agent is. ADDITIVE: `send`
ALSO mirrors into the old JSON inbox (back-compat, until every agent migrates). Stdlib-only, self-contained, never-throw on the CLI.

CLI:
  agent_bus.py init
  agent_bus.py send --from X --to Y --topic T --kind K [--thread TID] [--reply ID] [--sign-key PATH] --body "..."
  agent_bus.py recv --agent X [--mark] [--verify-sds [--strict-sds] [--sds-admission PATH]]
                                                  # unread (id>cursor); --mark: advance cursor + read_at
                                                  # v1.1: check sds-envelope rows (valid|invalid|unsigned|unverifiable)
  agent_bus.py tail --agent X [--limit N]        # latest messages (to or from it)
  agent_bus.py thread --id TID                    # one thread in time order
  agent_bus.py ack --agent X --upto ID           # advance cursor (mark read up to ID)
  agent_bus.py verify [--json]                    # divergence guard: does the DB match the frozen schema
"""
from __future__ import annotations
import argparse, hashlib, json, os, sqlite3, stat, sys, time

BRIDGE = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))  # site root; every default hangs off it
DB = os.environ.get("AGENT_BUS_DB", os.path.join(BRIDGE, "bus.db"))
INBOX_ROOT = os.environ.get("AGENT_BRIDGE_INBOX", os.path.join(BRIDGE, "inbox"))  # back-compat JSON mirror
KEYS_DIR = os.environ.get("AGENT_BUS_KEYS_DIR", os.path.join(BRIDGE, "keys"))     # A2: identity↔pubkey registry
_IMPORT_DB, _IMPORT_INBOX = DB, INBOX_ROOT                     # what we saw at IMPORT (to detect patching)


def _db_path():
    """The bus DB path at CALL time. The module-level path froze at import time, so anyone who imported the module
    first and set the env only afterwards (typical in-process measurement) had every `db=None` call go to the
    BAKED-IN default DB — on a live machine that would have written to the PRODUCTION bus from a call meant
    purely as a measurement. Rule: an explicit monkeypatch (ab.DB = ...) wins, otherwise the env is authoritative."""
    return DB if DB != _IMPORT_DB else os.environ.get("AGENT_BUS_DB", DB)


def _inbox_root():
    return INBOX_ROOT if INBOX_ROOT != _IMPORT_INBOX else os.environ.get("AGENT_BRIDGE_INBOX", INBOX_ROOT)


def reload_paths():
    """RE-READ the module-level paths from the environment (for measuring code, if the env was set after import)."""
    global DB, INBOX_ROOT, KEYS_DIR
    DB = os.environ.get("AGENT_BUS_DB", _IMPORT_DB)
    INBOX_ROOT = os.environ.get("AGENT_BRIDGE_INBOX", _IMPORT_INBOX)
    KEYS_DIR = os.environ.get("AGENT_BUS_KEYS_DIR", KEYS_DIR)
    return {"DB": DB, "INBOX_ROOT": INBOX_ROOT, "KEYS_DIR": KEYS_DIR}

# ── FROZEN WIRE CONTRACT v1.0.0 ──────────────────────
# Vendored clients RELY on this; the schema is frozen until the II fusion.
# Changes ONLY additive/back-compat (new nullable column, new kind/topic value, new CLI) → minor bump.
# Renaming/dropping/retyping a column, id monotonicity, the thread_id default, read_at/cursor semantics
# or breaking the JSON mirror keys = MAJOR, and requires approval from both operators.
# Full contract: docs/architecture/AGENT_BUS_SCHEMA.md
SCHEMA_VERSION = "1.0.0"
# v1.1 (2026-09-14): PROTOCOL version (kind vocabulary + CLI), SEPARATE from the DB schema pin. The new kinds (sds-envelope,
# operator-wake, operator-sleep-safe) and the new recv switches are additive (MINOR). The DB SCHEMA_VERSION DELIBERATELY
# stays 1.0.0: the schema did not change, and verify flags a pin mismatch as DRIFT — a bump would turn every live DB red.
# v1.2 (2026-09-14): cross-machine transport (bus_ssh_*, bus_relay), attachment-descriptor kind (`attachment`), SCE hook
# point (sce_hook). Additive → MINOR; the DB schema still does not change (SCHEMA_VERSION stays 1.0.0).
# v1.4.0: ENFORCEMENT (bus_enforce): product mode (AGENT_BUS_MODE=product / .product_mode.on) → recv REJECTS an
# unsigned/forged/stale/replayed row; the seen-store is a separate append-only file → the DB schema does NOT change; the default
# (dev) behaviour is byte-identical to the old one. Additive → MINOR.
PROTOCOL_VERSION = "1.5.0"
SDS_KIND = "sds-envelope"
ATTACH_KIND = "attachment"
MESSAGE_COLUMNS = ("id", "ts", "sender", "recipient", "topic", "kind",
                   "thread_id", "in_reply_to", "body", "read_at",
                   "sig", "pubkey")                                         # frozen: order+name; A2: sig/pubkey append-only (nullable)
CURSOR_COLUMNS = ("agent", "last_seen_id")                                  # frozen
JSON_MIRROR_KEYS = ("from", "to", "kind", "topic", "note", "ts", "bus_id")  # +opc. "in_reply_to"

_MAX_BODY = 64 * 1024                                            # D#1: AgentBus = COORDINATION (I2) → body size cap (like the ledger)
_MAX_FIELD = 4096                                               # R3-D#1: against field DoS bypassing the body cap (sender/recipient/topic/kind/thread_id get a cap too)
_RECV_LIMIT = 500                                               # D#2: recv paging (against the 'all unread into memory' DoS)
_CLOCK_SKEW_S = 300                                             # clock skew allowed on the age limit
_SQLITE_INT_MAX = 2 ** 63 - 1                                   # R3-I#3: upper bound of sqlite's 8-byte signed INTEGER

# C4: the divergence guard also checks TYPE/NOTNULL/PK (not just the name) — (name, type.upper(), notnull, pk).
_FROZEN_MESSAGES = (("id", "INTEGER", 0, 1), ("ts", "INTEGER", 1, 0), ("sender", "TEXT", 1, 0),
                    ("recipient", "TEXT", 1, 0), ("topic", "TEXT", 0, 0), ("kind", "TEXT", 0, 0),
                    ("thread_id", "TEXT", 0, 0), ("in_reply_to", "INTEGER", 0, 0),
                    ("body", "TEXT", 1, 0), ("read_at", "INTEGER", 0, 0))
_FROZEN_CURSORS = (("agent", "TEXT", 0, 1), ("last_seen_id", "INTEGER", 1, 0))


def _safe_name(s):
    """Filesystem-safe NAME component. ONLY ASCII [A-Za-z0-9._-]; everything else → '-'; '', '.', '..' → 'x'.
    R2-A1: if the raw input is >64 OR non-ASCII → short hash suffix — otherwise two DIFFERENT recipients/senders
    could truncate to the same file/dir name, or unicode homoglyphs could collide (cross-recipient leak/spoof).
    B1: the hash suffix is also needed if ANY character was sanitized ('safe != raw') —
    otherwise short ASCII names with special characters collide (e.g. 'a/b' and 'a-b' both map to 'a-b')."""
    import string, hashlib
    raw = s or ""
    safe = "".join(ch if ch in (string.ascii_letters + string.digits + "._-") else "-" for ch in raw)
    if len(safe) > 64 or any(ord(ch) > 127 for ch in raw) or safe != raw:   # truncation / non-ASCII / ANY sanitized char (B1: injective) → collision-resistant suffix
        safe = safe[:48] + "~" + hashlib.sha1(raw.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    safe = safe[:64]
    return safe if safe and safe not in (".", "..") else "x"


def _conn(db=None):
    path = db or _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = sqlite3.connect(path, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=10000")
    c.execute("PRAGMA wal_autocheckpoint=256")               # R2-B#2: keep -wal from growing without bound (checkpoint-starvation DoS)
    c.execute("PRAGMA journal_size_limit=%d" % (16 * 1024 * 1024))  # truncate back after checkpoint
    c.row_factory = sqlite3.Row
    return c


# A1-L1: cursor-move audit (append-only, HASH-CHAINED, DETECTION). ADDITIVE/internal observability — NOT the wire contract
# (vendored clients do not build on it), so it does NOT bump SCHEMA_VERSION; the frozen messages/cursors/meta/JSON mirror are untouched.
# The per-agent hash chain (prev_row_hash, in ONE SQLite transaction with the cursor move) is the ATTESTABLE SUBSTRATE: it catches
# accidental + naive/inconsistent tampering. RECALIBRATION: the local FILE ANCHOR is DEFERRED — a
# determined same-uid (root) attacker would consistently rewrite both the chain AND the local anchor, so the anchor's tamper-evidence
# value is real ONLY with an external witness (vendor-signed off-box / remote tier); it goes there (sign_audit_head pattern, gated).
_GENESIS = "0" * 64
_AUDIT_DDL = ("CREATE TABLE IF NOT EXISTS cursor_audit("
              "id INTEGER PRIMARY KEY AUTOINCREMENT, seq INTEGER NOT NULL, ts INTEGER NOT NULL, agent TEXT NOT NULL, "
              "from_id INTEGER NOT NULL, to_id INTEGER NOT NULL, op TEXT NOT NULL, "
              "skipped_undelivered INTEGER NOT NULL DEFAULT 0, prev_row_hash TEXT NOT NULL, row_hash TEXT NOT NULL)")


def _canonical(obj):
    """Canonical JSON for hashing: sorted keys, compact, allow_nan=False (the pattern of the Kernel's core/hashing.py:canonical, K-46)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


# ── A2: sender authentication (anti-spoof, Ed25519) ────────────────────────────────────────────────
# Closing the red-team A2 hole: `send(sender, …)` used to trust the sender string BLINDLY → any local
# caller could impersonate any agent. Now the sender OPTIONALLY signs the content (Ed25519,
# asymmetric+deterministic), and the receiver verifies against the root-owned registry pubkey.
# Design proposal + reference (one of the arms): docs/security/agentbus-a2-sender-authentication.md + a2_ref.py.
# The signed byte image is built with `_canonical` = BYTE-IDENTICAL to a2_ref's `<our engine>.determinism.canonical`
# (verified). FROZEN: `thread_id` is EXCLUDED from the signed fields (server-derived; the sender's
# threading INTENT is carried by the signed `in_reply_to`) → resolves the root chicken-and-egg. signed-shape v:2.
# ADDITIVE: signs if sign_key is given, OR (auto-sign) if the sender's guarded default seed file exists in the
# registry (keys/<sender>.ed25519.key) — opt-out: AGENT_BUS_AUTO_SIGN=0. Senders without a key are UNCHANGED.
# strict ONLY if AGENT_BUS_REQUIRE_SIG=1 (default OFF). NO SCHEMA_VERSION bump (like delivered_id).
_A2_ALG = "ed25519"
#: THE FROZEN FIELD SET (thread_id EXCLUDED — server-derived). The SET is fixed, NOT the order: in the
#: signed byte image the keys are in ALPHABETICAL order (sort_keys), not in this order.
#: The earlier "FROZEN order" comment was misleading — a reimplementer could have copied this tuple order
#: into serialization and got silent divergence. Measured: the byte-image order is
#: body, in_reply_to, kind, recipient, sender, topic, ts, v.
_A2_SIGNED_FIELDS = ("v", "sender", "recipient", "topic", "kind", "in_reply_to", "body", "ts")
try:
    from cryptography.hazmat.primitives import serialization as _a2_ser
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _a2_ed
    _A2_HAVE = True
    _A2_RAW_ENC, _A2_RAW_PUB = _a2_ser.Encoding.Raw, _a2_ser.PublicFormat.Raw
except Exception:                                                # pragma: no cover - environment-dependent
    _A2_HAVE = False


def canonical_text_field(value):
    """The canonical value of a SIGNED text field (topic, kind, body). ONE source; everyone calls this.

    WHY PUBLIC. Until now THREE places implemented the same rule separately: the byte-image builder
    (`_a2_content_bytes`), the client signer (`sign_for_send`) and the cross-machine inbound path
    (`bus_ssh_exchange`). Measured, how the three handled the shapes:

        shape           canonical      inbound path (old)
        kind omitted    ""             "msg"
        kind = ""       ""             "msg"
        kind = null     ""             "msg"
        kind = "msg"    "msg"          "msg"

    So a partner signing per SPEC failed on the inbound path in THREE of the four shapes
    — and not "silently": the bus rejected it with `presigned: signature does not verify (forged or
    tampered)`, i.e. it accused an honest partner of FORGERY.

    The fix was not copying the rule into a third place but this function: whoever produces a field of
    the signed byte image calls this. If the rule changes, it changes in one place."""
    return "" if value is None else str(value) if value else ""


def _signed_integer(name, value, *, allow_none=False):
    """The checked value of a SIGNED integer field (ts, in_reply_to). Non-integer → clear error, not a silent byte image.

    WHY FAIL-CLOSED. The spec requires `ts` to be an INTEGER, but the canonicalizer did not check types:
    measured `ts=1.5` → `"ts":1.5`, `ts=True` → `"ts":true`, `ts="123"` → `"ts":"123"`. All three give a
    byte image that is invalid under OUR OWN spec — and signable. The caller gets no signal; on the partner's
    side it turns into an inexplicable verify failure or a `true` in an integer field.

    `bool` is excluded SEPARATELY, although in Python it is a subclass of `int`: `True` has integer value 1, but
    JSON writes it as `true` — exactly the silent shape change this guard catches."""
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("signed shape: '%s' must be an integer (got %s) — a non-integer would sign a "
                         "byte image this spec calls invalid" % (name, type(value).__name__))
    return value


def _a2_content_bytes(msg):
    """The canonical byte image of the signed content (id EXCLUDED — the DB assigns it on insert; thread_id EXCLUDED — server-derived). Missing optional fields fall to None/"", so that signer and verifier
    build THE SAME byte image even from slightly different dicts. `v:2` = signed-shape version (≠ DB SCHEMA_VERSION)."""
    content = {
        "v": 2,
        "sender": msg.get("sender"),
        "recipient": msg.get("recipient"),
        "topic": canonical_text_field(msg.get("topic")),
        "kind": canonical_text_field(msg.get("kind")),
        "in_reply_to": _signed_integer("in_reply_to", msg.get("in_reply_to"), allow_none=True),
        "body": canonical_text_field(msg.get("body")),
        "ts": _signed_integer("ts", msg.get("ts")),
    }
    return _canonical(content).encode("utf-8")                   # == the reference engine's determinism.canonical(content) (igazolt byte-eq)


def _a2_sign(seed, msg):
    """Sign the content with a 32-byte Ed25519 private seed → {alg, sig, pubkey} (the pubkey travels so the registry holder can verify)."""
    if not _A2_HAVE:
        raise RuntimeError("ed25519 requires the 'cryptography' package")
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    priv = _a2_ed.Ed25519PrivateKey.from_private_bytes(seed)
    sig = priv.sign(_a2_content_bytes(msg))
    pub = priv.public_key().public_bytes(_A2_RAW_ENC, _A2_RAW_PUB)
    return {"alg": _A2_ALG, "sig": sig.hex(), "pubkey": pub.hex()}


def _a2_guarded_read(path):
    """Read a registry key file ONLY if the file AND its dir are root-owned and not group/world-writable — this is
    EXACTLY THE SAME trust guard that `agent_bus_watcher.is_armed` uses for the wake arm flag. Returns:
    the stripped hex, or None if the guard fails / the file is missing."""
    # `stat` and `open` used to be TWO separate operations — in between, the file (or a
    # symlink in its place) could be swapped, and the guard checked the OLD file while the read got the NEW one. So: a single
    # open with O_NOFOLLOW (the final component cannot be a symlink), and the permission check on the OPENED fd.
    try:
        dst = os.stat(os.path.dirname(path))
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or (st.st_mode & 0o022) or dst.st_uid != 0 or (dst.st_mode & 0o022):
            return None
        with os.fdopen(fd, encoding="utf-8") as f:
            fd = -1                                              # the file object took ownership of the fd
            return f.read().strip()
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _a2_load_registry_pubkey(agent, keys_dir):
    """The trust anchor: the registry pubkey bound to `agent`, or None if not registered / the guard fails.
    `agent` is basename-sanitized so a crafted name cannot break out of `keys_dir`."""
    safe = os.path.basename(agent)                               # no '/', no '..' traversal
    if not safe or safe in (".", ".."):
        return None
    return _a2_guarded_read(os.path.join(keys_dir, "%s.pub" % safe))


def _a2_auto_sign_enabled():
    """AUTO-SIGN opt-out switch: AGENT_BUS_AUTO_SIGN=0/false/no/off → OFF; everything else (including the default) → ON."""
    return os.environ.get("AGENT_BUS_AUTO_SIGN", "").strip().lower() not in ("0", "false", "no", "off")


def _a2_default_sign_key(sender, keys_dir=None):
    """Path of the sender's default private seed file (keys/<sender>.ed25519.key), or None if missing / the guard fails.
    Guard: the seed file is root-owned and STRICTLY private (0600 — no group or world bits), the dir is root-owned
    and not group/world-writable. The sender is basename-sanitized (against traversal). Guard failure → None (the send
    proceeds unsigned, as before) — auto-sign is a convenience layer, not enforcement (that is strict mode)."""
    if keys_dir is None:
        keys_dir = KEYS_DIR
    safe = os.path.basename(sender or "")
    if not safe or safe in (".", ".."):
        return None
    path = os.path.join(keys_dir, "%s.ed25519.key" % safe)
    try:                                                         # a symlink in the seed's place: the guard could be bypassed
        st = os.lstat(path)                                      # (this branch only returns a PATH, not an fd)
        dst = os.stat(os.path.dirname(path))
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o077) \
            or dst.st_uid != 0 or (dst.st_mode & 0o022):
        return None
    return path


def verify_sender(msg, keys_dir=None):
    """Classify the authenticity of a received (recv'd) message against the registry:
      - "unsigned" — no signature AND the registry binds NO key to the sender (back-compat path; NOT forgery).
      - "unsigned-pinned" — no signature, but the registry BINDS a key to the declared sender: the name belongs to a
                     party able to sign, yet the row is bare. NOT proven forgery (the back-compat path is legal), but
                     it does not blend into anonymous `unsigned` either — (2026-09-17): a bare row arriving in the name
                     of a sender that signs 100 percent of the time was until then only a HUMAN/statistical
                     detection, with no machine gate. This class is the machine gate's input (strict/product mode).
      - "forged"   — has a signature, but it is invalid, OR the pubkey is NOT the one the registry binds to the declared sender (impersonation).
      - "signed"   — valid signature with the registry key belonging to `msg['sender']`.
    Reads `sig`/`pubkey` directly from the recv'd `msg` (recv puts them in from the columns).
    If `keys_dir` is None it resolves to the MODULE-level KEYS_DIR at RUNTIME (not at definition time) — so
    deploy sees the live value and tests see the monkeypatched value."""
    if keys_dir is None:
        keys_dir = KEYS_DIR
    sig_hex = msg.get("sig")
    if not sig_hex:
        if _A2_HAVE and _a2_load_registry_pubkey(msg.get("sender", ""), keys_dir) is not None:
            return "unsigned-pinned"
        return "unsigned"
    if not _A2_HAVE:
        return "forged"
    pub_hex = msg.get("pubkey") or ""
    expect = _a2_load_registry_pubkey(msg.get("sender", ""), keys_dir)
    if expect is None or pub_hex != expect:                      # unknown sender or key mismatch
        return "forged"
    try:
        pub = _a2_ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), _a2_content_bytes(msg))
        return "signed"
    except Exception:
        return "forged"


_REQUIRE_SIG_MARKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".require_sig.on")


def _a2_strict():
    """Opt-in strict mode: recv MARKS (auth) the sender authenticity of every row (annotates, does NOT drop).
    Enabled by the AGENT_BUS_REQUIRE_SIG=1/true/yes/on env var OR the fleet-wide, reversible
    `.require_sig.on` marker file (rm the marker = off). Default OFF (env empty + no marker)."""
    if os.environ.get("AGENT_BUS_REQUIRE_SIG", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return os.path.exists(_REQUIRE_SIG_MARKER)


def _audit_row_hash(seq, ts, agent, op, from_id, to_id, skipped, prev_hash):
    content = {"seq": seq, "ts": ts, "agent": agent, "op": op, "from_id": from_id,
               "to_id": to_id, "skipped_undelivered": skipped, "prev_row_hash": prev_hash}
    return hashlib.sha256(_canonical(content).encode("utf-8")).hexdigest()


def _append_audit(c, agent, from_id, to_id, op, skipped):
    """Append a HASH-CHAINED cursor_audit row in the CALLER's transaction (→ atomic with the cursor move, no TOCTOU; Q1).
    Per-agent chain: prev = the agent's last row_hash (genesis if first). row_hash is over (prev_row_hash + content) → deleting/rewriting any row gives a chain break/hash mismatch (audit_verify)."""
    ts = time.time_ns()
    prev_row = c.execute("SELECT seq,row_hash FROM cursor_audit WHERE agent=? ORDER BY id DESC LIMIT 1", (agent,)).fetchone()
    # fix: if the last row is LEGACY (pre-chain, row_hash IS NULL from a non-empty migration) → fresh chain start
    # from GENESIS (we do not chain onto NULLs). Only if the last row is ALREADY chained (row_hash NOT NULL) do we continue.
    if prev_row and prev_row["row_hash"] is not None:
        seq = prev_row["seq"] + 1
        prev = prev_row["row_hash"]
    else:
        seq = 0
        prev = _GENESIS
    rh = _audit_row_hash(seq, ts, agent, op, from_id, to_id, skipped, prev)
    c.execute("INSERT INTO cursor_audit(seq,ts,agent,from_id,to_id,op,skipped_undelivered,prev_row_hash,row_hash) "
              "VALUES(?,?,?,?,?,?,?,?,?)", (seq, ts, agent, from_id, to_id, op, skipped, prev, rh))


def init(db=None):
    c = _conn(db)
    try:
        # R2-B#3: if the schema is ALREADY there, do NOT open a write transaction on every call → read-only ops (tail/thread/recv)
        # should not contend with a long writer. (INSERT OR IGNORE was a write txn and the main contention source.)
        primed = False
        try:
            primed = bool(c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone())
        except sqlite3.OperationalError:
            pass                                             # the meta table does not exist yet → full init needed
        if not primed:
            _init_schema(c)
        # A1-L1 additive migration (cursor_audit hash chain). Opens a write txn ONLY if the table is really missing/old
        # (the existence/column checks are reads → no write contention in the existing case).
        have_audit = bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cursor_audit'").fetchone())
        chained = have_audit and "row_hash" in {r[1] for r in c.execute("PRAGMA table_info(cursor_audit)")}
        if (not have_audit) or (not chained):
            with c:
                if not have_audit:
                    c.execute(_AUDIT_DDL)
                elif c.execute("SELECT COUNT(*) FROM cursor_audit").fetchone()[0] == 0:
                    # old (chainless), EMPTY cursor_audit → recreate (internal observability, no-deletion ok)
                    c.execute("DROP TABLE cursor_audit")
                    c.execute(_AUDIT_DDL)
                else:
                    # non-empty old table → additive nullable hash columns (the old rows predate the chain)
                    for _col in ("seq INTEGER", "prev_row_hash TEXT", "row_hash TEXT"):
                        c.execute("ALTER TABLE cursor_audit ADD COLUMN %s" % _col)
        # 7/3: AT MOST ONE replay per original — so a concurrent operator call (TOCTOU)
        # cannot duplicate: the second insert gets IntegrityError. On an old DB (if a duplicate already exists) it is just skipped.
        try:
            with c:
                c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_replay_once ON cursor_audit(agent, from_id) WHERE op='replay'")
        except sqlite3.DatabaseError:
            pass
        # A1-L3 additive migration: cursors.delivered_id (the highest actually DELIVERED id; ONLY mark-recv raises it).
        # PREFIX-frozen (CURSOR_COLUMNS=(agent,last_seen_id) untouched). SEED: for EXISTING cursors delivered_id:=last_seen_id
        # (the legitimately delivered baseline of pre-L3 history) → reconcile should not flag everything as skipped (because of default 0).
        try:
            _has_delivered = "delivered_id" in {r[1] for r in c.execute("PRAGMA table_info(cursors)")}
        except sqlite3.OperationalError:
            _has_delivered = True                            # the cursors table does not exist yet (a fresh init will create it)
        if not _has_delivered and c.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cursors'").fetchone():
            with c:
                c.execute("ALTER TABLE cursors ADD COLUMN delivered_id INTEGER NOT NULL DEFAULT 0")
                c.execute("UPDATE cursors SET delivered_id = last_seen_id")   # seed: legitimate baseline
        # A2 additive migration: messages.sig / messages.pubkey (nullable, sender signature). Mirrors the delivered_id/cursor_audit
        # precedent → NO SCHEMA_VERSION bump; old (unsigned) rows stay NULL (no-deletion).
        try:
            _msg_cols = {r[1] for r in c.execute("PRAGMA table_info(messages)")}
        except sqlite3.OperationalError:
            _msg_cols = {"sig", "pubkey"}                     # the messages table does not exist yet (a fresh init will create it)
        for _col in ("sig", "pubkey"):
            if _col not in _msg_cols:
                with c:
                    c.execute("ALTER TABLE messages ADD COLUMN %s TEXT" % _col)
    finally:
        c.close()


def _init_schema(c):
    with c:
        c.execute("""CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL,
            topic TEXT, kind TEXT, thread_id TEXT, in_reply_to INTEGER,
            body TEXT NOT NULL, read_at INTEGER,
            sig TEXT, pubkey TEXT)""")                            # A2: nullable sender signature (append-only; unsigned row = NULL)
        c.execute("CREATE INDEX IF NOT EXISTS ix_recipient ON messages(recipient, id)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_thread ON messages(thread_id, id)")
        c.execute("""CREATE TABLE IF NOT EXISTS cursors(
            agent TEXT PRIMARY KEY, last_seen_id INTEGER NOT NULL DEFAULT 0,
            delivered_id INTEGER NOT NULL DEFAULT 0)""")             # A1-L3: the highest DELIVERED id (mark-only)
        c.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")  # additive: version pin
        # the frozen version is written ONLY if not already there (we do not overwrite an older DB; no-deletion)
        c.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)", (SCHEMA_VERSION,))


def verify_schema(db=None):
    """Divergence guard: does the live DB schema match the frozen contract. Never-throw → dict.
    R2 hardening: IN ADDITION to the (name,type,notnull,pk) prefix, a REAL AUTOINCREMENT (regex on the id line, not just any
    'AUTOINCREMENT' substring in a carrier column/comment — R2-C1); behaviour-modifying CHECK/COLLATE/GENERATED
    is FORBIDDEN in the frozen tables (R2-C3/C4); an additive column ONLY if INSERT-able (nullable or default — R2-C6);
    trigger/view FORBIDDEN (a trigger could delete rows = no-deletion violation — R2-C7); the meta table is also part of the contract (R2-C5)."""
    import re
    out = {"ok": True, "schema_version": SCHEMA_VERSION, "pinned": None, "problems": []}
    try:
        c = _conn(db)
        try:
            def _info(tbl):
                return list(c.execute("PRAGMA table_info(%s)" % tbl))
            mi, ci, meta_i = _info("messages"), _info("cursors"), _info("meta")

            def _tup(rows):
                return tuple((r["name"], (r["type"] or "").upper(), r["notnull"], r["pk"]) for r in rows)
            msg, cur, meta = _tup(mi), _tup(ci), _tup(meta_i)

            def _sql(name):
                r = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
                return (r["sql"] or "") if r else ""
            msg_sql, cur_sql = _sql("messages"), _sql("cursors")
            objs = [r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type IN ('trigger','view')")]
            row = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            out["pinned"] = row["value"] if row else None
        finally:
            c.close()
    except sqlite3.Error as e:
        out["ok"] = False
        out["problems"].append("db-open: %s" % e)
        return out
    P = out["problems"]
    if msg[:len(_FROZEN_MESSAGES)] != _FROZEN_MESSAGES:
        P.append("messages schema drift: %r != frozen %r" % (msg, _FROZEN_MESSAGES))
    if cur[:len(_FROZEN_CURSORS)] != _FROZEN_CURSORS:
        P.append("cursors schema drift: %r != frozen %r" % (cur, _FROZEN_CURSORS))
    # R2-C1: a REAL AUTOINCREMENT on the id column (against substring bypass)
    # R3-A1: the id column may be quoted/bracketed ("id"/[id]/`id`) AND still be a REAL AUTOINCREMENT (the tuple check already
    # proved column 0 is named 'id' + pk=1); the regex accepts these too, otherwise a semantically IDENTICAL schema is a FALSE DRIFT.
    if not re.search(r'(?:\bID\b|"ID"|\[ID\]|`ID`)\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', (msg_sql or "").upper()):
        P.append("messages.id is not a real AUTOINCREMENT (id monotonicity at risk)")
    # R2-C3/C4: the DDL of the frozen tables must not contain a behaviour-modifying element (the tuple compare is blind to it).
    # R3-A1: the token scan runs WITH WORD BOUNDARIES and AFTER FILTERING OUT quoted identifiers/string literals — otherwise the mere
    # NAME of a LEGITIMATE additive column ('checksum'/'collate_marker'/'generated_at') or a DEFAULT 'unchecked' string gave a FALSE DRIFT
    # instead of OK (guard DoS: an additive column allowed by the contract was rejected).
    def _strip_literals(sq):
        # we neutralize quoted/bracket identifiers, '…' string literals AND SQL comments (--… and /*…*/) BEFORE the
        # token scan (a forbidden token only counts in RAW DDL). R4-B2: without filtering comments, a
        # harmless `/* CHECK */` / `-- COLLATE` comment gave a FALSE DRIFT (guard DoS: legitimate schema rejected).
        # The alternation matches left to right → a '--'/'/*' INSIDE a string literal is consumed as the string (not a comment).
        return re.sub(r'''"[^"]*"|\[[^\]]*\]|`[^`]*`|'[^']*'|--[^\n]*|/\*.*?\*/''', " ", sq or "", flags=re.DOTALL)
    for nm, sq in (("messages", msg_sql), ("cursors", cur_sql)):
        u = _strip_literals(sq).upper()
        for tok in ("CHECK", "COLLATE", "GENERATED"):
            if re.search(r"\b%s\b" % tok, u):           # word boundary: 'checksum' no longer matches CHECK
                P.append("%s table forbidden DDL element: %s (the frozen contract contains no such thing)" % (nm, tok))
    # R2-C7: the contract has NO trigger/view (an AFTER INSERT trigger could delete rows → no-deletion violation)
    if objs:
        P.append("forbidden trigger/view: %s" % ", ".join(sorted(objs)))
    # R2-C6: an additive (extra) column ONLY if INSERT-able (nullable OR has a default) — otherwise verify OK but send() broken
    for r in mi[len(_FROZEN_MESSAGES):]:
        if r["notnull"] and r["dflt_value"] is None:
            P.append("additive column breaks INSERT (NOT NULL without default): %s" % r["name"])
    extra = msg[len(_FROZEN_MESSAGES):]
    if extra:
        out["added_columns"] = [e[0] for e in extra]
    # R2-C5: the meta table (carrier of the version pin) is also part of the contract
    if meta[:2] != (("key", "TEXT", 0, 1), ("value", "TEXT", 0, 0)):
        P.append("meta table drift: %r" % (meta,))
    if out["pinned"] is None:                                # C5: a MISSING pin is also a problem (not a silent false OK)
        P.append("schema_version not pinned (meta)")
    elif out["pinned"] != SCHEMA_VERSION:
        P.append("version mismatch: db pinned %s, code %s" % (out["pinned"], SCHEMA_VERSION))
    out["ok"] = not P
    return out


def _mirror_json(row_id, sender, recipient, topic, kind, thread_id, in_reply_to, body, ts, inbox_root=None, sig=None, pubkey=None):
    """Back-compat JSON mirror (atomic tmp→rename). HARDENED (red-team A1–A8, I4): `_safe_name` on every path component of
    recipient/sender/topic (against path traversal/clobber/terminal injection) + realpath confinement (the resolved path must
    stay INSIDE the inbox) + O_EXCL|O_NOFOLLOW (no symlink follow / silent overwrite). Best-effort: ANY error →
    skip (I7 fail-safe), NEVER propagates into send. Note: the mirror is DELIBERATELY lossy/legacy (the DB is the source of truth, C6);
    in_reply_to stays in the established LIST shape (I1 — vendored clients build on it)."""
    try:
        root = os.path.realpath(inbox_root or INBOX_ROOT)
        d = os.path.realpath(os.path.join(root, _safe_name(recipient)))
        if d != root and not d.startswith(root + os.sep):       # I4 realpath confinement: the recipient cannot break out
            raise OSError("recipient escapes inbox: %r" % recipient)
        os.makedirs(d, exist_ok=True)
        rec = {"from": sender, "to": recipient, "kind": kind, "topic": topic,
               "note": body, "ts": ts, "bus_id": row_id}
        if in_reply_to:
            rec["in_reply_to"] = [in_reply_to]
        if sig:                                                  # the mirror consumer can verify too
            rec["sig"], rec["pubkey"] = sig, pubkey
        base = os.path.join(d, "%s_%d_%s.json" % (_safe_name(sender), row_id, _safe_name(topic or "msg")))
        tmp = base + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)  # A4/A7b: no clobber/symlink follow
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False, indent=2)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, base)
        return base
    except Exception as e:                                       # D#9: best-effort → any error = skip, never-throw
        sys.stderr.write("  (json-mirror skip: %s)\n" % e)
        return None


def check_presigned(sender, recipient, body, presigned, *, topic="", kind="msg", in_reply_to=None, keys_dir=None):
    """Check a CLIENT-SIDE signed row BEFORE the INSERT (v1.5.2, 2026-09-21). `presigned` = {ts, sig, pubkey}
    as given by the sender. Returns: (ts:int, sig:str, pubkey:str), or raises ValueError.
    WHY: by principle, the SSH exchange does not sign the REMOTE party's row with the bus machine's key (sign_key=False) — correct, because the
    bus machine is not the sender. But product mode rejects a bare row under a name pinned in the registry (`unsigned-pinned`), so since 09-19 EVERY row between the two machines was silently dropped on read (audit: 25 one arm→the partner arm,
    7064 the partner arm→one arm). The missing link: the sender signs its own row with ITS OWN key, the server checks it against the
    registry and stores exactly that. The `ts` is the sender's (it is in the signed content), and the enforce window
    (past/future) measures it the same way as a local row. Fail-closed: unknown sender, key mismatch, bad signature,
    malformed shape → ValueError (the caller returns it as a VISIBLE rejection, not a silent drop)."""
    if not _A2_HAVE:
        raise ValueError("presigned: ed25519 requires the 'cryptography' package")
    if not isinstance(presigned, dict):
        raise ValueError("presigned: must be an object {ts, sig, pubkey}")
    ts, sig_hex, pub_hex = presigned.get("ts"), presigned.get("sig"), presigned.get("pubkey")
    if isinstance(ts, bool) or not isinstance(ts, int) or ts <= 0 or ts > _SQLITE_INT_MAX:
        raise ValueError("presigned: ts must be a positive integer (ns)")
    if not isinstance(sig_hex, str) or not isinstance(pub_hex, str) or len(pub_hex) != 64 or len(sig_hex) != 128:
        raise ValueError("presigned: sig (128 hex) and pubkey (64 hex) required")
    expect = _a2_load_registry_pubkey(sender, keys_dir if keys_dir is not None else KEYS_DIR)
    if expect is None:
        raise ValueError("presigned: sender '%s' has no registry key (unknown sender)" % sender)
    if pub_hex != expect:
        raise ValueError("presigned: pubkey is not the registry key of '%s' (forged)" % sender)
    try:
        pub = _a2_ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), _a2_content_bytes({"sender": sender, "recipient": recipient, "topic": topic,
                                                              "kind": kind, "in_reply_to": in_reply_to, "body": body,
                                                              "ts": ts}))
    except Exception:
        raise ValueError("presigned: signature does not verify (forged or tampered)")
    return ts, sig_hex, pub_hex


def sign_for_send(sign_key, sender, recipient, body, *, topic="", kind="msg", in_reply_to=None, ts=None):
    """The CLIENT side: {ts, sig, pubkey} signed with its own seed file, for a later `send(..., presigned=...)`.
    The content byte image is the same as for a local `send` (`_a2_content_bytes`), so the bus machine's `check_presigned` and
    the recipient's `verify_sender` check the same thing.

    THIS DOCSTRING ONCE LIED. The function carried ITS OWN normalization of the fields (`kind or "msg"`,
    `topic or ""`) before passing them on — so for an EXPLICIT `kind=""` it signed `"msg"`, while
    `_a2_content_bytes` (the spec, and what the verifier computes) used `""`. Measured: the `sign_for_send(kind="")`
    signature fits the `kind="msg"` byte image, NOT the `kind=""` one — i.e. a partner computing per spec
    fails verify SILENTLY. One decision, two implementations; the weaker one won.

    The kwarg default (`kind="msg"`) is API convenience for an OMITTED field, and it stays. An EXPLICIT empty
    string is caller INTENT and passes through as `""`. ONLY `_a2_content_bytes` normalizes."""
    if in_reply_to is not None:
        in_reply_to = int(in_reply_to)
    ts = time.time_ns() if ts is None else int(ts)
    seed = bytes.fromhex(open(sign_key, encoding="utf-8").read().strip())
    rec = _a2_sign(seed, {"sender": sender, "recipient": recipient, "topic": topic, "kind": kind,
                          "in_reply_to": in_reply_to, "body": body, "ts": ts})
    return {"ts": ts, "sig": rec["sig"], "pubkey": rec["pubkey"]}


def send(sender, recipient, body, *, topic="", kind="msg", thread_id=None, in_reply_to=None,
         db=None, mirror=True, inbox_root=None, sign_key=None, presigned=None):
    if body is not None and len(body.encode("utf-8", "surrogatepass")) > _MAX_BODY:  # D#1/R3-A5: BYTE size (not chars) → against the multibyte 4× bypass
        raise ValueError("body exceeds %d B (AgentBus = coordination, I2)" % _MAX_BODY)
    # R3-D#1: against field DoS bypassing the body cap — routing/thread fields are bounded too (a 500K thread_id ×4 = MBs)
    for _nm, _v in (("sender", sender), ("recipient", recipient), ("topic", topic),
                    ("kind", kind), ("thread_id", thread_id)):
        if _v is not None and len(str(_v)) > _MAX_FIELD:
            raise ValueError("%s exceeds %d chars (AgentBus = coordination, I2)" % (_nm, _MAX_FIELD))
    # R3-I#3: in_reply_to goes into sqlite's 8-byte INTEGER → range check (≥0, ≤2^63-1), otherwise the insert
    # would raise a raw OverflowError (breaking the CLI's 'never-throw' promise) → controlled ValueError
    if in_reply_to is not None:
        try:
            _ir = int(in_reply_to)
        except (TypeError, ValueError):
            raise ValueError("in_reply_to must be an integer")
        if not (0 <= _ir <= _SQLITE_INT_MAX):
            raise ValueError("in_reply_to out of range [0, 2^63-1]")
        in_reply_to = _ir
    if kind == ATTACH_KIND:                                      # v1.2: an attachment message's body is ONLY the closed descriptor (the content lives outside the bus)
        import bus_attach
        try:
            bus_attach.check_descriptor(body)
        except ValueError as e:
            raise ValueError("attachment refused: %s" % e)
    if kind == SDS_KIND:                                         # v1.1 (partner arm step 1): the frame structure is fixed — a malformed frame does not reach the bus
        import sds_envelope
        try:
            sds_envelope.check_framed_shape(body)
        except ValueError as e:
            raise ValueError("sds-envelope refused: %s" % e)
    init(db)
    ts = time.time_ns()
    # A2: if sign_key is given, the content (id/thread_id EXCLUDED) is signed with Ed25519 BEFORE the INSERT →
    # sig/pubkey go into the row. AUTO-SIGN: without sign_key the sender's guarded default seed is resolved
    # (keys/<sender>.ed25519.key) — closing the "forgot sign_key=" gap; opt-out AGENT_BUS_AUTO_SIGN=0.
    # Neither an explicit key nor a default → both NULL, byte-identical to the previous (unsigned) behaviour.
    # PRESIGNED (v1.5.2): the sender signed it on its own machine — checked against the registry, we store EXACTLY that
    # (the ts is theirs too); the bus machine's key does NOT sign in this case (the two paths are mutually exclusive).
    sig = pubkey = None
    if presigned is not None:
        if sign_key:
            raise ValueError("presigned and sign_key are mutually exclusive")
        ts, sig, pubkey = check_presigned(sender, recipient, body, presigned, topic=topic, kind=kind,
                                          in_reply_to=in_reply_to)
        sign_key = False
    if sign_key is None and _a2_auto_sign_enabled():
        sign_key = _a2_default_sign_key(sender)
    if sign_key:
        seed = bytes.fromhex(open(sign_key, encoding="utf-8").read().strip())   # 32-byte hex seed
        _rec = _a2_sign(seed, {"sender": sender, "recipient": recipient, "topic": topic,
                               "kind": kind, "in_reply_to": in_reply_to, "body": body, "ts": ts})
        sig, pubkey = _rec["sig"], _rec["pubkey"]
    c = _conn(db)
    with c:
        cur = c.execute(
            "INSERT INTO messages(ts,sender,recipient,topic,kind,thread_id,in_reply_to,body,sig,pubkey) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, sender, recipient, topic, kind, thread_id, in_reply_to, body, sig, pubkey))
        rid = cur.lastrowid
        if not thread_id:                                   # no thread → its own id is the thread root
            c.execute("UPDATE messages SET thread_id=? WHERE id=?", (str(rid), rid))
    c.close()
    # in product mode the JSON mirror runs ONLY for a signed row (with sig/pubkey in it) — no unsigned message
    # may appear on the unenforced old channel. Unchanged in dev mode.
    if mirror and (sig or not _is_product(db)):
        _mirror_json(rid, sender, recipient, topic, kind, thread_id or str(rid), in_reply_to, body, ts, inbox_root,
                     sig=sig, pubkey=pubkey)
    return rid


def find_sds_record(sender, recipient, record_id, db=None):
    """The id of an EXISTING sds-envelope row from `sender` to `recipient` whose envelope carries `record_id`, else None.
    The idempotency key of docs/AGENT_BUS_SCHEMA.md §8.9: (sender, recipient, envelope.record_id). EVERY sds-envelope
    row of the pair is PARSED (by the same parser the insert path uses) and its envelope.record_id compared exactly:
    the key is the parsed value, never the JSON text. No text pre-filter — the same record_id has many valid JSON
    spellings (`"\u0073ha256:…"`), so a substring test on the stored body lets an escaped resend in as a new row; and
    a record_id quoted inside another record's text is not a match either. Cost: linear in the pair's sds-envelope
    rows. Read-only."""
    import sds_envelope
    if not (isinstance(record_id, str) and record_id.startswith("sha256:")):
        return None
    init(db)                                                  # a fresh bus has no `messages` table yet: that is "no row", not an error
    c = _conn(db)
    try:
        rows = c.execute("SELECT id, body FROM messages WHERE sender=? AND recipient=? AND kind=? ORDER BY id",
                         (sender, recipient, SDS_KIND)).fetchall()
    finally:
        c.close()
    for r in rows:
        try:
            _rec, env = sds_envelope.parse_framed(r["body"])
        except ValueError:
            continue
        if env.get("record_id") == record_id:
            return int(r["id"])
    return None


def _sds_annotate(rows, *, strict=False, admission_path=None):
    """v1.1 (partner arm steps 2+3): for every sds-envelope row `sds` = valid | invalid(<reason>) | unsigned | unverifiable(<reason>).
    The sender's registry key (A2, root-guarded) and the local admission file bind the sender to the admitted issuer.
    If the bus row's A2 signature is FORGED, the envelope is invalid(forged-sender). strict → non-valid sds rows are dropped from the
    OUTPUT (they stay in the DB, tail/thread sees them; no-deletion). Other kinds are untouched."""
    import sds_envelope
    adm = sds_envelope.load_admission(admission_path or os.environ.get("AGENT_BUS_SDS_ADMISSION"))
    out = []
    for m in rows:
        if m.get("kind") != SDS_KIND:
            out.append(m)
            continue
        if m.get("sig") and verify_sender(m) == "forged":
            st, why = "invalid", "forged-sender"
        else:
            st, why = sds_envelope.verify(m.get("body") or "", sender=m.get("sender"), admission=adm,
                                          registry_pubkey=_a2_load_registry_pubkey(m.get("sender", ""), KEYS_DIR))
        m["sds"] = sds_envelope.label(st, why)
        if not strict or st == "valid":
            out.append(m)
    return out


def _enforce_module():
    """OPTIONAL import of bus_enforce — a partial deploy (agent_bus.py only) does not stop the mail in dev
    mode. None if missing."""
    try:
        import bus_enforce
        return bus_enforce
    except ImportError:
        return None


def _product_hint_paths(db=None):
    """EVERY search location of the marker on the path WITHOUT the module. The same union that `bus_enforce.marker_paths`
    looks at — and that is the point: these two lists answer the same question, so they must move together.

    This function decides when `bus_enforce` CANNOT be imported, i.e. exactly in the situation
    the final guard exists for. An earlier version looked only at `abspath`, not `realpath` — measured on the
    published 1.5.3: the same DB refused delivery on its real path (fail-closed), but through a symlink
    it handed out the same letters. The symlink fix existed in the module, it just did not reach here: one
    decision, two implementations, and the weaker one opened."""
    dbp = db or DB
    paths = ["/etc/agent-bus/product_mode.on",
             os.path.join(os.path.dirname(os.path.realpath(dbp)), ".product_mode.on"),
             os.path.join(os.path.dirname(os.path.abspath(dbp)), ".product_mode.on")]
    # The BRIDGE (the site root) is also a search location: it always was on the module side, and the two lists MUST
    # MATCH. I did not notice this — the parity test I had just written failed on it first.
    for base in (os.environ.get("AGENT_BUS_DIR"), BRIDGE):
        if base:
            paths.append(os.path.join(os.path.realpath(base), ".product_mode.on"))
            paths.append(os.path.join(base, ".product_mode.on"))
    return list(dict.fromkeys(paths))


def _product_hint(db=None):
    """A product-mode signal recognizable even WITHOUT bus_enforce (env non-dev value / marker in ANY search location) →
    the missing module is then fail-closed, not silently dev."""
    raw = os.environ.get("AGENT_BUS_MODE", "").strip().lower()
    if raw and raw != "dev":
        return True
    return any(os.path.exists(p) for p in _product_hint_paths(db))


def _is_product(db=None):
    enf = _enforce_module()
    return (enf.mode(db=db) == "product") if enf is not None else _product_hint(db)


def recv(agent, *, mark=False, limit=_RECV_LIMIT, db=None, verify_sds=False, strict_sds=False, sds_admission=None):
    """The unread messages after the cursor (id>cursor), AT MOST `limit`. `mark`:
    the cursor moves to the last id of the returned PAGE → the next call gives the next page (cursor semantics preserved).
    B#3: with `mark`, read+mark run in ONE immediate transaction (write-lock upfront) → two concurrent recvs do not double-deliver.
    v1.4 + in product mode, enforcement runs in THE SAME transaction, BEFORE the cursor (/):
    a rejected row does not raise delivered_id, its read_at stays NULL, it gets an `enforce_reject:<reason>` audit row (→
    reconcile/replay sees it), the recv_mark audit skipped = number rejected; the seen-store is in the DB (/)."""
    init(db)
    enf = _enforce_module()
    if enf is None:
        if _product_hint(db):                                   # product mode signalled, module missing → fail-closed
            sys.stderr.write("recv refused: product mode signalled, but the bus_enforce module is missing (fail-closed; "
                             "the cursor did not move)\n")
            return []
        product = False
    else:
        product = enf.mode(db=db) == "product"
    rejected = []
    c = _conn(db)
    try:
        if mark:
            c.isolation_level = None                            # explicit transaction control for THIS connection
            c.execute("BEGIN IMMEDIATE")                        # B#3: write-lock upfront → read+mark serialized
        row = c.execute("SELECT last_seen_id FROM cursors WHERE agent=?", (agent,)).fetchone()
        last = row["last_seen_id"] if row else 0
        rows = c.execute("SELECT * FROM messages WHERE recipient=? AND id>? ORDER BY id LIMIT ?",
                         (agent, last, max(1, int(limit)))).fetchall()
        out = [dict(r) for r in rows]
        if _a2_strict():                                        # A2 opt-in strict (AGENT_BUS_REQUIRE_SIG=1): auth status of every row (default OFF → untouched)
            for _m in out:
                _m["auth"] = verify_sender(_m)
        if product:
            try:
                _store, _kept = enf.DbSeenStore(c, agent), []
                if mark:
                    _store.ensure()
                for _m in out:
                    _ok, _why = enf.check(_m, seen=_store, record=mark)   # peek: only checks, does NOT consume
                    if _ok:
                        _kept.append(_m)
                    else:
                        _m["enforce"] = _why                    # the row stays in the DB (no-deletion)
                        rejected.append(_m)
                if not mark and rejected:                       # the peek path also NAMES the rejection
                    for _m in rejected:                         # (idempotent: one audit entry per row)
                        have_row = c.execute("SELECT 1 FROM cursor_audit WHERE agent=? AND from_id=? AND op LIKE "
                                             "'enforce_reject%' LIMIT 1", (agent, _m["id"])).fetchone()
                        if not have_row:
                            _append_audit(c, agent, _m["id"], _m["id"], "enforce_reject:%s" % _m["enforce"], 1)
                    c.commit()
            except Exception as e:                              # never-throw, fail-closed, the cursor does NOT move
                if mark:
                    c.execute("ROLLBACK")
                sys.stderr.write("recv refused: enforcement error (%s) — fail-closed, the cursor did not move\n"
                                 % type(e).__name__)
                return []
            out = _kept
        if mark and rows:
            top = rows[-1]["id"]
            now = time.time_ns()
            if product:
                acc = [m["id"] for m in out]
                # delivered_id ONLY up to what was actually delivered (monotonic MAX); a rejected row's read_at stays NULL
                c.execute("INSERT INTO cursors(agent,last_seen_id,delivered_id) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
                          "last_seen_id=excluded.last_seen_id, delivered_id=MAX(cursors.delivered_id, excluded.delivered_id)",
                          (agent, top, max(acc) if acc else 0))
                c.executemany("UPDATE messages SET read_at=? WHERE id=? AND read_at IS NULL", [(now, i) for i in acc])
                for _m in rejected:                             # the chain records the rejection, not a delivery
                    _append_audit(c, agent, _m["id"], _m["id"], "enforce_reject:%s" % _m["enforce"], 1)
                _append_audit(c, agent, last, top, "recv_mark", len(rejected))
            else:
                # A1-L3: the mark-consuming recv DELIVERS → raises delivered_id (monotonic MAX) IN THE SAME transaction as the
                # cursor + the chain row (atomic, no TOCTOU; INV-A1.6). The non-mark recv (watcher poll) is a PEEK → never gets here.
                c.execute("INSERT INTO cursors(agent,last_seen_id,delivered_id) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
                          "last_seen_id=excluded.last_seen_id, delivered_id=MAX(cursors.delivered_id, excluded.delivered_id)",
                          (agent, top, top))
                c.execute("UPDATE messages SET read_at=? WHERE recipient=? AND read_at IS NULL AND id<=?",
                          (now, agent, top))
                # A1-L1: the recv-mark covers the page just DELIVERED (last→top == the returned rows) → skipped=0; hash-chained
                _append_audit(c, agent, last, top, "recv_mark", 0)
        if mark:
            c.execute("COMMIT")
    finally:
        c.close()
    if product:
        if rejected:                                            # the rejection is NOT silent (not even on peek)
            cnt = {}
            for _m in rejected:
                cnt[_m["enforce"]] = cnt.get(_m["enforce"], 0) + 1
            sys.stderr.write("# %d row(s) rejected (product mode): %s%s\n" % (
                len(rejected), ", ".join("%s×%d" % kv for kv in sorted(cnt.items())),
                " — recovery: reconcile/replay" if mark else ""))
            if mark:
                for _m in rejected:
                    enf.log_rejected(agent, _m, _m["enforce"])  # best-effort 
        # in product mode the sds-envelope is MANDATORILY checked and only valid ones remain (no 'unsigned' envelope)
        verify_sds, strict_sds = True, True
    if verify_sds or strict_sds:
        out = _sds_annotate(out, strict=strict_sds, admission_path=sds_admission)
    return out


def _strict_ack(db=None):
    """A1-L3: ack clamps to delivered_id (not to the high-water mark) — THE DEFAULT IN PRODUCT MODE.

    The MAJOR gate opened (the operator 2026-09-16 "yes, go ahead"; one arm's measured opinion: with the clamp on, THE DAMAGE
    ITSELF disappears — the cursor cannot step over undelivered mail, so `skipped_undelivered` never
    arises; the +11 test failures are all FIXTURE preconditions, not product code).
    Escape hatch: `AGENT_BUS_STRICT_ACK=0/false/no/off` — the FACT of switching it off goes into the round entry
    (`strict_ack: 0`), so it is not silent. In dev mode it stays opt-in (byte-identical to the vendored client).
    """
    raw = os.environ.get("AGENT_BUS_STRICT_ACK", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return _is_product(db)


def strict_ack_state(db=None):
    """(active, disabled_in_product_mode) — for the round entry, so that use of the escape hatch is visible."""
    active = _strict_ack(db)
    return active, bool(_is_product(db) and not active)


def _ack_target(c, agent, upto, db=None):
    """(current cursor, cursor after the ack) — the ack's clamp rule in one place (for the ack and the log-first preview)."""
    hi = c.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE recipient=?", (agent,)).fetchone()[0]
    row = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent=?", (agent,)).fetchone()
    base = row["last_seen_id"] if row else 0
    cap = (row["delivered_id"] if row else 0) if _strict_ack(db) else hi   # strict → up to delivered; default → high-water
    return base, max(base, min(int(upto), cap))                  # forward-only + (strict: delivered / default: high-water) clamp


def ack_preview(agent, upto, db=None):
    """v1.5 SSH log-first: (cursor now, cursor after the ack) — WITHOUT CALLING ack, with the same rule."""
    init(db)
    c = _conn(db)
    try:
        return _ack_target(c, agent, upto, db=db)
    finally:
        c.close()


def audit_head(agent, db=None):
    """Head of the agent's hash-chained cursor_audit chain: (seq, row_hash) — 0/None if there is no row yet.

    54Z: the log alone does not refute the SELF-REPORTED numbers (pending/next_id) of the round entry;
    the anchor makes them comparable afterwards with the bus's OWN hash-chained log (one of the two records is lying).
    """
    init(db)
    c = _conn(db)
    try:
        r = c.execute("SELECT seq,row_hash FROM cursor_audit WHERE agent=? ORDER BY id DESC LIMIT 1", (agent,)).fetchone()
        return (r["seq"], r["row_hash"]) if r else (0, None)
    finally:
        c.close()


# an enforcement rejection can be PERMANENT or TRANSIENT. The water level (delivered_id)
# may step only over a PERMANENTLY undeliverable row; a transient one (clock running ahead, key not yet registered) must be waited for,
# otherwise a clock skew or an ongoing key rollout permanently swallows legitimate mail.
TRANSIENT_REJECT = ("future-ts",)          # expires by itself (the sender's clock runs ahead)
# D: `forged` is PERMANENT by default (otherwise one garbage row would pin the water level forever = DoS). The partner arm's
# key-rollout case is real, but it is an OPERATOR window: while /etc/agent-bus/key_rollout.on (or .key_rollout.on next to the DB)
# is present, `forged` counts as transient — a deliberate, visible, reversible switch.
ROLLOUT_MARKERS = ("/etc/agent-bus/key_rollout.on",)
FORGED_GRACE_S = int(os.environ.get("AGENT_BUS_FORGED_GRACE_S", str(24 * 3600)))


def _key_rollout(db=None):
    if any(os.path.exists(p) for p in ROLLOUT_MARKERS):
        return True
    try:
        return os.path.exists(os.path.join(os.path.dirname(os.path.abspath(db or DB)), ".key_rollout.on"))
    except Exception:
        return False


def _reject_age_s(m):
    """The row's age in SECONDS from its own `ts` — or None if the `ts` is unusable for an age limit.

    7/1: `ts` is the SENDER's field, and for a `forged` row the question is precisely whether it is credible.
    A future `ts` gave a NEGATIVE age → the grace stayed true forever → the row permanently pinned the water level.
    So: a future (beyond clock skew) or unparseable `ts` → None = NOT fresh, hence not transient.
    """
    try:
        raw = int(m.get("ts") or 0)
    except (TypeError, ValueError):
        return None
    if raw <= 0:
        return None
    secs = raw / 1e9 if raw > 1e12 else raw
    age = time.time() - secs
    if age < -_CLOCK_SKEW_S:                     # a "fresh" row from the future gets no grace period
        return None
    return max(0.0, age)


def pending_blocking_ids(agent, db=None):
    """Rows above the cursor that are deliverable TODAY OR transiently rejected (so they may still come out). -> [id]"""
    init(db)
    c = _conn(db)
    try:
        cur = (c.execute("SELECT last_seen_id FROM cursors WHERE agent=?", (agent,)).fetchone() or {"last_seen_id": 0})["last_seen_id"]
        rows = [dict(r) for r in c.execute("SELECT * FROM messages WHERE recipient=? AND id>? AND kind IS NOT 'replay' "
                                           "ORDER BY id LIMIT ?", (agent, cur, _RECV_LIMIT))]
    finally:
        c.close()
    if not _product_hint(db):
        return [r["id"] for r in rows]
    try:
        import bus_enforce as enf
    except Exception:
        return [r["id"] for r in rows]                 # no enforcement module: fail-closed (we would rather wait)
    rollout = _key_rollout(db)
    out = []
    for m in rows:
        try:
            ok, why = enf.check(m, seen=None, record=False)
        except Exception:
            # 7/2: an UNPARSEABLE row would fail on recv too, so it can NEVER be delivered —
            # if we treated it as blocking, a single garbage row could stop the water level forever (DoS).
            continue                                   # does not block; the lifeboat (reconcile) still lists it
        # `forged` = the sender's key is not (yet) in the registry OR the signature is bad. The first is TRANSIENT (key rollout),
        # the second PERMANENT — we cannot tell them apart from here, so a TIME LIMIT: transient up to FORGED_GRACE_S (default 24 h,
        # or unlimited with a rollout marker), permanent afterwards. So fresh mail is protected, while an old
        # garbage row does not pin the water level forever.
        transient = list(TRANSIENT_REJECT)
        if why == "forged":
            age = _reject_age_s(m)
            if rollout or (age is not None and age <= FORGED_GRACE_S):
                transient.append("forged")
        if ok or why in transient:
            out.append(m["id"])
    return out


def audit_export(agent, from_seq: int = 0, db=None) -> list:
    """The agent's hash-chained cursor_audit rows (machine-readable, portable form) — for COMPARISON with the notary log.

    54Z's open item: the `pending`/`next_id` numbers of the round entry are the bus's SELF-REPORT. This export
    makes them comparable on the other machine: `bus_notary.reconcile(..., bus_audit=...)` flags a contradiction between the two.
    """
    init(db)
    c = _conn(db)
    try:
        return [{"seq": r["seq"], "ts": r["ts"], "agent": r["agent"], "from_id": r["from_id"], "to_id": r["to_id"],
                 "op": r["op"], "skipped_undelivered": r["skipped_undelivered"],
                 "prev_row_hash": r["prev_row_hash"], "row_hash": r["row_hash"]}
                for r in c.execute("SELECT * FROM cursor_audit WHERE agent=? AND seq>=? ORDER BY id", (agent, from_seq))]
    finally:
        c.close()


def audit_chain_verify(rows: list, start_row_hash: str | None = None) -> dict:
    """Self-check of the exported audit chain: contiguous seq + hash chain. -> {ok, errors[], slice_start_seq, anchored}

    an internally intact chain is NOT by itself a claim about the full chain — exactly the
    class of error we already closed twice in the notary `verify` (`unverified_tail`, then `slice_start_seq`/`anchored`).
    So this one also states where the slice starts and whether it is ANCHORED: it starts from GENESIS
    (seq 0, prev = GENESIS), or the caller supplied a `start_row_hash` known out of band. The counterexample was in our own
    module: the in-DB `audit_verify()` always starts from `_GENESIS` — that was lost on the exported path.
    """
    errors, prev = [], None
    for i, r in enumerate(rows):
        try:
            rh = _audit_row_hash(r["seq"], r["ts"], r["agent"], r["op"], r["from_id"], r["to_id"],
                                 r["skipped_undelivered"], r["prev_row_hash"])
        except Exception as e:
            errors.append({"seq": r.get("seq"), "error": "hash: %s" % type(e).__name__}); continue
        if rh != r.get("row_hash"):
            errors.append({"seq": r["seq"], "error": "row_hash mismatch"})
        if prev is not None:
            if r["prev_row_hash"] != prev["row_hash"]:
                errors.append({"seq": r["seq"], "error": "chain break"})
            if r["seq"] != prev["seq"] + 1:
                errors.append({"seq": r["seq"], "error": "seq gap"})
        prev = r
    first = rows[0] if rows else None
    if first is not None:
        if start_row_hash is not None:
            anchored = first.get("prev_row_hash") == start_row_hash
            if not anchored:
                errors.append({"seq": first.get("seq"), "error": "chain does not continue from the given start_row_hash"})
        else:
            # `ok` states the chain's INTEGRITY (as in the notary `verify`), the anchor is carried by a separate field, and the
            # CONSUMER (reconcile / CLI) decides on it — so a partial-slice export remains checkable.
            anchored = first.get("seq") == 0 and first.get("prev_row_hash") == _GENESIS
    else:
        anchored = False
    # (open probe, now closed): the NAME `ok` meant two different things. The DB path
    # (`audit_verify`) always starts from GENESIS, so there `ok` = intact AND anchored; on the exported path, however,
    # it only stated integrity — same field, two guarantees. Whoever reads only `ok` gets a false green
    # for an unanchored slice. From now on the name carries the STRICTER meaning, and the slice check
    # is still available through `chain_ok` (that is what `reconcile` uses).
    return {"ok": (not errors) and bool(anchored), "chain_ok": not errors, "errors": errors,
            "rows": len(rows), "slice_start_seq": (first or {}).get("seq"), "anchored": bool(anchored)}


def _permanent_rejects(agent, ids, db=None):
    """The ids among the given ones that enforcement PERMANENTLY rejects (can never be delivered). -> set"""
    ids = [int(i) for i in (ids or [])]
    if not ids or not _product_hint(db):
        return set()
    try:
        import bus_enforce as enf
    except Exception:
        return set()
    c = _conn(db)
    try:
        q = ",".join("?" * len(ids))
        rows = [dict(r) for r in c.execute("SELECT * FROM messages WHERE recipient=? AND id IN (%s)" % q, tuple([agent] + ids))]
    finally:
        c.close()
    rollout, out = _key_rollout(db), set()
    for m in rows:
        try:
            ok, why = enf.check(m, seen=None, record=False)
        except Exception:
            out.add(m["id"])                       # unparseable row: would fail on recv too -> permanent
            continue
        if ok:
            continue
        transient = list(TRANSIENT_REJECT)
        if why == "forged":
            age = _reject_age_s(m)
            if rollout or (age is not None and age <= FORGED_GRACE_S):
                transient.append("forged")
        if why not in transient:
            out.add(m["id"])
    return out

def mark_delivered(agent, ids, db=None):
    """Delivery marking for REMOTE (SSH) delivery: read_at + delivered_id (monotonic MAX) — the CURSOR does NOT move.

    peek delivery (recv mark=False) used not to raise delivered_id, so
    (1) the local lifeboat (reconcile/skipped_undelivered) reported a full window even for an honest round, and
    (2) the AGENT_BUS_STRICT_ACK clamp froze the remote cursor. The cursor is still moved ONLY by ack.
    """
    ids = [int(i) for i in (ids or []) if isinstance(i, int) and not isinstance(i, bool) and i > 0]
    if not ids:
        return 0
    del_top = None
    init(db)
    # 7/4: the remote side's ack is NOT proof. If it reported as delivered an id that
    # enforcement PERMANENTLY rejects (e.g. stale-ts), the read_at marking + the `remote_delivered` row would
    # FALSELY close the open enforce_reject trace. Such ids are removed and recorded in a separate row.
    refused = sorted(_permanent_rejects(agent, ids, db=db))
    if refused:
        ids = [i for i in ids if i not in set(refused)]
        cr = _conn(db)
        try:
            with cr:
                for _i in refused:
                    _append_audit(cr, agent, _i, _i, "remote_delivered_refused", 0)
        finally:
            cr.close()
    if not ids:
        return 0
    now = int(time.time())
    top = max(ids)
    # "unread" is NOT the same as "deliverable" — a row rejected in product mode
    # (e.g. stale-ts) stays unread but can never be delivered. The water level is the top of the DELIVERABLE prefix, so
    # we query the deliverable set with the same filter recv uses (BEFORE the transaction).
    try:                                               # BESIDES the deliverable ones, the transiently rejected also block
        pend = pending_blocking_ids(agent, db=db)
    except Exception:
        pend = None
    c = _conn(db)
    try:
        c.execute("BEGIN IMMEDIATE")
        c.executemany("UPDATE messages SET read_at=? WHERE id=? AND recipient=? AND read_at IS NULL",
                      [(now, i, agent) for i in ids])
        # the delivered_id HIGH-WATER invariant (INV-A1.8) can only be raised up to the top of the CONTIGUOUS
        # delivered prefix — subset delivery (MAX) would have let the strict clamp through.
        if pend is None:                                       # the filtered query failed: fail-closed, keep the raw unread
            row = c.execute("SELECT MIN(id) AS m FROM messages WHERE recipient=? AND read_at IS NULL", (agent,)).fetchone()
            first_unread = row["m"] if row and row["m"] is not None else None
        else:                                                  # the smallest among the DELIVERABLE and still UNREAD rows
            unread = {r["id"] for r in c.execute("SELECT id FROM messages WHERE recipient=? AND read_at IS NULL", (agent,))}
            left = [i for i in pend if i in unread and i not in set(ids)]
            first_unread = min(left) if left else None
        top_row = c.execute("SELECT MAX(id) AS x FROM messages WHERE recipient=?", (agent,)).fetchone()
        prefix_top = (first_unread - 1) if first_unread is not None else (top_row["x"] if top_row and top_row["x"] else 0)
        # C: MAX would have kept the old water level even above a LATER-arrived, lower-id unread message
        # -> delivered_id is the RECOMPUTED value of the CONTIGUOUS prefix (read_at is the truth).
        c.execute("INSERT INTO cursors(agent,last_seen_id,delivered_id) VALUES(?,0,?) ON CONFLICT(agent) DO UPDATE SET "
                  "delivered_id=excluded.delivered_id", (agent, prefix_top))
        # the FACT of delivery is a separate, hash-chained row -> an earlier enforce_reject "closes" on it
        for _i in sorted(set(ids)):                        # ID-LEVEL row; a range would also have "closed" the intermediate,
            _append_audit(c, agent, _i, _i, "remote_delivered", 0)   # NOT delivered ids (false silence)
        c.execute("COMMIT")
        return len(ids)
    finally:
        c.close()


def cursor_of(agent, db=None):
    """The agent's cursor (last_seen_id; 0 if none yet)."""
    init(db)
    c = _conn(db)
    try:
        row = c.execute("SELECT last_seen_id FROM cursors WHERE agent=?", (agent,)).fetchone()
        return row["last_seen_id"] if row else 0
    finally:
        c.close()


def ack(agent, upto, db=None):
    """Move the cursor forward. HARDENED: the target is `max(current, min(upto, MAX(id)))` → ONLY FORWARD
    and NEVER beyond real messages. A1-L3 strict (opt-in): clamps to delivered_id INSTEAD of the high-water mark → a one-step
    `ack --upto BIG` cannot jump over UNDELIVERED mail (against naive/one-step delivery denial; the 2-step one is the remote tier)."""
    init(db)
    c = _conn(db)
    with c:
        base, tgt = _ack_target(c, agent, upto, db=db)
        if tgt > base:
            # A1-L1: an ack is NOT delivery — UNREAD rows (read_at IS NULL) in the (base,tgt] range = messages potentially
            # skipped without delivery. A large `skipped_undelivered` on an ack row = a suspicious jump (tamper-evident).
            skipped = c.execute("SELECT COUNT(*) FROM messages WHERE recipient=? AND id>? AND id<=? AND read_at IS NULL",
                                (agent, base, tgt)).fetchone()[0]
            _append_audit(c, agent, base, tgt, "ack", skipped)
        c.execute("INSERT INTO cursors(agent,last_seen_id) VALUES(?,?) "
                  "ON CONFLICT(agent) DO UPDATE SET last_seen_id=excluded.last_seen_id", (agent, tgt))
        c.execute("UPDATE messages SET read_at=COALESCE(read_at,?) WHERE recipient=? AND id<=?",
                  (time.time_ns(), agent, tgt))
    c.close()


def reconcile(agent, db=None):
    """A1-L2 (RECOVERY, advisory): messages skipped WITHOUT delivery. Since A1-L3 it is EXACT (instead of the over-listing audit-jump
    heuristic): the `delivered_id < id <= cursor` range = messages the cursor moved past but that were NEVER delivered
    (mark-only delivered_id; INV-A1.8). Excludes those ALREADY redelivered (kind='replay', in_reply_to=orig_id) and the
    replay messages themselves. ONLY lists."""
    init(db)
    c = _conn(db)
    try:
        replayed = {r[0] for r in c.execute(
            "SELECT in_reply_to FROM messages WHERE kind='replay' AND in_reply_to IS NOT NULL")}
        row = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent=?", (agent,)).fetchone()
        cursor = row["last_seen_id"] if row else 0
        delivered = row["delivered_id"] if row else 0
        out = []
        for m in c.execute("SELECT * FROM messages WHERE recipient=? AND id>? AND id<=? AND kind IS NOT 'replay' "
                           "ORDER BY id", (agent, delivered, cursor)):
            if m["id"] in replayed:
                continue
            out.append(dict(m))
        # rows REJECTED in product mode (enforce_reject audit) are candidates even if a
        # later accepted row raised delivered_id above them — otherwise the lifeboat would be blind to them.
        have = {m["id"] for m in out}
        extra = {}
        # an enforce_reject row is OPEN until there is a later row recording delivery for the same id
        # (recv_mark / remote_delivered) — otherwise mail delivered properly later would be falsely accused.
        arows = [dict(a) for a in c.execute("SELECT id, from_id, to_id, op FROM cursor_audit WHERE agent=? ORDER BY id",
                                            (agent,))]
        for i, a in enumerate(arows):
            if not str(a["op"]).startswith("enforce_reject"):
                continue
            mid = a["from_id"]
            # ONLY actual delivery closes it (remote_delivered). A recv_mark row's range also covers the rejected id,
            # although it did NOT deliver it — that would create false SILENCE instead of a false accusation.
            closed = any(str(b["op"]) == "remote_delivered" and b["from_id"] <= mid <= b["to_id"] for b in arows[i + 1:])
            if not closed:
                extra.setdefault(mid, a["op"].partition(":")[2] or "enforce_reject")
        for mid in sorted(set(extra) - have - replayed):
            m = c.execute("SELECT * FROM messages WHERE id=? AND recipient=? AND kind IS NOT 'replay'",
                          (mid, agent)).fetchone()          # the audit row is the signal, not read_at (ack sets everything)
            if m:
                out.append({**dict(m), "enforce": extra[mid]})
        for m in out:
            if m["id"] in extra:
                m["enforce"] = extra[m["id"]]
        out.sort(key=lambda m: m["id"])
    finally:
        c.close()
    return out


def replay(agent, *, commit=False, limit=100, db=None):
    """A1-L2: REDELIVERY of skipped-undelivered messages — NOT a cursor rewind (the forward-only invariant
    is load-bearing: L1 tamper-evidence + remote I4(a) monotonic seq anchor), but a NEW message (from=system, kind='replay',
    in_reply_to=orig_id, new id>cursor). Thanks to no-deletion the original is there to copy. `commit=False` → dry-run
    (only shows what it would do); the actual replay is OPERATOR-INVOKED (same-uid locally → replay-flood risk)."""
    cands = reconcile(agent, db=db)[:max(0, int(limit))]
    c0 = _conn(db)                                             # IDEMPOTENCE — what we already replayed is not repeated
    try:
        already = set()
        for a in c0.execute("SELECT from_id, to_id FROM cursor_audit WHERE agent=? AND op='replay'", (agent,)):
            already.add(a["from_id"])
            already.add(a["to_id"])                            # 7/3: the COPY cannot be replayed again either
    finally:                                                   # (otherwise an undelivered copy would spawn a copy: flood)
        c0.close()
    cands = [m for m in cands if m["id"] not in already]
    if _product_hint(db):                                      # a PERMANENTLY rejected row (e.g. stale-ts) would fail again
        try:
            import bus_enforce as enf
            cands = [m for m in cands if enf.check(dict(m), seen=None, record=False)[0]
                     or enf.check(dict(m), seen=None, record=False)[1] in TRANSIENT_REJECT]
            _filtered = True
        except Exception as _e:
            # This branch was `pass`: if the gate cannot run, a PERMANENTLY rejected row can get back into the
            # lifeboat — silently. The ABSENCE of filtering is a third state, not "fine".
            # (measured): my first fix put the `warning` ONLY on the dry branch,
            # but the DAMAGE happens on the commit branch (a signed copy of the permanently rejected row enters the DB),
            # and there it stayed silent. Two changes: (a) the signal also goes into the commit branch's response, (b) IN PRODUCT MODE
            # a missing gate is FAIL-CLOSED — a lifeboat without a gate writes no durable state. The dry run
            # (`commit=False`) still shows WHAT it would do, so there is an escape route for diagnosis.
            _filtered = False
            _lifeboat_warn = "enforce_filter_unavailable:%s" % _e.__class__.__name__
    if not commit:
        _out = {"committed": False, "would_replay": [{"orig": m["id"], "from": m["sender"]} for m in cands]}
        if locals().get("_lifeboat_warn"):
            _out["warning"] = _lifeboat_warn
        return _out
    done = []
    product = _product_hint(db)
    if locals().get("_lifeboat_warn") and product:
        # fail-closed: the gate did not run, so we do not know whether the row is PERMANENTLY rejected
        return {"committed": False, "replayed": [], "warning": _lifeboat_warn,
                "refused": "the enforcement gate could not run, so the lifeboat did not write anything "
                           "(product mode); run with commit=False to see what it would replay"}
    for m in cands:
        if product and m.get("sig"):
            # in product mode the replay carries the ORIGINAL, SIGNED row over
            # intact (new id, same signed fields) — enforcement dropped the wrapped `system` message as
            # `unsigned-downgrade`, so the lifeboat was "lists but does not deliver". The signed byte image (v,sender,recipient,
            # topic,kind,in_reply_to,body,ts) stays UNCHANGED, so the signature remains valid.
            cc = _conn(db)
            try:                                   # (TOCTOU): the COPY and the log row in ONE write-locked transaction
                cc.execute("BEGIN IMMEDIATE")      # -> of two concurrent operator replays, the second does not duplicate
                if cc.execute("SELECT 1 FROM cursor_audit WHERE agent=? AND op='replay' AND from_id=?",
                              (agent, m["id"])).fetchone():
                    cc.execute("ROLLBACK")
                    continue
                cur = cc.execute("INSERT INTO messages(sender,recipient,kind,topic,thread_id,in_reply_to,body,ts,read_at,"
                                 "sig,pubkey) VALUES(?,?,?,?,?,?,?,?,NULL,?,?)",
                                 (m["sender"], agent, m["kind"], m["topic"], m["thread_id"], m["in_reply_to"],
                                  m["body"], m["ts"], m["sig"], m["pubkey"]))
                new_id = cur.lastrowid
                _append_audit(cc, agent, m["id"], new_id, "replay", 0)
                cc.execute("COMMIT")
            except sqlite3.IntegrityError:         # ux_replay_once: someone got there first -> we do not produce a second
                cc.execute("ROLLBACK")
                continue
            finally:
                cc.close()
            done.append({"orig": m["id"], "new": new_id, "mode": "signed-copy"})
            continue
        body = "[replay #%d ← %s] %s" % (m["id"], m["sender"], m["body"] or "")
        new_id = send("system", agent, body, topic=m["topic"] or "", kind="replay",
                      thread_id=m["thread_id"], in_reply_to=m["id"], db=db)
        cc = _conn(db)
        with cc:
            _append_audit(cc, agent, m["id"], new_id, "replay", 0)   # the replay event also enters the hash chain
        cc.close()
        done.append({"orig": m["id"], "new": new_id})
    _res = {"committed": True, "replayed": done}
    if locals().get("_lifeboat_warn"):          # dev mode: passes, but NOT silently
        _res["warning"] = _lifeboat_warn
    return _res


def audit(agent=None, *, limit=50, db=None):
    """A1-L1: the cursor-move log (latest rows). agent narrows; None = all."""
    init(db)
    c = _conn(db)
    if agent:
        rows = c.execute("SELECT * FROM cursor_audit WHERE agent=? ORDER BY id DESC LIMIT ?", (agent, limit)).fetchall()
    else:
        rows = c.execute("SELECT * FROM cursor_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in reversed(rows)]


def audit_verify(agent=None, db=None):
    """A1-L1 tamper EVIDENCE (FAIL-CLOSED): checks the per-agent hash chain. Whoever moved the cursor and rewrote/deleted
    the log (NOT a determined same-uid attacker, but accidental/naive/inconsistent) FAILS here: chain break
    (prev_row_hash≠previous row_hash) OR row_hash recomputation mismatch → ok=False. Never-throw → dict; an inserted row is DETECTED, not a DoS.
    (A determined same-uid attacker re-chains consistently → only an external witness/remote tier protects against that; see the recalibration above.)"""
    init(db)
    out = {"ok": True, "checked": 0, "pre_chain": 0, "problems": []}
    try:
        c = _conn(db)
        try:
            agents = ([agent] if agent
                      else [r[0] for r in c.execute("SELECT DISTINCT agent FROM cursor_audit ORDER BY agent")])
            for ag in agents:
                # fix: LEGACY (pre-chain, row_hash IS NULL) rows are NOT checked (not flagged as tamper,
                # only counted) — the chain runs from GENESIS from the first CHAINED (row_hash NOT NULL) row. No-deletion: legacy rows stay.
                out["pre_chain"] += c.execute(
                    "SELECT COUNT(*) FROM cursor_audit WHERE agent=? AND row_hash IS NULL", (ag,)).fetchone()[0]
                prev = _GENESIS
                for r in c.execute("SELECT * FROM cursor_audit WHERE agent=? AND row_hash IS NOT NULL ORDER BY id", (ag,)):
                    out["checked"] += 1
                    if r["prev_row_hash"] != prev:
                        out["problems"].append("%s seq=%s: chain break (prev_row_hash≠previous) — inserted/deleted row" % (ag, r["seq"]))
                        break
                    rh = _audit_row_hash(r["seq"], r["ts"], ag, r["op"], r["from_id"], r["to_id"], r["skipped_undelivered"], r["prev_row_hash"])
                    if rh != r["row_hash"]:
                        out["problems"].append("%s seq=%s: row_hash mismatch — rewritten row" % (ag, r["seq"]))
                        break
                    prev = r["row_hash"]
        finally:
            c.close()
    except sqlite3.Error as e:
        out["problems"].append("db: %s" % e)
    out["ok"] = not out["problems"]
    return out


def tail(agent=None, *, limit=20, db=None):
    init(db)
    c = _conn(db)
    if agent:
        rows = c.execute("SELECT * FROM messages WHERE recipient=? OR sender=? ORDER BY id DESC LIMIT ?",
                         (agent, agent, limit)).fetchall()
    else:
        rows = c.execute("SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in reversed(rows)]


def thread(thread_id, db=None):
    init(db)
    c = _conn(db)
    rows = c.execute("SELECT * FROM messages WHERE thread_id=? ORDER BY id", (str(thread_id),)).fetchall()
    c.close()
    return [dict(r) for r in rows]


# ── BUS-TRANSPORT SEAM (remote-tiering, 2026-06-21) — ABOVE the frozen contract (I1) ─────
# The seam of the tier-segmented AgentBus (Pro=offline / Enterprise=remote). The CONTRACT IS UNCHANGED:
# the schema (MESSAGE_COLUMNS/CURSOR_COLUMNS), the CLI, the JSON mirror and the cursor semantics are BYTE-IDENTICAL — ONLY the
# transport underneath is swapped (like the trust-provider seam). The remote security frame: one arm's DESIGN_remote_agentbus.md
# (I1–I8 + 2.3 go/no-go). Local is the default and NEVER opens a network (I7/I8: offline guarantee intact).
from abc import ABC, abstractmethod


class BusTransport(ABC):
    """The bus transport abstraction. The methods mirror the module-level API (vendored clients build on it)."""
    @abstractmethod
    def send(self, sender, recipient, body, *, topic="", kind="msg", thread_id=None, in_reply_to=None, mirror=True, sign_key=None, presigned=None): ...
    @abstractmethod
    def recv(self, agent, *, mark=False): ...
    @abstractmethod
    def ack(self, agent, upto): ...
    @abstractmethod
    def tail(self, agent=None, *, limit=20): ...
    @abstractmethod
    def thread(self, thread_id): ...
    @abstractmethod
    def verify_schema(self): ...


class LocalBusTransport(BusTransport):
    """Pro / DEFAULT — today's shared-disk SQLite `bus.db` + JSON mirror; behaviour 1:1. NEVER opens a network.
    The actual logic lives in the module-level functions (this is the Local implementation); this facade only binds `db`."""
    def __init__(self, db=None, inbox_root=None):
        self.db = db
        self.inbox_root = inbox_root                        # forward-looking seam parameter (today _mirror_json uses INBOX_ROOT)

    def send(self, sender, recipient, body, *, topic="", kind="msg", thread_id=None, in_reply_to=None, mirror=True, sign_key=None, presigned=None):
        return send(sender, recipient, body, topic=topic, kind=kind, thread_id=thread_id,
                    in_reply_to=in_reply_to, db=self.db, mirror=mirror, inbox_root=self.inbox_root, sign_key=sign_key,
                    presigned=presigned)  # D#6: actually wired in

    def recv(self, agent, *, mark=False, limit=_RECV_LIMIT):
        return recv(agent, mark=mark, limit=limit, db=self.db)

    def ack(self, agent, upto):
        return ack(agent, upto, db=self.db)

    def tail(self, agent=None, *, limit=20):
        return tail(agent, limit=limit, db=self.db)

    def thread(self, thread_id):
        return thread(thread_id, db=self.db)

    def verify_schema(self):
        return verify_schema(db=self.db)


class RemoteBusTransport(BusTransport):
    """Enterprise (sovereign) — mTLS relay client to the CUSTOMER-side relay (remote/home-office coordination).
    NOT YET IMPLEMENTED: waiting for the security frame to be finalized
    and for the operator's green light — node admission on the vendor control plane (attestation + entitlement-gated,
    HSM root, fail-closed), E2E coordination (the vendor does not decrypt), per-sender signed sequence. UNTIL DONE: opens NO
    network; the client falls back to LocalBusTransport (I7 fail-safe degradation)."""
    def __init__(self, *a, **k):
        raise NotImplementedError(
            "RemoteBusTransport: the remote AgentBus is waiting for the security frame to be finalized + the operator's green light "
            "(2.3 go/no-go; distributed_bus vocabulary lockstep). Until then LocalBusTransport (Pro, offline, zero network).")

    def send(self, *a, **k): raise NotImplementedError
    def recv(self, *a, **k): raise NotImplementedError
    def ack(self, *a, **k): raise NotImplementedError
    def tail(self, *a, **k): raise NotImplementedError
    def thread(self, *a, **k): raise NotImplementedError
    def verify_schema(self): raise NotImplementedError


def default_transport():
    """The current (Pro) transport: LocalBusTransport. Tier selection (Local/Remote) will later be up to the connected SKU + entitlement
    (I5: valid Enterprise + distributed_bus → Remote; otherwise fail-safe Local). TODAY always Local, zero network."""
    return LocalBusTransport()


def _scrub(s):
    """R3-A3: terminal control characters (ANSI ESC, CR, NL, other C0/C1) are FILTERED OUT of CLI display — otherwise an
    attacker-sent body/sender/topic with `\\x1b[…`/`\\r` could OVERWRITE a `tail`/`recv`/`thread` line and forge a FALSE
    '[operator→… APPROVED]' entry on the operator's terminal (bus=DATA, display must not mutate)."""
    return "".join(ch if (ch >= " " and ch != "\x7f" and not (0x80 <= ord(ch) <= 0x9f)) else "·"
                   for ch in (s or ""))


def _fmt(m):
    rd = "·read" if m.get("read_at") else ""
    if m.get("sds"):
        rd += " sds:" + _scrub(m["sds"])
    return "[#%s %s→%s %s/%s%s] %s" % (m["id"], _scrub(m["sender"]), _scrub(m["recipient"]),
                                        _scrub(m.get("topic")) or "-", _scrub(m.get("kind")) or "-", rd,
                                        _scrub((m["body"] or "")[:200]))


def main(argv=None):
    p = argparse.ArgumentParser(prog="agent_bus")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    s = sub.add_parser("send")
    s.add_argument("--from", dest="sender", required=True); s.add_argument("--to", dest="recipient", required=True)
    s.add_argument("--body", required=True); s.add_argument("--topic", default=""); s.add_argument("--kind", default="msg")
    s.add_argument("--thread", default=None); s.add_argument("--reply", type=int, default=None)
    s.add_argument("--no-mirror", action="store_true")
    s.add_argument("--sign-key", dest="sign_key", default=None, help="A2: path to a 32-byte hex Ed25519 seed → the send is signed (optional)")
    r = sub.add_parser("recv"); r.add_argument("--agent", required=True); r.add_argument("--mark", action="store_true")
    r.add_argument("--limit", type=int, default=_RECV_LIMIT)
    r.add_argument("--verify-sds", dest="verify_sds", action="store_true", help="v1.1: check sds-envelope rows")
    r.add_argument("--strict-sds", dest="strict_sds", action="store_true", help="v1.1: only valid sds-envelope rows (other kinds stay)")
    r.add_argument("--sds-admission", dest="sds_admission", default=None, help="v1.1: local admission file (or AGENT_BUS_SDS_ADMISSION)")
    a = sub.add_parser("ack"); a.add_argument("--agent", required=True); a.add_argument("--upto", type=int, required=True)
    t = sub.add_parser("tail"); t.add_argument("--agent", default=None); t.add_argument("--limit", type=int, default=20)
    th = sub.add_parser("thread"); th.add_argument("--id", required=True)
    v = sub.add_parser("verify"); v.add_argument("--json", action="store_true")
    au = sub.add_parser("audit"); au.add_argument("--agent", default=None); au.add_argument("--limit", type=int, default=50)
    sub.add_parser("doctor")                                   # v1.4: product-profile status (loud warning in dev mode)
    avf = sub.add_parser("audit-verify"); avf.add_argument("--agent", default=None); avf.add_argument("--json", action="store_true")
    # the enforced policy ("incomplete evidence") used to send the operator to a NON-EXISTENT
    # command — no shipped command produced the `--bus-audit` file. Here it is.
    axp = sub.add_parser("audit-export", help="the bus's hash-chained cursor_audit rows as JSONL (input for bus_notary --bus-audit)")
    axp.add_argument("--agent", required=True)
    axp.add_argument("--from-seq", dest="from_seq", type=int, default=0)
    rc = sub.add_parser("reconcile"); rc.add_argument("--agent", required=True)  # A1-L2: list of skipped-undelivered
    rp = sub.add_parser("replay"); rp.add_argument("--agent", required=True)
    rp.add_argument("--commit", action="store_true", help="actually redeliver (otherwise dry-run); OPERATOR-invoked")
    rp.add_argument("--limit", type=int, default=100)
    args = p.parse_args(argv)

    if args.cmd == "init":
        init(); print("bus init: %s" % DB)
    elif args.cmd == "send":
        try:                                                    # R3-I#3/D#1: CLI never-throw — a gate ValueError is never a raw traceback
            rid = send(args.sender, args.recipient, args.body, topic=args.topic, kind=args.kind,
                       thread_id=args.thread, in_reply_to=args.reply, mirror=not args.no_mirror, sign_key=args.sign_key)
        except ValueError as e:
            sys.stderr.write("send refused: %s\n" % e)
            return 2
        print("sent #%d (%s→%s)" % (rid, args.sender, args.recipient))
    elif args.cmd == "recv":
        for m in recv(args.agent, mark=args.mark, limit=args.limit, verify_sds=args.verify_sds,
                      strict_sds=args.strict_sds, sds_admission=args.sds_admission):
            print(_fmt(m))
    elif args.cmd == "ack":
        ack(args.agent, args.upto); print("ack %s → #%d" % (args.agent, args.upto))
    elif args.cmd == "tail":
        for m in tail(args.agent, limit=args.limit):
            print(_fmt(m))
    elif args.cmd == "thread":
        for m in thread(args.id):
            print(_fmt(m))
    elif args.cmd == "verify":
        res = verify_schema()
        if args.json:
            print(json.dumps(res, ensure_ascii=False))
        else:
            tag = "OK" if res["ok"] else "DRIFT"
            print("[%s] schema v%s (db pinned: %s)" % (tag, res["schema_version"], res["pinned"]))
            for pr in res["problems"]:
                print("  ! " + pr)
            if res.get("added_columns"):
                print("  + additive columns: " + ", ".join(res["added_columns"]))
        return 0 if res["ok"] else 1
    elif args.cmd == "doctor":                                  # v1.4: enforcement status
        bus_enforce = _enforce_module()
        if bus_enforce is None:
            sys.stderr.write("!!! bus_enforce module missing — enforcement not available (product signal: %s)\n"
                             % ("yes, recv is fail-closed" if _product_hint() else "none"))
            return 1
        ok, lines = bus_enforce.doctor()
        for ln in lines:
            (sys.stdout if ok else sys.stderr).write(ln + "\n")
        return 0 if ok else 1
    elif args.cmd == "audit":                                   # A1-L1: cursor-move log
        for r in audit(args.agent, limit=args.limit):
            flag = "  ⚠ SKIPPED %d" % r["skipped_undelivered"] if r["skipped_undelivered"] else ""
            print("[#%s %s %s: #%s→#%s]%s" % (r["id"], _scrub(r["agent"]), r["op"], r["from_id"], r["to_id"], flag))
    elif args.cmd == "audit-export":                            # the machine form of the SECOND record
        rows = audit_export(args.agent, from_seq=max(0, args.from_seq))
        for r in rows:
            print(json.dumps(r, ensure_ascii=False, sort_keys=True))
        # the slice's anchor for the caller (reconcile in product mode requires an anchored slice): seq 0 + GENESIS
        # prev = full chain; otherwise the caller must know the starting row_hash out of band.
        if rows and rows[0]["seq"] != 0:
            sys.stderr.write("audit-export: PARTIAL SLICE from row %d — full chain: --from-seq 0; the anchor is the "
                             "preceding row's row_hash: %s\n" % (rows[0]["seq"], rows[0]["prev_row_hash"]))
        return 0
    elif args.cmd == "audit-verify":                            # A1-L1: tamper evidence (hash chain)
        res = audit_verify(args.agent)
        if args.json:
            print(json.dumps(res, ensure_ascii=False))
        else:
            print("[%s] audit-chain (%d rows checked)" % ("OK" if res["ok"] else "TAMPER", res["checked"]))
            for pr in res["problems"]:
                print("  ! " + pr)
        return 0 if res["ok"] else 1
    elif args.cmd == "reconcile":                               # A1-L2: what should be redelivered
        rows = reconcile(args.agent)
        print("reconcile %s: %d skipped-undelivered candidate(s)" % (args.agent, len(rows)))
        for m in rows:
            print("  " + _fmt(m))
    elif args.cmd == "replay":                                  # A1-L2: redelivery (dry-run without commit)
        res = replay(args.agent, commit=args.commit, limit=args.limit)
        if not res["committed"]:
            print("DRY-RUN — %d message(s) marked for redelivery (--commit to execute):" % len(res["would_replay"]))
            for w in res["would_replay"]:
                print("  #%s (← %s)" % (w["orig"], w["from"]))
        else:
            print("REPLAY done — %d message(s) redelivered:" % len(res["replayed"]))
            for d in res["replayed"]:
                print("  #%s → new #%s" % (d["orig"], d["new"]))


if __name__ == "__main__":
    sys.exit(main() or 0)
