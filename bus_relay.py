#!/usr/bin/env python3
"""bus_relay — ZERO-TRUST STORE-AND-FORWARD RELAY + SSE notification between machines (v1.2).

When it is needed: if there is no direct SSH between the two machines (both behind NAT/firewall). Then a relay mediates —
but BLINDLY:

- **E2E encryption at the sender** (`seal`): X25519 static ECDH → HKDF-SHA256 → ChaCha20-Poly1305. The routing fields
  (v/from/to/ts) are authenticated as AAD, the content is UNREADABLE to the relay. The relay stores only an opaque envelope.
- **Signed pickup** (`/pickup`, closing the July gap): the request is `{agent, ts, nonce, sig}`, where sig is Ed25519 over the
  bytes of `agentbus-relay|<purpose>|<agent>|<ts>|<nonce>`, with the key bound to the agent in the relay's REGISTRY.
  Unsigned, forged, outside the time band (±WINDOW s) or an ALREADY SEEN nonce → 401. So no one else can pull (or
  archive away) someone else's rows.
- **SSE** (`/events`, Server-Sent Events): authenticated subscription; the relay only sends
  `event: pending` / `data: {"count": N}` — NEVER CONTENT. The client pulls immediately on it; if SSE is not live, it polls.
- **Fail-closed:** without `cryptography` the relay does NOT start (RuntimeError), nor with an empty registry.
- **No deletion:** a picked-up envelope moves under `.picked/`.

This is an open network surface, so exposing it in production is an operator decision (TLS in front of the relay, rate limit on the proxy). The tests
run only on 127.0.0.1. The partner arm's open HIGH finding on the network layer is exactly why it got signed pickup and
a fail-closed start."""
from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidSignature, InvalidTag
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover - the relay does not start then
    HAVE_CRYPTO = False

V = "abr1"
WINDOW = 120                                      # s: the pickup request's ts window (replay protection together with the nonce cache)
MAX_ENVELOPE = 1024 * 1024
# /deliver is unauthenticated (a relay must also accept from senders unknown to it) — so
# built-in, fail-closed limits EVEN before the proxy/TLS: only a known recipient, a per-recipient pending ceiling,
# a per-recipient per-minute rate and a total spool ceiling. A proxy-side rate limit is still needed for public exposure.
MAX_PENDING_PER_RECIPIENT = int(os.environ.get("AGENT_BUS_RELAY_MAX_PENDING", "200"))
MAX_PER_MIN_PER_RECIPIENT = int(os.environ.get("AGENT_BUS_RELAY_MAX_PER_MIN", "120"))
MAX_SPOOL_TOTAL = int(os.environ.get("AGENT_BUS_RELAY_MAX_SPOOL", "5000"))
# A picked-up envelope goes under `.picked/`, and on a notary write error it stays under the name `.unnotarized`
# — NEITHER was counted by the spool limit (another directory, and a hidden name respectively). Because of the "no deletion" principle this
# grows monotonically: an authenticated party could fill the disk with repeated send+pickup rounds. So a SEPARATE archive quota:
# above it NEW deliveries are not accepted (fail-closed 429), but nothing is deleted — cleanup is an operator decision.
MAX_ARCHIVE_TOTAL = int(os.environ.get("AGENT_BUS_RELAY_MAX_ARCHIVE", "100000"))
MAX_SSE_PER_AGENT = int(os.environ.get("AGENT_BUS_RELAY_MAX_SSE", "2"))   # concurrent SSE connections per agent
_ROUTING = ("v", "from", "to", "ts", "nonce", "ct", "alg")


def _need_crypto():
    if not HAVE_CRYPTO:
        raise RuntimeError("bus_relay requires the 'cryptography' package (fail-closed: no plaintext fallback)")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode(), validate=True)


# ── keys ─────────────────────────────────────────────────────────────────────
def x25519_keypair():
    """-> (private raw bytes, public base64). The private key stays on ITS OWN machine."""
    _need_crypto()
    k = X25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw, _b64(pub)


def ed25519_keypair():
    """-> (32-byte seed, public hex) for the pickup signature."""
    _need_crypto()
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return seed, pub


# ── E2E enveloping ──────────────────────────────────────────────────────────
def _aead_key(shared: bytes, sender: str, recipient: str) -> bytes:
    info = ("%s|%s|%s" % (V, sender, recipient)).encode()     # direction binding (anti-reflection)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def seal(body: str, sender: str, recipient: str, sender_x25519_priv: bytes, recipient_x25519_pub_b64: str,
         ts: int | None = None) -> dict:
    _need_crypto()
    ts = int(time.time()) if ts is None else int(ts)
    shared = X25519PrivateKey.from_private_bytes(sender_x25519_priv).exchange(
        X25519PublicKey.from_public_bytes(_unb64(recipient_x25519_pub_b64)))
    nonce = os.urandom(12)
    aad = ("%s|%s|%s|%d" % (V, sender, recipient, ts)).encode()
    ct = ChaCha20Poly1305(_aead_key(shared, sender, recipient)).encrypt(nonce, body.encode("utf-8"), aad)
    return {"v": V, "from": sender, "to": recipient, "ts": ts, "alg": "x25519-chacha20poly1305",
            "nonce": _b64(nonce), "ct": _b64(ct)}


def unseal(env: dict, recipient: str, recipient_x25519_priv: bytes, sender_x25519_pub_b64: str) -> str:
    """AEAD-checked decryption. Forged / not addressed to me / wrong sender → exception (fail-closed)."""
    _need_crypto()
    if env.get("v") != V:
        raise ValueError("unknown envelope version")
    if env.get("to") != recipient:
        raise ValueError("envelope is not addressed to this recipient")
    shared = X25519PrivateKey.from_private_bytes(recipient_x25519_priv).exchange(
        X25519PublicKey.from_public_bytes(_unb64(sender_x25519_pub_b64)))
    aad = ("%s|%s|%s|%d" % (V, env["from"], recipient, int(env["ts"]))).encode()
    try:
        return ChaCha20Poly1305(_aead_key(shared, env["from"], recipient)).decrypt(
            _unb64(env["nonce"]), _unb64(env["ct"]), aad).decode("utf-8")
    except InvalidTag:
        raise ValueError("envelope authentication failed")


# ── signed pickup ───────────────────────────────────────────────────────────
def _auth_bytes(purpose: str, agent: str, ts: int, nonce: str) -> bytes:
    return ("agentbus-relay|%s|%s|%d|%s" % (purpose, agent, ts, nonce)).encode()


def sign_request(purpose: str, agent: str, seed: bytes, ts: int | None = None, nonce: str | None = None) -> dict:
    _need_crypto()
    ts = int(time.time()) if ts is None else int(ts)
    nonce = nonce or os.urandom(12).hex()
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(_auth_bytes(purpose, agent, ts, nonce)).hex()
    return {"agent": agent, "ts": ts, "nonce": nonce, "sig": sig}


class _Auth:
    """Registry (agent → Ed25519 pub hex) + time band + nonce cache. Thread-safe."""

    def __init__(self, registry: dict, window: int = WINDOW, nonce_path: str | None = None):
        _need_crypto()
        if not registry:
            raise RuntimeError("relay registry is empty (fail-closed)")
        self.registry, self.window = dict(registry), window
        self._seen, self._lock = {}, threading.Lock()
        # v1.4: a DURABLE nonce store (append-only JSONL) — the v1.2 in-memory cache allowed a pickup to be replayed once
        # after a restart. On load only keys still within the window (2×window)
        # live; compaction NEVER drops an unexpired entry.
        self.nonce_path = nonce_path
        self.not_before = 0.0
        if nonce_path:
            now = time.time()
            # if the durable nonce store is MISSING (deleted, or first start), we cannot know what
            # we have already seen → a request signed BEFORE the start is rejected (fail-closed). The client retries with a fresh ts.
            if not os.path.exists(nonce_path):
                self.not_before = now
            try:
                with open(nonce_path, encoding="utf-8") as f:
                    for line in f:
                        try:
                            r = json.loads(line)
                            if now - float(r["t"]) <= 2 * self.window:
                                self._seen[(r["p"], r["a"], r["n"])] = float(r["t"])
                        except (ValueError, KeyError, TypeError):
                            continue
            except FileNotFoundError:
                pass
            self._compact_locked()

    def _compact_locked(self):
        """Atomic rewrite with the still-live keys (the caller holds the lock, or single-threaded in init)."""
        if not self.nonce_path:
            return
        tmp = self.nonce_path + ".tmp"
        os.makedirs(os.path.dirname(os.path.abspath(self.nonce_path)), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            for (p_, a_, n_), t_ in self._seen.items():
                f.write(json.dumps({"p": p_, "a": a_, "n": n_, "t": t_}) + "\n")
        os.replace(tmp, self.nonce_path)

    def check(self, purpose: str, req: dict) -> str | None:
        """-> the agent's name if the request is authentic; otherwise None."""
        try:
            agent, ts, nonce, sig = req["agent"], int(req["ts"]), str(req["nonce"]), bytes.fromhex(req["sig"])
        except (KeyError, TypeError, ValueError):
            return None
        pub = self.registry.get(agent)
        now = time.time()
        if not pub or abs(now - ts) > self.window or ts < int(self.not_before) or not (8 <= len(nonce) <= 64):
            return None
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(sig, _auth_bytes(purpose, agent, ts, nonce))
        except (InvalidSignature, ValueError):
            return None
        key = (purpose, agent, nonce)
        with self._lock:
            expired = [k for k, t in self._seen.items() if now - t > 2 * self.window]
            for k in expired:                                   # only expired (out-of-window) keys drop out
                del self._seen[k]
            if key in self._seen:                              # REPLAY: the same signed request a second time
                return None
            self._seen[key] = now
            if self.nonce_path:
                if expired:
                    self._compact_locked()
                else:
                    with open(self.nonce_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps({"p": purpose, "a": agent, "n": nonce, "t": now}) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
        return agent


# ── relay server ─────────────────────────────────────────────────────────────
class Relay:
    def __init__(self, spool: str, registry: dict, host: str = "127.0.0.1", port: int = 0, window: int = WINDOW,
                 sse_interval: float = 0.5, nonce_path: str | None = None, notary=None):
        # v1.5: notary log at the boundary (None → per environment; mandatory in product mode, fail-closed)
        if notary is None:
            import bus_notary
            notary = bus_notary.Notary.from_env()
        self.notary = notary or None
        # v1.4: the nonce store lives next to the spool by default (durable) → a pickup cannot be replayed even after a restart
        nonce_path = nonce_path or os.path.join(spool, ".pickup_nonces.jsonl")
        self.spool, self.auth, self.sse_interval = spool, _Auth(registry, window, nonce_path), sse_interval
        self.max_pending_per_recipient = MAX_PENDING_PER_RECIPIENT
        self.max_per_min_per_recipient = MAX_PER_MIN_PER_RECIPIENT
        self.max_spool_total = MAX_SPOOL_TOTAL
        self.max_archive_total = MAX_ARCHIVE_TOTAL
        self.max_sse_per_agent = MAX_SSE_PER_AGENT
        self._sse, self._sse_lock = {}, threading.Lock()          # how many SSE connections are live per agent
        self._rate, self._rate_lock = {}, threading.Lock()
        relay = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):                          # the relay does not log content
                pass

            def _json(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _body(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                if n <= 0 or n > MAX_ENVELOPE:
                    raise ValueError("bad length")
                return json.loads(self.rfile.read(n).decode())

            def do_POST(self):
                path = urlparse(self.path).path
                try:
                    obj = self._body()
                except (ValueError, OSError):
                    return self._json(400, {"error": "bad_request"})
                if path == "/deliver":
                    return self._json(*relay.deliver(obj))
                if path == "/pickup":
                    agent = relay.auth.check("pickup", obj)
                    if not relay._note(envelope=obj, sender_identity=agent or (str(obj.get("agent", ""))[:128] if isinstance(obj, dict) else ""),
                                       sender_auth="pickup-sig" if agent else "unauthenticated-claim",
                                       recipient="relay", kind="pickup", decision="accepted" if agent else "rejected",
                                       reason="" if agent else "unauthorized"):
                        return self._json(503, {"error": "notary unavailable"})
                    if not agent:
                        return self._json(401, {"error": "unauthorized"})
                    return self._json(200, {"envelopes": relay.pickup(agent)})
                return self._json(404, {"error": "not_found"})

            def do_GET(self):
                u = urlparse(self.path)
                if u.path == "/health":
                    return self._json(200, {"ok": True})
                if u.path != "/events":
                    return self._json(404, {"error": "not_found"})
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                agent = relay.auth.check("events", q)
                if not agent:
                    return self._json(401, {"error": "unauthorized"})
                try:
                    max_s = min(float(q.get("max_seconds", 300)), 3600.0)
                except ValueError:
                    max_s = 300.0
                if not relay.sse_slot(agent, True):                 # thread/fd exhaustion with a per-agent limit
                    return self._json(429, {"error": "too many SSE connections for this agent"})
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                last, t0 = -1, time.time()
                try:
                    while time.time() - t0 < max_s:
                        n = relay.count(agent)
                        if n != last:
                            self.wfile.write(("event: pending\ndata: %s\n\n" % json.dumps({"count": n})).encode())
                            last = n
                        else:
                            self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        time.sleep(relay.sse_interval)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    relay.sse_slot(agent, False)

        self.server = ThreadingHTTPServer((host, port), H)
        self.server.daemon_threads = True
        self.url = "http://%s:%d" % self.server.server_address[:2]

    def _dir(self, agent: str) -> str:
        import agent_bus as ab
        d = os.path.join(self.spool, ab._safe_name(agent))
        os.makedirs(os.path.join(d, ".picked"), exist_ok=True)
        return d

    def _note(self, **kw) -> bool:
        """One notary entry; False if the log is on but not writable (→ the caller is fail-closed)."""
        if self.notary is None:
            return True
        try:
            self.notary.record(**kw)
            return True
        except Exception:
            return False

    def deliver(self, env: dict):
        """v1.5: every accepted/rejected envelope is a notary entry (`from` is NOT authenticated here → labelled so;
        the sealed `ct` goes into the log only as a hash). A log error → the envelope does not enter the spool."""
        code, res = self._deliver(env)
        ok = code == 200
        e = env if isinstance(env, dict) else {}
        ts = e.get("ts")
        if not self._note(envelope=env if isinstance(env, (dict, list, str)) else repr(env),
                          sender_identity=str(e.get("from", ""))[:128], sender_auth="unauthenticated-claim",
                          recipient=str(e.get("to", ""))[:128], kind="sealed", decision="accepted" if ok else "rejected",
                          reason="" if ok else str(res.get("error", code)), claimed_ts=ts if isinstance(ts, int) else None):
            if ok:
                self._unwrite(env["to"], res["id"])
            return 503, {"error": "notary unavailable"}
        return code, res

    def _unwrite(self, agent: str, mid: str):
        try:
            os.replace(os.path.join(self._dir(agent), mid + ".json"), os.path.join(self._dir(agent), "." + mid + ".unnotarized"))
        except OSError:
            pass

    def _deliver(self, env: dict):
        if not isinstance(env, dict) or set(env) != set(_ROUTING) or env.get("v") != V:
            return 400, {"error": "malformed (only sealed envelopes are accepted)"}
        if not all(isinstance(env[k], str) and env[k] for k in ("from", "to", "nonce", "ct")):
            return 400, {"error": "malformed"}
        if env["to"] not in self.auth.registry:                      # only a known recipient has a mailbox
            return 404, {"error": "unknown recipient"}
        with self._rate_lock:                                          # the limit check + write is one critical section
            now = time.time()
            win = [x for x in self._rate.get(env["to"], []) if now - x < 60]
            if len(win) >= self.max_per_min_per_recipient:
                return 429, {"error": "rate limited (recipient)"}
            if self.count(env["to"]) >= self.max_pending_per_recipient:
                return 429, {"error": "recipient mailbox full"}
            if self._spool_total() >= self.max_spool_total:
                return 429, {"error": "relay spool full"}
            if self.archive_total() >= self.max_archive_total:
                return 429, {"error": "relay archive full (cleaning up picked/unnotarized envelopes is an operator decision)"}
            win.append(now)
            self._rate[env["to"]] = win
            return self._write(env)

    def _spool_total(self) -> int:
        n = 0
        try:
            for name in os.listdir(self.spool):
                d = os.path.join(self.spool, name)
                if os.path.isdir(d):
                    n += sum(1 for f in os.listdir(d) if f.endswith(".json"))
        except OSError:
            return self.max_spool_total                                # not measurable → fail-closed
        return n

    def archive_total(self) -> int:
        """The number of PICKED-UP (`.picked/`) and half-finished unnotarized (`.unnotarized`) envelopes.
        Deletes nothing: the number is needed for the quota gate and for the operator (cleanup is their decision)."""
        n = 0
        try:
            for name in os.listdir(self.spool):
                d = os.path.join(self.spool, name)
                if not os.path.isdir(d):
                    continue
                n += sum(1 for f in os.listdir(d) if f.endswith(".unnotarized"))
                pd = os.path.join(d, ".picked")
                if os.path.isdir(pd):
                    n += sum(1 for f in os.listdir(pd) if f.endswith(".json"))
        except OSError:
            return self.max_archive_total                          # not measurable → fail-closed
        return n

    def sse_slot(self, agent: str, take: bool) -> bool:
        """SSE connection slot per agent. -> True if there is room (with take=True it also reserves it).

        An authenticated party could open unlimited `/events` connections, each holding a thread
        (and an fd) for up to an hour -> the relay would also be paralysed for `/deliver`. We limit it per agent.
        """
        with self._sse_lock:
            cur = self._sse.get(agent, 0)
            if not take:
                self._sse[agent] = max(0, cur - 1)
                return True
            if cur >= self.max_sse_per_agent:
                return False
            self._sse[agent] = cur + 1
            return True

    def _write(self, env: dict):
        mid = "%d_%s" % (time.time_ns(), os.urandom(4).hex())
        d = self._dir(env["to"])
        tmp = os.path.join(d, "." + mid)
        with open(tmp, "w") as f:
            json.dump(env, f)
        os.replace(tmp, os.path.join(d, mid + ".json"))
        return 200, {"ok": True, "id": mid}

    def count(self, agent: str) -> int:
        return sum(1 for n in os.listdir(self._dir(agent)) if n.endswith(".json"))

    def pickup(self, agent: str) -> list:
        d, out = self._dir(agent), []
        for name in sorted(os.listdir(d)):
            if not name.endswith(".json"):
                continue
            p = os.path.join(d, name)
            try:
                with open(p) as f:
                    out.append(json.load(f))
                os.replace(p, os.path.join(d, ".picked", name))  # no deletion
            except (OSError, ValueError):
                continue
        return out

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


# ── kliens ───────────────────────────────────────────────────────────────────
class RelayClient:
    def __init__(self, url: str, agent: str, sign_seed: bytes, x25519_priv: bytes, peers_x25519: dict):
        _need_crypto()
        self.url, self.agent, self.seed, self.priv, self.peers = url.rstrip("/"), agent, sign_seed, x25519_priv, peers_x25519

    def _post(self, path: str, obj: dict, timeout: float = 15.0) -> dict:
        req = urllib.request.Request(self.url + path, data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - an operator-given relay URL
            return json.loads(r.read().decode())

    def deliver(self, recipient: str, body: str) -> dict:
        return self._post("/deliver", seal(body, self.agent, recipient, self.priv, self.peers[recipient]))

    def pickup(self) -> list:
        """-> [{"from", "ts", "body"}] — only the authentically decryptable ones; the rest are skipped (fail-closed)."""
        res = self._post("/pickup", sign_request("pickup", self.agent, self.seed))
        out = []
        for env in res.get("envelopes", []):
            try:
                out.append({"from": env["from"], "ts": env["ts"],
                            "body": unseal(env, self.agent, self.priv, self.peers[env["from"]])})
            except (KeyError, ValueError):
                continue
        return out

    def deliver_attachment(self, recipient: str, store, desc) -> int:
        """An attachment through the relay: every chunk is a SEPARATE sealed envelope ({"attach": descriptor, "chunk": chunk}).
        -> the number of chunks sent. The receiver assembles them with `take_attachments()` (with a hash check)."""
        n = 0
        for ch in store.chunks(desc):
            self.deliver(recipient, json.dumps({"attach": desc, "chunk": ch}))
            n += 1
        return n

    @staticmethod
    def take_attachments(items: list, store) -> tuple:
        """Assemble the attachment chunks from pickup()'s result into the store. -> (remaining messages, [finished descriptors], [errors])."""
        import bus_attach
        rest, done, errors = [], [], []
        for it in items:
            try:
                obj = json.loads(it["body"])
            except (ValueError, TypeError):
                obj = None
            if not (isinstance(obj, dict) and set(obj) == {"attach", "chunk"}):
                rest.append(it)
                continue
            try:
                d = store.receive_chunk(obj["attach"], obj["chunk"])
                if d:
                    done.append(d)
            except bus_attach.AttachmentError as e:
                errors.append(str(e))
        return rest, done, errors

    def wait_pending(self, timeout: float = 30.0) -> int:
        """SSE: waits until the relay signals >0 pending envelopes. -> the count (0 = expired). If SSE is unreachable,
        it falls back to polling (it sees no count, so it pulls: the return value signals the number that can be pulled)."""
        q = sign_request("events", self.agent, self.seed)
        q["max_seconds"] = str(int(timeout) + 1)
        url = self.url + "/events?" + "&".join("%s=%s" % (k, v) for k, v in q.items())
        t0 = time.time()
        try:
            with urllib.request.urlopen(url, timeout=timeout + 5) as r:  # noqa: S310
                for raw in r:
                    line = raw.decode("utf-8", "replace").strip()
                    if line.startswith("data:"):
                        n = int(json.loads(line[5:]).get("count", 0))
                        if n > 0:
                            return n
                    if time.time() - t0 > timeout:
                        return 0
        except (OSError, ValueError):
            return -1                                           # SSE not live → the caller should poll (pickup())
        return 0
