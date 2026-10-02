#!/usr/bin/env python3
"""sds_envelope — the SDS evidential envelope on the bus (the partner arm's three additive steps, 2026-09-14). Stdlib + optional cryptography.

The bus TRANSPORTS and WAKES; SDS (capsule2-spec, capsule-sync v2) says what a valid, provable message is.
This module is the bridge between the two — it is NOT SDS's reference verifier, and it does not replace the two arms' cross-check:

1. `send --kind sds-envelope`: the body is a framed pair `{"record": …, "envelope": …}` (SPEC §5.5 "Combined framing").
   On send only the STRUCTURE is bound (check_framed_shape) — a malformed frame does not reach the bus.
2. `recv --verify-sds`: per row `valid | invalid(<reason>) | unsigned | unverifiable(<reason>)`.
   - If the AGENT_BUS_SDS_VALIDATOR / CAPSULE2_SDS_VALIDATOR env names a `module:function`, THAT decides
     (e.g. an adapter written around the capsule2 reference verifier). Call: fn(framed_dict, context_dict) → (status, reason) | status.
   - Otherwise the built-in MINIMAL check runs (below), with a narrow JCS profile.
3. Governance bridge: the bus's `keys/<sender>.pub` registry binds the sender to the key; a local admission file
   says who may be a sender and with what org/role. A sender not admitted → invalid(not-admitted);
   the registry key ≠ the admitted issuer → invalid(key-mismatch).

Admission file (the bus's LOCAL view of the §5.4 admitted-set binding; NOT a check of the JOINT genesis chain):
  {"config_id": "sha256:<64hex>", "domain_hash": "<64hex>" (optional),
   "admitted": [{"sender": "<bus identity>", "issuer": "<ed25519 pubkey 64hex>", "org": "...", "role": "..."}]}
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import unicodedata

KIND = "sds-envelope"
DOM_AUTH = b"capsule-sync/auth/v1"                         # SPEC §5: the ONE domain-separation constant
_ENVELOPE_KEYS = {"record_id", "config_id", "domain", "domain_hash", "epoch", "sigs"}   # SPEC §5.5: a closed object
_DOMAIN_KEYS = {"project", "stream", "repo"}
_SLUG = re.compile(r"^[a-z0-9._:-]{1,64}$")
_H64 = re.compile(r"^[0-9a-f]{64}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_H128 = re.compile(r"^[0-9a-f]{128}$")
_SAFE_INT = 2 ** 53 - 1

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
    HAVE_CRYPTO = True
except Exception:                                           # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False


# ── SPEC §1: canonical form (RFC 8785 JCS profile — narrow: integers, strings, literals, arrays, objects) ──
def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\t\n\f\r":
            out.append({"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)                                  # U+007F and everything else verbatim; no normalization
    out.append('"')
    return "".join(out)


def jcs(value):
    """Canonical UTF-8 bytes. Object keys in UTF-16 code-unit order; float → ValueError (the profile knows only integers)."""
    def enc(v):
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            if not (-_SAFE_INT <= v <= _SAFE_INT):
                raise ValueError("integer outside safe range")
            return str(v)
        if isinstance(v, float):
            raise ValueError("non-integer number")
        if isinstance(v, str):
            return _jcs_str(v)
        if isinstance(v, list):
            return "[" + ",".join(enc(x) for x in v) + "]"
        if isinstance(v, dict):
            items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(_jcs_str(k) + ":" + enc(x) for k, x in items) + "}"
        raise ValueError("unsupported JSON type")
    return enc(value).encode("utf-8")


def record_id_of(record):
    """SPEC §2: record_id = "sha256:" + hex(SHA256(JCS(record MINUS top-level record_id)))."""
    body = {k: v for k, v in record.items() if k != "record_id"}
    return "sha256:" + hashlib.sha256(jcs(body)).hexdigest()


# ── step 1: the frame's structure (on send) ─────────────────────────────────────────────────────
def _no_float(obj):
    return json.loads(obj, parse_float=lambda s: (_ for _ in ()).throw(ValueError("non-integer number")))


def parse_framed(body):
    """The body → (record, envelope). A malformed structure → ValueError('<reason>'). An empty `sigs` is ALLOWED here
    (verify flags it as 'unsigned'); everything else follows the closed/bounded shape of SPEC §5.5."""
    try:
        framed = _no_float(body) if isinstance(body, str) else body
    except ValueError as e:
        raise ValueError("not-json: %s" % e)
    if not isinstance(framed, dict) or set(framed) != {"record", "envelope"}:
        raise ValueError("not-framed: exactly {record, envelope} required")
    rec, env = framed["record"], framed["envelope"]
    if not isinstance(rec, dict) or not isinstance(env, dict):
        raise ValueError("not-framed: record and envelope must be objects")
    if set(env) != _ENVELOPE_KEYS:
        raise ValueError("envelope-malformed: members must be exactly %s" % sorted(_ENVELOPE_KEYS))
    if not (isinstance(env["record_id"], str) and _SHA.match(env["record_id"])):
        raise ValueError("envelope-malformed: record_id")
    if not (isinstance(env["config_id"], str) and _SHA.match(env["config_id"])):
        raise ValueError("envelope-malformed: config_id")
    dom = env["domain"]
    if not (isinstance(dom, dict) and set(dom) == _DOMAIN_KEYS and all(isinstance(dom[k], str) and _SLUG.match(dom[k]) for k in dom)):
        raise ValueError("envelope-malformed: domain")
    if not (isinstance(env["domain_hash"], str) and _H64.match(env["domain_hash"])):
        raise ValueError("envelope-malformed: domain_hash")
    ep = env["epoch"]
    if isinstance(ep, bool) or not isinstance(ep, int) or not (0 <= ep <= _SAFE_INT):
        raise ValueError("envelope-malformed: epoch")
    sigs = env["sigs"]
    if not isinstance(sigs, list) or len(sigs) > 2:
        raise ValueError("envelope-malformed: sigs")
    for s in sigs:
        if not (isinstance(s, dict) and set(s) == {"issuer", "sig"} and isinstance(s["issuer"], str)
                and _H64.match(s["issuer"]) and isinstance(s["sig"], str) and _H128.match(s["sig"])):
            raise ValueError("envelope-malformed: sigs entry")
    issuers = [s["issuer"] for s in sigs]
    if issuers != sorted(issuers) or len(set(issuers)) != len(issuers):
        raise ValueError("envelope-malformed: sigs order/duplicate")
    return rec, env


def check_framed_shape(body):
    """The `send` gate: a malformed frame → ValueError (the bus does not accept it)."""
    parse_framed(body)


# ── step 2: checking on the receiving side ──────────────────────────────────────────────────────
def signed_message(env, role, org):
    """SPEC §5: DOM_AUTH ‖ record_id(32) ‖ config_id(32) ‖ domain_hash(32) ‖ len(role)‖role ‖ epoch_be8 ‖ len(org)‖org."""
    r, o = role.encode("utf-8"), org.encode("utf-8")
    if len(r) > 255 or len(o) > 255:
        raise ValueError("role/org too long")
    return (DOM_AUTH + bytes.fromhex(env["record_id"][7:]) + bytes.fromhex(env["config_id"][7:])
            + bytes.fromhex(env["domain_hash"]) + bytes([len(r)]) + r
            + int(env["epoch"]).to_bytes(8, "big") + bytes([len(o)]) + o)


def load_admission(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            adm = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(adm, dict) or not isinstance(adm.get("admitted"), list):
        return None
    return adm


def _external_validator():
    spec = os.environ.get("AGENT_BUS_SDS_VALIDATOR") or os.environ.get("CAPSULE2_SDS_VALIDATOR")
    if not spec:
        return None
    mod, _, fn = spec.partition(":")
    return getattr(importlib.import_module(mod), fn or "validate")


def verify(body, *, sender, admission=None, registry_pubkey=None):
    """Classify an sds-envelope bus row → (status, reason). status: 'valid'|'invalid'|'unsigned'|'unverifiable'."""
    try:
        rec, env = parse_framed(body)
    except ValueError as e:
        return "invalid", str(e).split(":")[0]
    try:
        ext = _external_validator()
    except Exception:
        return "unverifiable", "validator-import"
    # The external validator used to decide ALONE, and an arbitrary module could be loaded from an env variable
    # (`AGENT_BUS_SDS_VALIDATOR=rogue:ok`) — signature, admission, everything could be bypassed. From now on the
    # BUILT-IN check runs FIRST, and the external one can ONLY TIGHTEN: it can downgrade `valid`, but cannot create it.
    base_status, base_why = _builtin_verify(rec, env, sender, admission, registry_pubkey)
    if ext is None:
        return base_status, base_why
    try:
        res = ext({"record": rec, "envelope": env},
                  {"sender": sender, "admission": admission, "registry_pubkey": registry_pubkey,
                   "builtin": {"status": base_status, "why": base_why}})
    except Exception:
        return "unverifiable", "validator-error"
    ext_status, ext_why = ((res, "") if isinstance(res, str) else (res[0], res[1] if len(res) > 1 else ""))
    if base_status != "valid":
        return base_status, base_why                       # the external one cannot overwrite the built-in rejection
    if ext_status != "valid":
        return ext_status, ext_why or "external"
    return "valid", ""


def _builtin_verify(rec, env, sender, admission, registry_pubkey):
    """The built-in, minimal check (narrow JCS profile). -> (status, reason)"""
    if not env["sigs"]:
        return "unsigned", "no-sigs"
    try:
        if record_id_of(rec) != env["record_id"]:
            return "invalid", "record-id-mismatch"            # SPEC §2 recomputed
    except ValueError:
        return "invalid", "record-not-canonicalizable"
    if rec.get("record_id") != env["record_id"]:
        return "invalid", "record-id-binding"                 # SPEC §5.5 RECORD_ID_BINDING_MISMATCH
    if hashlib.sha256(jcs(env["domain"])).hexdigest() != env["domain_hash"]:
        return "invalid", "domain-hash-mismatch"              # SPEC §5.5 recomputed on the receiving side
    if admission is None:
        return "unverifiable", "no-admission"                 # without role/org the signed message cannot be built
    # the OPTIONAL `config_id` silently skipped the binding -> an envelope transplanted into another config context
    # also passed (cross-config replay). A missing binding is a third state, not green.
    if admission.get("config_id") is None:
        return "unverifiable", "no-config-binding"
    if admission["config_id"] != env["config_id"]:
        return "invalid", "config-mismatch"
    if admission.get("domain_hash") is not None and admission["domain_hash"] != env["domain_hash"]:
        return "invalid", "domain-hash-mismatch"
    by_issuer = {a.get("issuer"): a for a in admission["admitted"] if isinstance(a, dict)}
    mine = [a for a in admission["admitted"] if isinstance(a, dict) and a.get("sender") == sender]
    if not mine:
        return "invalid", "not-admitted"                      # step 3: the bus sender is not admitted
    if registry_pubkey is not None and registry_pubkey not in {a.get("issuer") for a in mine}:
        return "invalid", "key-mismatch"                      # step 3: registry key ≠ admitted issuer
    if not any(s["issuer"] in {a.get("issuer") for a in mine} for s in env["sigs"]):
        return "invalid", "not-admitted"                      # the sender's own issuer did not sign it
    if any(s["issuer"] not in by_issuer for s in env["sigs"]):
        return "invalid", "not-admitted"
    if not HAVE_CRYPTO:
        return "unverifiable", "no-crypto"
    for s in env["sigs"]:
        a = by_issuer[s["issuer"]]
        try:
            # the NFC/NFD ambiguity gives two DIFFERENT signed byte sequences for the same apparent role/org.
            # JCS deliberately does not normalize, so we normalize the admission fields ONCE, here.
            msg = signed_message(env, unicodedata.normalize("NFC", str(a.get("role", ""))),
                                 unicodedata.normalize("NFC", str(a.get("org", ""))))
            _ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(s["issuer"])).verify(bytes.fromhex(s["sig"]), msg)
        except Exception:
            return "invalid", "bad-signature"
    return "valid", ""


# ── attachment companion record (docs/AGENT_BUS_SCHEMA.md §8.7–§8.8) ─────────────────────────────────────────
#: capsule-sync-v2 SPEC §4 (the NORMATIVE home of these two numbers — this module only measures against them):
#: `MAX_RAW_BYTES` = the WHOLE FRAME's raw UTF-8 bytes as sent; `MAX_BYTES` = the record's `canonical_body` =
#: JCS(record MINUS top-level record_id) (SPEC §2) — NOT the record with its record_id member.
SPEC_MAX_RAW_BYTES = 8192
SPEC_MAX_BYTES = 4096
#: the record schema of the ONE companion record that hands over an attachment (§8.7).
ATTACH_SCHEMA = "capsule-sync/attachment/v1"


def spec_limits(body):
    """Measure a framed body against SPEC §4 -> {"frame_bytes", "canonical_body_bytes", "within_spec_limits"}.
    The bus MEASURES every sds-envelope with this (and returns the numbers to the sender); it ENFORCES them only on
    the attachment companion schema (§8.8) — 150 earlier long notes on the live bus are above 4096 and stay valid."""
    raw = body.encode("utf-8", "surrogatepass") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    rec, _env = parse_framed(body)
    cb = len(jcs({k: v for k, v in rec.items() if k != "record_id"}))
    return {"frame_bytes": len(raw), "canonical_body_bytes": cb,
            "within_spec_limits": len(raw) <= SPEC_MAX_RAW_BYTES and cb <= SPEC_MAX_BYTES}


def attachment_descriptor_of(record):
    """The companion record's descriptor (closed, checked) if `record.schema` is ATTACH_SCHEMA, else None.
    A record that CLAIMS the schema but carries no valid descriptor -> ValueError (it is not silently "not ours")."""
    if not isinstance(record, dict) or record.get("schema") != ATTACH_SCHEMA:
        return None
    import bus_attach
    try:
        return bus_attach.check_descriptor(record.get("descriptor"))
    except bus_attach.AttachmentError as e:
        raise ValueError("attachment-record: %s" % e)


def label(status, why):
    return status if not why or status in ("valid", "unsigned") else "%s(%s)" % (status, why)
