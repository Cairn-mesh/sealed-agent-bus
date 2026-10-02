#!/usr/bin/env python3
"""Mutation floor for sab-attach/1 (docs/AGENT_BUS_SCHEMA.md §8): every fix has at least one CODE-anchored mutant, and
the protocol test file must KILL each one by an ASSERTION (a test that decided), not by a crash or an import error.

Per mutant: copy the tree to a temp dir, apply exactly one replacement (the anchor must occur EXACTLY once — a missing
anchor is a broken floor, not a survivor), run test_attach_protocol_20261002.py with --junit-xml, and classify:
  KILLED   ≥1 <failure> (assertion) in the junit report
  CRASHED  only <error>s (setup/import) — the mutant broke the module, the test did not decide
  SURVIVED all passed
A control run on the unmutated copy must be all-pass first. Exit 0 only if the control passes and every mutant is
KILLED. stdlib-only; never touches the source tree."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST = "test_attach_protocol_20261002.py"

# (name, file, anchor, replacement) — the anchor is CODE, never a comment.
MUTANTS = [
    ("fetch: ignore the round budget", "bus_ssh_exchange.py",
     "                if used + ln > budget:\n", "                if False:\n"),
    ("fetch: next_seq off by one", "bus_ssh_exchange.py",
     "        nxt = from_seq + len(chunks)\n", "        nxt = from_seq + len(chunks) + 1\n"),
    ("fetch: from_seq range lets total through", "bus_ssh_exchange.py",
     "            if not (0 <= from_seq < total):\n", "            if not (0 <= from_seq <= total):\n"),
    ("fetch: stored file not re-checked before serving", "bus_attach.py",
     "        self._verify_file(p, desc[\"sha256\"], desc[\"size\"])\n        n = self.chunk_count(desc, chunk_bytes)\n",
     "        n = self.chunk_count(desc, chunk_bytes)\n"),
    ("chunk hash: served hash is wrong", "bus_attach.py",
     "\"chunk_sha256\": hashlib.sha256(part).hexdigest()}", "\"chunk_sha256\": hashlib.sha256(b\"\").hexdigest()}"),
    ("chunk hash: upload check disabled", "bus_attach.py",
     "            if hashlib.sha256(data).hexdigest() != ch_h:\n", "            if False:\n"),
    ("status: partial next_seq off by one", "bus_attach.py",
     "                return {\"state\": \"partial\", \"next_seq\": nxt}\n",
     "                return {\"state\": \"partial\", \"next_seq\": nxt - 1}\n"),
    ("status: success always says stored", "bus_ssh_exchange.py",
     "            out[\"attachments\"].append({\"sha256\": sha, \"status\": st[\"state\"], \"code\": st[\"state\"],\n",
     "            out[\"attachments\"].append({\"sha256\": sha, \"status\": \"stored\", \"code\": st[\"state\"],\n"),
    ("codes: quota code lost", "bus_attach.py",
     "                                      \"quota_exceeded\")\n", "                                      \"attachment_error\")\n"),
    ("companion: bytes-stored check disabled", "bus_ssh_exchange.py",
     "                    elif store.status(att)[\"state\"] != \"stored\":\n", "                    elif False:\n"),
    ("limits: raw frame cap disabled", "bus_ssh_exchange.py",
     "                    if lim[\"frame_bytes\"] > sds_envelope.SPEC_MAX_RAW_BYTES:\n", "                    if False:\n"),
    ("limits: canonical body measured WITH record_id", "sds_envelope.py",
     "    cb = len(jcs({k: v for k, v in rec.items() if k != \"record_id\"}))\n", "    cb = len(jcs(rec))\n"),
    ("idempotency: duplicate not detected", "bus_ssh_exchange.py",
     "                if dup is not None:\n", "                if False:\n"),
    ("idempotency: lookup->insert not serialized", "bus_ssh_exchange.py",
     "    fcntl.flock(fd, fcntl.LOCK_EX)\n", "    pass\n"),
    ("idempotency: substring match accepted as identity", "agent_bus.py",
     "        if env.get(\"record_id\") == record_id:\n", "        if True:\n"),
    ("idempotency: lookup failure fails open", "bus_ssh_exchange.py",
     "                except Exception:                              # noqa: BLE001 — cannot decide -> no insert (fail-closed)\n"
     "                    _idem_unlock(idem_fd)\n"
     "                    out[\"rejected\"].append({\"index\": i, \"reason\": \"idempotency lookup failed\", \"code\": \"idem_unknown\"})\n",
     "                except Exception:                              # noqa: BLE001 — cannot decide -> no insert (fail-closed)\n"
     "                    dup = None\n"
     "                if False:\n"
     "                    out[\"rejected\"].append({\"index\": i, \"reason\": \"idempotency lookup failed\", \"code\": \"idem_unknown\"})\n"),
    ("in_reply_to: mismatch accepted", "bus_ssh_exchange.py",
     "                if outer is not None and inner is not None and outer != inner:\n", "                if False:\n"),
    ("in_reply_to: inner-only not warned", "bus_ssh_exchange.py",
     "                if outer is None and inner is not None:\n", "                if False:\n"),
]


def _run(tree):
    xml = os.path.join(tree, "junit.xml")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", TEST, "--junit-xml", xml],
                   cwd=tree, env=env, capture_output=True, timeout=600)
    r = ET.parse(xml).getroot()
    cases = list(r.iter("testcase"))
    fails = [c.get("name") for c in cases if c.find("failure") is not None]
    errs = [c.get("name") for c in cases if c.find("error") is not None]
    return len(cases), fails, errs


def _copy(dst):
    for n in os.listdir(ROOT):
        if n in (".git", "__pycache__", ".pytest_cache"):
            continue
        s = os.path.join(ROOT, n)
        (shutil.copytree if os.path.isdir(s) else shutil.copy2)(s, os.path.join(dst, n))


def main():
    with tempfile.TemporaryDirectory() as t:
        ctl = os.path.join(t, "control")
        os.mkdir(ctl)
        _copy(ctl)
        n, f, e = _run(ctl)
        print("control: %d tests, %d failures, %d errors" % (n, len(f), len(e)))
        if f or e or not n:
            print("CONTROL NOT GREEN — floor not measurable")
            return 2
        bad = 0
        for i, (name, fn, a, b) in enumerate(MUTANTS):
            d = os.path.join(t, "m%02d" % i)
            os.mkdir(d)
            _copy(d)
            p = os.path.join(d, fn)
            src = open(p, encoding="utf-8").read()
            if src.count(a) != 1:
                print("BROKEN-ANCHOR  %-52s (%s: anchor occurs %d×)" % (name, fn, src.count(a)))
                bad += 1
                continue
            open(p, "w", encoding="utf-8").write(src.replace(a, b, 1))
            _n, f, e = _run(d)
            verdict = "KILLED" if f else ("CRASHED" if e else "SURVIVED")
            bad += verdict != "KILLED"
            print("%-8s %-52s by %s" % (verdict, name, (f or e or ["-"])[0]))
        print("mutants: %d, not killed by an assertion: %d" % (len(MUTANTS), bad))
        return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
