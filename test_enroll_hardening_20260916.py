"""An attack on the SSH enrolment line — our own.

This module produces the `authorized_keys` line the operator puts onto the bus machine — so it is the
gate of ARMING. Four findings from the non-Claude arm:

  1. no `from=` source limit -> a leaked key can be used from anywhere in the world.
     Fix: a `--from` switch; without it the CLI WARNS (the limit depends on the partner's address, so it is an option).
  2. the idempotence was a SILENT DOWNGRADE: if the key was already present in a weaker (without restrict or
     pinned to another identity) line, the module said "already present", and the restricted line NEVER
     got in. Fix: the same key + a different line -> a loud error.
  3. `ssh-rsa` passed with any length (we only looked at the shape). Fix: decoding the blob and checking the modulus
     bit length (min. 3072; ed25519 is recommended).
  4. REFUTED: shell injection into `command=` — the identity's charset is bound, the key comment is cut off, the
     command is free of metacharacters.

stdlib unittest.
"""
import base64
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_ssh_enroll as en  # noqa: E402

CMD = "/usr/bin/python3 /opt/agent-bus/bus_ssh_exchange.py"


def _ssh_blob(*fields):
    return base64.b64encode(b"".join(struct.pack(">I", len(f)) + f for f in fields)).decode()


def ed25519_key():
    return "ssh-ed25519 %s test@host" % _ssh_blob(b"ssh-ed25519", os.urandom(32))


def rsa_key(bits):
    n = (1 << (bits - 1)) | 1
    modulus = n.to_bytes(bits // 8, "big")
    return "ssh-rsa %s test@host" % _ssh_blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + modulus)


class EnrollHardening(unittest.TestCase):
    # ── control: the shape of the restricted line ──────────────────────────────────
    def test_control_line_shape(self):
        line = en.enroll_line("peer", ed25519_key(), CMD)
        self.assertTrue(line.startswith('command="%s peer",restrict,' % CMD))
        for opt in ("no-pty", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding", "no-user-rc"):
            self.assertIn(opt, line)
        self.assertNotIn("test@host", line, "the key comment cannot get into the line")

    # ── 1: the from= source limit ───────────────────────────────────────────────
    def test_from_restriction_is_emitted_and_validated(self):
        line = en.enroll_line("peer", ed25519_key(), CMD, source="192.0.2.0/24")
        self.assertIn('from="192.0.2.0/24",restrict', line)
        for bad in ('192.0.2.5" command="rm -rf /', "192.0.2.1 192.0.2.2", 'x"y'):
            with self.subTest(src=bad):
                with self.assertRaises(ValueError):
                    en.enroll_line("peer", ed25519_key(), CMD, source=bad)

    # ── 3: key strength ────────────────────────────────────────────────────
    def test_weak_rsa_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            en.enroll_line("peer", rsa_key(1024), CMD)
        self.assertIn("1024 bits", str(cm.exception))

    def test_strong_rsa_is_accepted(self):
        self.assertIn("ssh-rsa", en.enroll_line("peer", rsa_key(4096), CMD))

    def test_blob_type_must_match_the_prefix(self):
        fake = "ssh-ed25519 %s x" % _ssh_blob(b"ssh-rsa", os.urandom(32))
        with self.assertRaises(ValueError) as cm:
            en.enroll_line("peer", fake, CMD)
        self.assertIn("does not match", str(cm.exception))

    # ── 2: no silent downgrade ──────────────────────────────────────────
    def test_existing_weaker_line_is_not_silently_kept(self):
        key = ed25519_key()
        line = en.enroll_line("peer", key, CMD)
        path = os.path.join(tempfile.mkdtemp(), "authorized_keys")
        with open(path, "w", encoding="utf-8") as f:                    # an OLD line without restrictions
            f.write("%s\n" % " ".join(key.split()[:2]))
        with self.assertRaises(ValueError) as cm:
            en.write_line(path, line)
        self.assertIn("DIFFERENT line", str(cm.exception))

    def test_identical_line_is_a_noop(self):
        line = en.enroll_line("peer", ed25519_key(), CMD)
        path = os.path.join(tempfile.mkdtemp(), "authorized_keys")
        self.assertTrue(en.write_line(path, line))
        self.assertFalse(en.write_line(path, line), "the same line is not duplicated the second time")

    def test_same_key_other_identity_is_refused(self):
        key = ed25519_key()
        path = os.path.join(tempfile.mkdtemp(), "authorized_keys")
        en.write_line(path, en.enroll_line("peer", key, CMD))
        with self.assertRaises(ValueError):
            en.write_line(path, en.enroll_line("masik", key, CMD))

    # ── 4: REFUTED — shell injection into command= ─────────────────────────
    def test_shell_metacharacters_cannot_enter(self):
        for ident in ("peer; rm -rf /", 'peer" ', "peer$(id)", "../peer", "peer\nother"):
            with self.subTest(i=ident):
                with self.assertRaises(ValueError):
                    en.enroll_line(ident, ed25519_key(), CMD)
        with self.assertRaises(ValueError):
            en.enroll_line("peer", ed25519_key(), 'python3 x.py" ; rm -rf / ; echo "')


if __name__ == "__main__":
    unittest.main()
