"""An attack on the duty watcher — our own.

Two fixes and two STATED limits.

  CLOSED 1 — a "report" cannot be merely a FILE NAME: a `touch`ed file or one containing `{}` used to
            count as a report, and that produced the supervisor's "reported and idle — the next one may go".
            From now on a structural rule: the file must be a row of the bus JSON mirror sent BY THE AGENT.
  CLOSED 2 — there was a SINGLE `alerted` key for every alert type, so the first alert suppressed the OTHER one too
            within the `remind_s` window (e.g. "no pane" suppressed "stuck busy"). Per type.

  STATED 1 — the assignment file (`duty_active.json`) is not authenticated: whoever can write it can rewrite who is
            on duty. The module is OUR OWN machine's supervision helper, not a trust boundary.
  STATED 2 — the evidence of "working" is the pane's content, which THE AGENT writes. The byte hash + time (stuckness)
            narrows this, but does not make it unforgeable. Real evidence would be process-level CPU time.

stdlib unittest.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_duty as ad  # noqa: E402

T0 = 1_700_000_000.0


class DutyHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inbox = os.path.join(self.tmp.name, "inbox", "operator")
        os.makedirs(self.inbox)

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, name, body, when=T0 + 100):
        p = os.path.join(self.inbox, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
        os.utime(p, (when, when))
        return p

    def count(self):
        return ad.count_reports_inbox("agentx", T0, bridge=self.tmp.name, supervisor="operator")

    # ── control: a real mirror row is a report ───────────────────────────────
    def test_control_real_mirror_row_counts(self):
        self._report("agentx_1.json", json.dumps({"from": "agentx", "to": "operator", "kind": "msg",
                                                  "note": "measurement done"}))
        self.assertEqual(self.count(), 1)

    # ── 1: a bare file name is not a report ────────────────────────────────────
    def test_touched_empty_file_is_not_a_report(self):
        self._report("agentx_2.json", "")
        self.assertEqual(self.count(), 0, 'a 0-byte file counted as a report')

    def test_empty_json_object_is_not_a_report(self):
        self._report("agentx_3.json", "{}")
        self.assertEqual(self.count(), 0, 'an empty JSON object counted as a report')

    def test_report_from_someone_else_does_not_count(self):
        self._report("agentx_4.json", json.dumps({"from": "masik", "to": "operator", "note": "not the agent's"}))
        self.assertEqual(self.count(), 0, "a row written in someone else's name cannot be the agent's report")

    def test_unparseable_file_does_not_count(self):
        self._report("agentx_5.json", "{ this is not json")
        self.assertEqual(self.count(), 0)

    # ── 2: alert suppression per type ───────────────────────────────────
    def test_alert_types_do_not_suppress_each_other(self):
        """The "no pane" alert cannot suppress the "stuck busy" alert in the same window."""
        now = T0
        st = {"no_pane_since": now - 3600}
        act, st = ad.decide(st, now=now, pane=None, asleep=False, reported=0, own_prefix="x")
        self.assertEqual(act, "alert")
        self.assertIn("alerted_no_pane", st, "the alert type has its own key")
        # in the same minute a STUCK-busy pane: the other type must speak up
        from unittest import mock
        st2 = dict(st)
        with mock.patch.object(ad.aw, "is_busy", lambda pane: True):
            act2, st2 = ad.decide(st2, now=now, pane="$ dolgozom", asleep=False, reported=0, own_prefix="x",
                                  busy_stuck_min=0)
        self.assertEqual(act2, "alert", "the stuck-busy alert was suppressed by another type's alert")
        self.assertIn("alerted_stuck", st2)


if __name__ == "__main__":
    unittest.main()
