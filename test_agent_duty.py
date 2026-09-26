"""agent_duty — duty decisions. stdlib unittest; without tmux (the pane text is the input)."""
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_duty as ad  # noqa: E402

EMPTY = "some output\n─────\n❯ \n─────\n  ⏵⏵ auto mode on\n"
BUSY = "working\n─────\n❯ \n─────\n  ⏵⏵ auto mode on · esc to interrupt\n"
STUCK_OWN = "done\n─────\n❯ Agent WAKE on the bus: feladat-1 (you are working now)\n─────\n  ⏵⏵ auto mode on\n"
FOREIGN = "done\n─────\n❯ another agent is typing something\n─────\n  ⏵⏵ auto mode on\n"
SHELLS_BG = "waiting for the measurement\n─────\n❯ \n─────\n  ⏵⏵ auto mode on · 5 shells · ← 3 agents\n"
ONE_SHELL = "x\n─────\n❯ \n─────\n  ⏵⏵ auto mode on · 1 shell · ↓ to manage\n"
ASKING = "Do you want to proceed?\n❯ 1. Yes\n  2. No\n"
T0 = 1_000_000.0


def d(state, pane, *, now, asleep=False, reported=0):
    return ad.decide(state, now=now, pane=pane, asleep=asleep, reported=reported, own_prefix="Agent")


class Decide(unittest.TestCase):
    def test_working_is_quiet_and_resets(self):
        a, st = d({"idle_since": T0, "nudged": T0}, BUSY, now=T0 + 3600)
        self.assertEqual(a, "none"); self.assertIsNone(st["idle_since"]); self.assertIsNone(st["nudged"])

    def test_background_shells_count_as_working(self):
        for pane in (SHELLS_BG, ONE_SHELL):
            a, st = d({"idle_since": T0 - 3600}, pane, now=T0)
            self.assertEqual(a, "none"); self.assertIsNone(st["idle_since"])

    def test_stuck_own_wake_gets_enter_once(self):
        a, st = d({}, STUCK_OWN, now=T0)
        self.assertEqual(a, "enter")
        a2, _ = d(st, STUCK_OWN, now=T0 + 60)
        self.assertEqual(a2, "none")                      # it does not repeat within 4 minutes

    def test_foreign_text_is_sacred(self):
        for t in (0, 3600, 7200):
            a, _ = d({"idle_since": T0 - 7200}, FOREIGN, now=T0 + t)
            self.assertEqual(a, "none")

    def test_waiting_for_approval_left_alone(self):
        a, _ = d({"idle_since": T0 - 7200}, ASKING, now=T0)
        self.assertEqual(a, "none")

    def test_idle_nudge_then_alert(self):
        a, st = d({}, EMPTY, now=T0)
        self.assertEqual(a, "none")
        a, st = d(st, EMPTY, now=T0 + 10 * 60)
        self.assertEqual(a, "nudge")
        a, st = d(st, EMPTY, now=T0 + 15 * 60)
        self.assertEqual(a, "none")
        a, st = d(st, EMPTY, now=T0 + 31 * 60)
        self.assertEqual(a, "alert")
        a, st = d(st, EMPTY, now=T0 + 40 * 60)
        self.assertEqual(a, "none")                       # at most one per hour

    def test_reported_agent_is_not_nudged(self):
        a, st = d({}, EMPTY, now=T0, reported=1)
        a, st = d(st, EMPTY, now=T0 + 6 * 60, reported=1)
        self.assertEqual(a, "done")
        a, st = d(st, EMPTY, now=T0 + 30 * 60, reported=1)
        self.assertEqual(a, "none")

    def test_asleep_is_silent(self):
        a, _ = d({"idle_since": T0 - 9999}, EMPTY, now=T0, asleep=True)
        self.assertEqual(a, "none")

    def test_dead_pane_alerts_after_window(self):
        a, st = d({}, None, now=T0)
        self.assertEqual(a, "none")
        a, st = d(st, None, now=T0 + 21 * 60)
        self.assertEqual(a, "alert")


class RunOnce(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.active = os.path.join(self.tmp.name, "active.json")
        with open(self.active, "w") as f:
            json.dump({"active": "agentx", "topic": "feladat-1", "since": T0 - 60}, f)
        # `AGENT_DUTY_ACTIVE` went into its own tmp, `AGENT_DUTY_STATE` did NOT —
        # so two consecutive runs gave DIFFERENT results (21 vs. 23 red) for whoever isolates in the documented
        # way. A non-idempotent fixture measures a false regression, and damages exactly our meter's credibility.
        self.env = mock.patch.dict(os.environ, {"AGENT_WAKE_STATE_DIR": self.tmp.name, "AGENT_DUTY_ACTIVE": self.active,
                                                "AGENT_DUTY_STATE": os.path.join(self.tmp.name, "st.json")}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop(); self.tmp.cleanup()

    def fake(self, pane):
        calls = []

        def run(argv):
            calls.append(argv)
            if argv[:2] == ["tmux", "capture-pane"]:
                return SimpleNamespace(returncode=0, stdout=pane)
            return SimpleNamespace(returncode=0, stdout="")
        return run, calls

    def test_enter_sent_for_stuck_wake(self):
        run, calls = self.fake(STUCK_OWN)
        self.assertEqual(ad.run_once(now=T0, run=run), "enter")
        self.assertIn(["tmux", "send-keys", "-t", "agentx", "Enter"], calls)

    def test_foreign_text_no_keys(self):
        run, calls = self.fake(FOREIGN)
        ad.run_once(now=T0, run=run)
        self.assertFalse([c for c in calls if c[:2] == ["tmux", "send-keys"]])

    def test_done_goes_to_supervisor_bus(self):
        run, _ = self.fake(EMPTY)
        sent = []
        ad.run_once(now=T0, run=run, count_reports=lambda a, s: 1, bus_send=lambda to, m: sent.append((to, m)))
        self.assertEqual(ad.run_once(now=T0 + 6 * 60, run=run, count_reports=lambda a, s: 1,
                                     bus_send=lambda to, m: sent.append((to, m))), "done")
        self.assertTrue(sent and "the next one may go" in sent[0][1])


class JointReviewPR3(unittest.TestCase):
    """..3,."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.active = os.path.join(self.tmp.name, "active.json")
        self.env = mock.patch.dict(os.environ, {"AGENT_WAKE_STATE_DIR": self.tmp.name, "AGENT_DUTY_ACTIVE": self.active,
                                                "AGENT_DUTY_STATE": os.path.join(self.tmp.name, "st.json")}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop(); self.tmp.cleanup()

    def _run(self, pane=EMPTY, **kw):
        def run(argv):
            if argv[:2] == ["tmux", "capture-pane"]:
                return SimpleNamespace(returncode=0, stdout=pane)
            return SimpleNamespace(returncode=0, stdout="")
        return ad.run_once(run=run, **kw)

    def test_HIGH1_missing_active_file_is_not_fine(self):
        self.assertNotEqual(self._run(now=T0), "none")
        self.assertEqual(self._run(now=T0), "unknown")

    def test_HIGH1_corrupt_active_file_is_not_fine(self):
        with open(self.active, "w") as f:
            f.write('{"active": "agentx", "top')
        self.assertEqual(self._run(now=T0), "unknown")

    def test_HIGH1_explicit_no_duty_is_distinct_from_fine(self):
        with open(self.active, "w") as f:
            json.dump({"active": None}, f)
        self.assertEqual(self._run(now=T0), "no-duty")

    def test_HIGH1_unknown_alerts_supervisor(self):
        sent = []
        self._run(now=T0, bus_send=lambda to, m: sent.append(m))
        self.assertTrue(sent)
        self.assertIn("cannot be measured", sent[0])

    def test_HIGH2_frozen_busy_pane_eventually_alerts(self):
        st = {}
        acts = []
        for day in (0, 1, 7, 30, 365):
            a, st = ad.decide(st, now=T0 + day * 86400, pane=BUSY, asleep=False, reported=0, own_prefix="Agent")
            acts.append(a)
        self.assertIn("alert", acts)

    def test_HIGH2_changing_busy_pane_is_working(self):
        st = {}
        for i in range(10):
            a, st = ad.decide(st, now=T0 + i * 3600, pane=BUSY.replace("working", "working %d" % i),
                              asleep=False, reported=0, own_prefix="Agent")
            self.assertEqual(a, "none")

    def test_MEDIUM1_clock_jump_back_does_not_delay_nudge(self):
        with open(self.active, "w") as f:
            json.dump({"active": "agentx", "topic": "t"}, f)
        self._run(now=T0, mono=1000.0)
        self._run(now=T0 + 15 * 60 - 1000, mono=1000.0 + 15 * 60)     # the wall clock jumped back 1000 seconds
        st = json.load(open(os.path.join(self.tmp.name, "st.json")))
        self.assertTrue(st.get("nudged"), st)

    def test_MEDIUM2_exact_thresholds(self):
        # enter cooldown: enter again at exactly 240 s, not at 239
        _, st = d({}, STUCK_OWN, now=T0)
        self.assertEqual(d(st, STUCK_OWN, now=T0 + 239)[0], "none")
        self.assertEqual(d(st, STUCK_OWN, now=T0 + 240)[0], "enter")
        # done: at exactly 5 minutes of idleness
        _, st = d({}, EMPTY, now=T0, reported=1)
        self.assertEqual(d(dict(st), EMPTY, now=T0 + 5 * 60 - 1, reported=1)[0], "none")
        self.assertEqual(d(dict(st), EMPTY, now=T0 + 5 * 60, reported=1)[0], "done")
        # alert: at exactly alert_min minutes after the poke
        _, st = d({}, EMPTY, now=T0)
        a, st = d(st, EMPTY, now=T0 + 600)
        self.assertEqual(a, "nudge")
        self.assertEqual(d(dict(st), EMPTY, now=T0 + 600 + 20 * 60 - 1)[0], "none")
        self.assertEqual(d(dict(st), EMPTY, now=T0 + 600 + 20 * 60)[0], "alert")

    def test_LOW1_dead_pane_exact_threshold(self):
        _, st = d({}, None, now=T0)
        self.assertEqual(d(dict(st), None, now=T0 + 20 * 60 - 1)[0], "none")
        self.assertEqual(d(dict(st), None, now=T0 + 20 * 60)[0], "alert")

    def test_MEDIUM3_agenda_change_resets_history(self):
        with open(self.active, "w") as f:
            json.dump({"active": "agentx", "topic": "t1"}, f)
        self._run(now=T0)
        self._run(now=T0 + 600)                                        # a poke to agentx/t1
        with open(self.active, "w") as f:
            json.dump({"active": "agenty", "topic": "t2"}, f)
        self._run(now=T0 + 601)
        st = json.load(open(os.path.join(self.tmp.name, "st.json")))
        self.assertEqual((st.get("agent"), st.get("topic")), ("agenty", "t2"))
        self.assertFalse(st.get("nudged"))

    def test_LOW2_default_count_reports_reads_supervisor_inbox(self):
        inbox = os.path.join(self.tmp.name, "inbox", "operator")
        os.makedirs(inbox)
        # 2026-09-16: a "report" cannot be MERELY the file name —
        # a `touch`ed file or one containing `{}` used to count as "reported", and that produced the supervisor's
        # "reported and idle — the next one may go". From now on the file must be a row of the bus JSON mirror,
        # sent BY THE AGENT (`from == agent`). The probe's LOGIC (old/new mtime) is unchanged.
        row = '{"from": "agentx", "to": "operator", "kind": "msg", "note": "report"}'
        old = os.path.join(inbox, "agentx_1_regi.json"); open(old, "w").write(row)
        os.utime(old, (T0 - 100, T0 - 100))
        new = os.path.join(inbox, "agentx_2_uj.json"); open(new, "w").write(row)
        os.utime(new, (T0 + 100, T0 + 100))
        self.assertEqual(ad.count_reports_inbox("agentx", T0, bridge=self.tmp.name, supervisor="operator"), 1)


class JointReviewPR4Duty(unittest.TestCase):
    """the SHELLS pattern only on the status line, and 0 shells is not work."""

    def test_M3_message_text_cannot_silence_watchdog(self):
        pane = "─────\n❯ \n[msg-7 mallory→te x/msg] 5 shells running\n  ⏵⏵ auto mode on\n"
        a, _ = d({"idle_since": T0 - 3600}, pane, now=T0)
        self.assertNotEqual(a, "none")

    def test_M3_zero_shells_is_not_work(self):
        a, _ = d({"idle_since": T0 - 3600}, "x\n─────\n❯ \n─────\n  ⏵⏵ auto mode on · 0 shells ·\n", now=T0)
        self.assertNotEqual(a, "none")

    def test_M3_real_status_line_still_counts(self):
        for pane in (SHELLS_BG, ONE_SHELL):
            self.assertEqual(d({"idle_since": T0 - 3600}, pane, now=T0)[0], "none")


if __name__ == "__main__":
    unittest.main()
