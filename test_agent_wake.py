"""agent_wake + its wiring (bus_poke, agent_bus_watcher): SACRED typing, SLEEP-SAFE, operator WAKE. stdlib unittest."""
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_wake as aw  # noqa: E402

DIM, RST = "\x1b[2m", "\x1b[0m"


class FakeTmux:
    """Recording tmux calls; the successive outputs of capture-pane come from `panes` (the last one repeats)."""

    def __init__(self, panes, claude_pane=True):
        self.panes = list(panes)
        self.calls = []
        self.claude_pane = claude_pane

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["tmux", "capture-pane"]:
            out = self.panes.pop(0) if len(self.panes) > 1 else self.panes[0]
            return SimpleNamespace(returncode=0 if out is not None else 1, stdout=out or "")
        if argv[:2] == ["tmux", "list-panes"]:
            return SimpleNamespace(returncode=0, stdout="0.0\tclaude\n" if self.claude_pane else "")
        return SimpleNamespace(returncode=0, stdout="")

    def sends(self):
        return [c for c in self.calls if c[:2] == ["tmux", "send-keys"]]


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"AGENT_WAKE_STATE_DIR": self.tmp.name,
                                                "AGENT_WAKE_DIR": os.path.join(self.tmp.name, "wake"),
                                                "AGENT_BRIDGE_DIR": self.tmp.name,
                                                "AGENT_WAKE_OPERATORS": "operator"}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class PromptState(unittest.TestCase):
    def test_empty_prompt(self):
        self.assertEqual(aw.prompt_input_state("some output\n❯ \n"), "empty")

    def test_typed_text_is_typed(self):
        self.assertEqual(aw.prompt_input_state("❯ continue the measurement"), "typed")

    def test_dim_suggestion_is_ghost(self):
        self.assertEqual(aw.prompt_input_state("❯ %sTry \"fix lint\"%s" % (DIM, RST)), "ghost")

    def test_typed_after_dim_reset_is_typed(self):
        self.assertEqual(aw.prompt_input_state("❯ %shint%s x" % (DIM, RST)), "typed")

    def test_last_prompt_line_counts(self):
        self.assertEqual(aw.prompt_input_state("❯ old\noutput\n❯ "), "empty")

    def test_dead(self):
        self.assertEqual(aw.prompt_input_state(None), "dead")

    def test_busy(self):
        self.assertTrue(aw.is_busy("… working (esc to interrupt)\n❯ "))
        self.assertFalse(aw.is_busy("done\n❯ "))


class SafeSend(Env):
    def test_typing_present_nothing_sent(self):
        t = FakeTmux(["❯ a half-typed command"])
        self.assertEqual(aw.safe_send("a1", "a1:0.0", "poke", run=t, settle=lambda: None), "typed")
        self.assertEqual(t.sends(), [])
        self.assertFalse(any("C-u" in c for c in t.calls))

    def test_empty_prompt_sends_literal_then_enter(self):
        t = FakeTmux(["❯ ", "❯ "])
        self.assertEqual(aw.safe_send("a1", "a1:0.0", "poke", run=t, settle=lambda: None), "sent")
        self.assertEqual(t.sends(), [["tmux", "send-keys", "-t", "a1:0.0", "-l", "poke"],
                                     ["tmux", "send-keys", "-t", "a1:0.0", "Enter"]])

    def test_stuck_text_is_not_cleared(self):
        t = FakeTmux(["❯ ", "❯ poke"])
        self.assertEqual(aw.safe_send("a1", "a1:0.0", "poke", run=t, settle=lambda: None), "stuck")
        self.assertEqual(len(t.sends()), 2)
        self.assertFalse(any("C-u" in c for c in t.calls))

    def test_busy_agent_not_poked(self):
        t = FakeTmux(["running (esc to interrupt)\n❯ "])
        self.assertEqual(aw.safe_send("a1", "a1:0.0", "poke", run=t, settle=lambda: None), "busy")
        self.assertEqual(t.sends(), [])

    def test_sleep_safe_agent_not_poked(self):
        aw.enter_sleep_safe("a1", by="operator")
        t = FakeTmux(["❯ "])
        self.assertEqual(aw.safe_send("a1", "a1:0.0", "poke", run=t, settle=lambda: None), "sleep-safe")
        self.assertEqual(t.calls, [])


class SleepSafeMarkers(Env):
    def test_global_marker_sleeps_everyone(self):
        aw.enter_sleep_safe(None)
        self.assertTrue(aw.is_asleep("a1") and aw.is_asleep("a2"))

    def test_per_agent_marker(self):
        aw.enter_sleep_safe("a1")
        self.assertTrue(aw.is_asleep("a1"))
        self.assertFalse(aw.is_asleep("a2"))

    def test_wake_moves_marker_to_history_no_deletion(self):
        aw.enter_sleep_safe("a1")
        aw.enter_sleep_safe(None)
        self.assertEqual(aw.wake_up(None, by="operator", now=100), 2)
        self.assertFalse(aw.is_asleep("a1"))
        hist = sorted(os.listdir(os.path.join(self.tmp.name, "history")))
        self.assertEqual(len(hist), 2)
        self.assertTrue(all("woke-100-by-operator" in h for h in hist))


class OperatorCommands(Env):
    def _msg(self, sender, kind, body=""):
        return {"id": 1, "sender": sender, "kind": kind, "body": body}

    def test_non_operator_wake_ignored(self):
        aw.enter_sleep_safe("a1")
        res = aw.handle_operator_message(self._msg("a1", aw.KIND_WAKE, "a1"), verify=lambda m: "signed")
        self.assertEqual(res, "ignored:not-operator")
        self.assertTrue(aw.is_asleep("a1"))

    def test_agent_cannot_wake_itself_even_if_listed(self):
        with mock.patch.dict(os.environ, {"AGENT_WAKE_OPERATORS": "operator,a1"}):
            aw.enter_sleep_safe("a1")
            res = aw.handle_operator_message(self._msg("a1", aw.KIND_WAKE, "a1"), verify=lambda m: "signed")
        self.assertEqual(res, "ignored:self")
        self.assertTrue(aw.is_asleep("a1"))

    def test_forged_or_unsigned_operator_ignored(self):
        aw.enter_sleep_safe("a1")
        self.assertEqual(aw.handle_operator_message(self._msg("operator", aw.KIND_WAKE, "a1"),
                                                    verify=lambda m: "forged"), "ignored:bad-signature")
        self.assertEqual(aw.handle_operator_message(self._msg("operator", aw.KIND_WAKE, "a1"),
                                                    verify=lambda m: "unsigned"), "ignored:bad-signature")
        self.assertTrue(aw.is_asleep("a1"))

    def test_operator_sleep_then_wake(self):
        ok = lambda m: "signed"  # noqa: E731
        self.assertEqual(aw.handle_operator_message(self._msg("operator", aw.KIND_SLEEP, '{"agents":["a1","a2"]}'), verify=ok), "slept")
        self.assertTrue(aw.is_asleep("a1") and aw.is_asleep("a2"))
        self.assertEqual(aw.handle_operator_message(self._msg("operator", aw.KIND_WAKE, "a1"), verify=ok), "woke")
        self.assertFalse(aw.is_asleep("a1"))
        self.assertTrue(aw.is_asleep("a2"))

    def test_bad_body_ignored(self):
        self.assertEqual(aw.handle_operator_message(self._msg("operator", aw.KIND_SLEEP, "../../x y"),
                                                    verify=lambda m: "signed"), "ignored:bad-body")

    def test_other_kinds_untouched(self):
        self.assertIsNone(aw.handle_operator_message(self._msg("operator", "msg", "a1")))


class BusPokeIntegration(Env):
    def setUp(self):
        super().setUp()
        import bus_poke
        self.bp = bus_poke
        self.inbox = os.path.join(self.tmp.name, "inbox", "a1")
        os.makedirs(self.inbox)
        with open(os.path.join(self.inbox, "x_1_t.json"), "w") as f:
            f.write('{"from":"b","to":"a1","kind":"msg","topic":"t","note":"n","ts":1,"bus_id":1}')

    def _poker(self, tmux):
        p = self.bp.Poker("a1", explicit_target="a1:0.0", run=tmux, cooldown_ns=0, settle=lambda: None)
        p.inbox = self.inbox
        return p

    def test_poke_skips_live_typing(self):
        t = FakeTmux(["❯ the operator is typing right now"])
        with mock.patch.object(self.bp, "BRIDGE", self.tmp.name):
            self.assertEqual(self._poker(t).on_new(1, now_ns=10**12), "typed")
        self.assertEqual(t.sends(), [])

    def test_poke_skips_sleep_safe(self):
        aw.enter_sleep_safe("a1")
        t = FakeTmux(["❯ "])
        with mock.patch.object(self.bp, "BRIDGE", self.tmp.name):
            self.assertEqual(self._poker(t).on_new(1, now_ns=10**12), "sleep-safe")
        self.assertEqual(t.sends(), [])

    def test_poke_sends_when_idle(self):
        t = FakeTmux(["❯ ", "❯ "])
        with mock.patch.object(self.bp, "BRIDGE", self.tmp.name):
            self.assertEqual(self._poker(t).on_new(1, now_ns=10**12), "injected")
        self.assertEqual(len(t.sends()), 2)


class WatcherIntegration(Env):
    def test_headless_wake_refused_while_asleep(self):
        import agent_bus_watcher as w
        aw.enter_sleep_safe("a1")
        with mock.patch.object(w, "is_armed", return_value=True), mock.patch.object(w.subprocess, "run") as run:
            self.assertEqual(w.wake("a1", self.tmp.name, 3), "sleep-safe")
            run.assert_not_called()


class WakeDirDerivation(unittest.TestCase):
    """the watcher's WAKE_DIR derives from AGENT_BRIDGE_DIR, at call time."""

    def test_wake_dir_follows_bridge_dir_when_no_override(self):
        import agent_bus_watcher as w
        with tempfile.TemporaryDirectory() as d:
            env = {k: v for k, v in os.environ.items() if k != "AGENT_WAKE_DIR"}
            env["AGENT_BRIDGE_DIR"] = d
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(w, "WAKE_DIR", None):
                self.assertEqual(w.wake_dir(), os.path.join(d, "wake"))
                w._log("a1", "probe")
                self.assertTrue(os.path.exists(os.path.join(d, "wake", "a1.log")))

    def test_agent_wake_dir_still_overrides(self):
        import agent_bus_watcher as w
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"AGENT_BRIDGE_DIR": "/nonexistent-bridge", "AGENT_WAKE_DIR": d}), \
                    mock.patch.object(w, "WAKE_DIR", None):
                self.assertEqual(w.wake_dir(), d)


class JointReviewPR1(Env):
    """H2 and M2 regression."""

    def _msg(self, sender, kind, body=""):
        return {"id": 1, "sender": sender, "kind": kind, "body": body}

    def test_H2_overlong_agent_name_in_json_body_is_refused(self):
        msg = self._msg("operator", aw.KIND_SLEEP, '{"agents": ["%s"]}' % ("X" * 300))
        self.assertEqual(aw.handle_operator_message(msg, verify=lambda m: "signed"), "ignored:bad-body")

    def test_H2_json_body_name_must_match_same_regex_as_plain(self):
        msg = self._msg("operator", aw.KIND_SLEEP, '{"agents": ["a/b"]}')
        self.assertEqual(aw.handle_operator_message(msg, verify=lambda m: "signed"), "ignored:bad-body")

    def test_H2_watcher_survives_crashing_operator_handler(self):
        import agent_bus_watcher as w
        rows = [{"id": 7, "sender": "operator", "kind": aw.KIND_SLEEP, "body": "x"}]
        with mock.patch.object(w.bus, "recv", return_value=rows), \
                mock.patch.object(w.aw, "handle_operator_message", side_effect=OSError(36, "File name too long")), \
                mock.patch.object(w, "wake", return_value="dry"):
            self.assertEqual(w.run("a1", self.tmp.name, poll=0, debounce=0, once=True), 7)

    def test_M2_keyless_operator_is_refused_by_default(self):
        aw.enter_sleep_safe("a1")
        res = aw.handle_operator_message(self._msg("operator", aw.KIND_WAKE, "a1"),
                                         verify=lambda m: "unsigned", has_key=False)
        self.assertEqual(res, "ignored:operator-no-key")
        self.assertTrue(aw.is_asleep("a1"))

    def test_M2_keyless_operator_allowed_only_with_explicit_dev_switch(self):
        aw.enter_sleep_safe("a1")
        with mock.patch.dict(os.environ, {"AGENT_WAKE_ALLOW_KEYLESS_OPERATOR": "1"}):
            res = aw.handle_operator_message(self._msg("operator", aw.KIND_WAKE, "a1"),
                                             verify=lambda m: "unsigned", has_key=False)
        self.assertEqual(res, "woke")


if __name__ == "__main__":
    unittest.main()
