"""bus_singleflight — "one agent — one instance" regression. stdlib unittest.

The tests start REAL OS processes with the documented CLI (`python3 bus_singleflight.py acquire …`),
because the B1 bug showed up exactly on the short-lived CLI call: the lock's owner died at the end of the call."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_singleflight as sf  # noqa: E402


def _cli(bridge, *args):
    env = dict(os.environ, AGENT_BRIDGE_DIR=bridge)
    return subprocess.Popen([sys.executable, os.path.join(HERE, "bus_singleflight.py"), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)


class SessionLockCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bridge = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _statuses(self, procs):
        out = []
        for p in procs:
            so, _ = p.communicate(timeout=30)
            out.append((p.returncode, so.strip()))
        return out

    def test_B1_concurrent_distinct_instances_only_one_acquires(self):
        """two concurrent `acquire --instance PROC_A/PROC_B` → exactly one wins."""
        for _ in range(5):
            agent = "race%d" % _
            res = self._statuses([_cli(self.bridge, "acquire", "--agent", agent, "--instance", "PROC_A"),
                                  _cli(self.bridge, "acquire", "--agent", agent, "--instance", "PROC_B")])
            acquired = [r for r in res if "status=acquired" in r[1]]
            self.assertEqual(len(acquired), 1, res)
            self.assertEqual(sorted(r[0] for r in res), [0, 3], res)

    def test_B1_sequential_bare_acquire_does_not_steal(self):
        """sequential, flagless `acquire --agent X` shifted by 1 second.
        From the same calling process (the same owner) → the second gets THE SAME identity
        back (already-own), a new instance does NOT take over; ANOTHER, live owner → duplicate."""
        r1 = self._statuses([_cli(self.bridge, "acquire", "--agent", "race2")])[0]
        self.assertEqual(r1[0], 0, r1)
        inst1 = r1[1].split()[0]
        time.sleep(1)
        r2 = self._statuses([_cli(self.bridge, "acquire", "--agent", "race2")])[0]
        self.assertEqual(r2[0], 0, r2)
        self.assertIn("status=already-own", r2[1])
        self.assertEqual(r2[1].split()[0], inst1)
        other = subprocess.Popen(["sleep", "30"])
        try:
            r3 = self._statuses([_cli(self.bridge, "acquire", "--agent", "race2", "--owner-pid", str(other.pid))])[0]
            self.assertEqual(r3[0], 3, r3)
            self.assertIn("status=duplicate", r3[1])
        finally:
            other.kill(); other.wait()

    def test_B1var_owner_pid_vs_nonexistent_target_never_double_acquired(self):
        """re-measurement (B1-var): `--owner-pid` vs `--target nemletezo-session` for the same
        agent, 15 rounds → there can never be two `acquired`. Previously 9/15 double: the other saw a lock written with a never-live target
        as stale immediately and reclaimed it, while the first had already got `acquired`."""
        other = subprocess.Popen(["sleep", "60"])
        try:
            for i in range(15):
                agent = "b1var%d" % i
                res = self._statuses([
                    _cli(self.bridge, "acquire", "--agent", agent, "--owner-pid", str(other.pid)),
                    _cli(self.bridge, "acquire", "--agent", agent, "--instance", "FAKE_T",
                         "--target", "nemletezo-session-b1var-%d" % i)])
                acquired = [r for r in res if "status=acquired" in r[1]]
                self.assertLessEqual(len(acquired), 1, res)
        finally:
            other.kill(); other.wait()


def _api_acquire(bridge, agent, instance, target=None, owner_pid=None):
    code = ("import sys; sys.path.insert(0, %r); import bus_singleflight as sf; "
            "st, _ = sf.SessionLock(%r, bridge=%r).acquire(%r, target=%r, owner_pid=%r); print('status=' + st)"
            % (HERE, agent, bridge, instance, target, owner_pid))
    return subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


class OwnerNotLiveB1var2(unittest.TestCase):
    """CHANGES_REQUESTED, the B1-var fix (317702e) closed only the target branch.
    A lock written with a NEVER-LIVE owner pid (or a dead derived pid) is seen as stale immediately by the other caller and
    reclaimed, while the first has already got `acquired` → two workers. Measured: 7/15 double acquired.
    4 cases × 15 rounds, real parallel processes, real pid liveness and a real tmux pane."""
    ROUNDS = 15
    NEVER = 999999999                                           # a pid that never lived

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bridge = self.tmp.name
        self.live = subprocess.Popen(["sleep", "120"])
        self.sess = "sfb1v2%d" % os.getpid()
        self.have_tmux = subprocess.run(["tmux", "new-session", "-d", "-s", self.sess, "sleep 120"],
                                        capture_output=True).returncode == 0

    def tearDown(self):
        self.live.kill(); self.live.wait()
        if self.have_tmux:
            subprocess.run(["tmux", "kill-session", "-t", self.sess], capture_output=True)
        self.tmp.cleanup()

    def _race(self, tag, left, right):
        doubles = 0
        for i in range(self.ROUNDS):
            agent = "%s%d" % (tag, i)
            procs = [_api_acquire(self.bridge, agent, **left), _api_acquire(self.bridge, agent, **right)]
            outs = [p.communicate(timeout=30)[0].strip() for p in procs]
            if sum("status=acquired" in o for o in outs) > 1:
                doubles += 1
        return doubles

    def test_dead_owner_vs_live_owner_never_double(self):
        self.assertEqual(self._race("o", dict(instance="A", owner_pid=self.NEVER),
                                    dict(instance="B", owner_pid=self.live.pid)), 0)

    def test_live_panel_dead_owner_vs_live_panel_live_owner_never_double(self):
        if not self.have_tmux:
            self.skipTest("no tmux")
        self.assertEqual(self._race("p", dict(instance="A", target=self.sess, owner_pid=self.NEVER),
                                    dict(instance="B", target=self.sess, owner_pid=self.live.pid)), 0)

    def test_ttl_branch_dead_instance_vs_live_instance_never_double(self):
        self.assertEqual(self._race("t", dict(instance="host:%d" % self.NEVER),
                                    dict(instance="host:%d" % self.live.pid)), 0)

    def test_control_two_live_owners_never_double(self):
        other = subprocess.Popen(["sleep", "120"])
        try:
            self.assertEqual(self._race("c", dict(instance="A", owner_pid=self.live.pid),
                                        dict(instance="B", owner_pid=other.pid)), 0)
        finally:
            other.kill(); other.wait()

    def test_dead_owner_is_refused_and_writes_nothing(self):
        lock = sf.SessionLock("onl", bridge=self.bridge)
        st, _ = lock.acquire("A", owner_pid=self.NEVER)
        self.assertEqual(st, "owner-not-live")
        self.assertIsNone(lock.holder())
        r = subprocess.run([sys.executable, os.path.join(HERE, "bus_singleflight.py"), "acquire", "--agent", "onl2",
                            "--owner-pid", str(self.NEVER)], capture_output=True, text=True,
                           env=dict(os.environ, AGENT_BRIDGE_DIR=self.bridge), timeout=30)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("owner-not-live", r.stdout)


class SessionLockLiveness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_H1_target_alive_but_owner_pid_dead_is_stale(self):
        """the tmux pane is alive, but the explicit owner pid DIES → the lock must NOT get stuck.
        B1var-2  rewording: the earlier version got `acquired` with a NEVER-LIVE owner pid, and so
        pinned exactly the double acquired as the expectation. H1's goal stays, with a real life cycle: the owner is alive at
        acquire → acquired; `kill -9` → per the guard the lock is no longer alive → a new caller (with a live owner) claims it."""
        owner = subprocess.Popen(["sleep", "120"])
        lock = sf.SessionLock("tmuxtest", bridge=self.tmp.name, target_alive=lambda t: True)
        st, _ = lock.acquire("workerX", target="sftest:0.0", owner_pid=owner.pid)
        self.assertEqual(st, "acquired")
        self.assertTrue(lock._holder_alive(lock.holder(), time.time_ns()))
        owner.kill(); owner.wait()                                               # kill -9
        self.assertFalse(lock._holder_alive(lock.holder(), time.time_ns()))      # guard: clean
        heir = subprocess.Popen(["sleep", "120"])
        try:
            st2, h = sf.SessionLock("tmuxtest", bridge=self.tmp.name, target_alive=lambda t: True).acquire(
                "workerY", target="sftest:0.0", owner_pid=heir.pid)
            self.assertEqual((st2, h["instance"]), ("acquired", "workerY"))
        finally:
            heir.kill(); heir.wait()

    def test_H1_target_without_owner_pid_still_uses_pane(self):
        lock = sf.SessionLock("t2", bridge=self.tmp.name, is_alive=lambda pid: False, target_alive=lambda t: True)
        lock.acquire("w1", target="s:0.0")
        self.assertTrue(lock._holder_alive(lock.holder(), time.time_ns()))

    def test_B1var_acquire_with_dead_target_is_refused_and_writes_nothing(self):
        """A non-live target at the moment of acquire → `target-not-live`, and the lock file is NOT created
        (a lock written with a never-live target would immediately be stale for everyone else → an exclusivity violation)."""
        lock = sf.SessionLock("t4", bridge=self.tmp.name, is_alive=lambda pid: True, target_alive=lambda t: False)
        st, _ = lock.acquire("w1", target="nosuch:0.0")
        self.assertEqual(st, "target-not-live")
        self.assertIsNone(lock.holder())

    def test_ttl_without_pid_is_alive_until_ttl(self):
        """A non-pid-shaped instance (e.g. "PROC_A") + no owner pid: a fresh lock is ALIVE until the TTL (previously it was immediately dead)."""
        lock = sf.SessionLock("t3", bridge=self.tmp.name, is_alive=lambda pid: False, ttl_ns=10 * 10**9)
        now = time.time_ns()
        lock.acquire("PROC_A", now_ns=now)
        self.assertTrue(lock._holder_alive(lock.holder(), now + 5 * 10**9))
        self.assertFalse(lock._holder_alive(lock.holder(), now + 11 * 10**9))


class MessageClaimBasics(unittest.TestCase):
    def test_claim_is_exclusive(self):
        with tempfile.TemporaryDirectory() as d:
            inbox = os.path.join(d, "inbox", "a")
            os.makedirs(inbox)
            for i in range(5):
                with open(os.path.join(inbox, "m%d.json" % i), "w") as f:
                    json.dump({"i": i}, f)
            a = sf.MessageClaim("a", "ia", bridge=d)
            b = sf.MessageClaim("a", "ib", bridge=d)
            won_a = a.claim_pending()
            won_b = b.claim_pending()
            self.assertEqual(len(won_a), 5)
            self.assertEqual(won_b, [])


if __name__ == "__main__":
    unittest.main()
