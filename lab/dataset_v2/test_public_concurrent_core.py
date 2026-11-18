"""Synthetic process cleanup and scheduler regressions; no VM access."""
import sys
import unittest
from unittest.mock import Mock
import psutil
from lab.dataset_v2.tracked_processes import TrackedProcessSupervisor
from lab.dataset_v2.concurrent_activity_scheduler import run_concurrent_schedule

class CleanupRegressionTests(unittest.TestCase):
    def registered(self):
        supervisor = TrackedProcessSupervisor()
        process = Mock(); process.pid = 123456
        process.create_time.return_value = 100.0
        process.is_running.return_value = True
        process.children.return_value = []
        supervisor._processes[process.pid] = Mock()
        supervisor._remember(process, process.pid)
        return supervisor, process

    def test_failed_terminate_and_kill_never_disappear_from_registry(self):
        s, p = self.registered()
        p.terminate.side_effect = psutil.AccessDenied(p.pid)
        p.kill.side_effect = psutil.AccessDenied(p.pid)
        for _ in range(2):
            result = s.terminate_tree(p.pid, graceful_seconds=0, kill_seconds=0)
            self.assertFalse(result['confirmed_stopped'])
            self.assertFalse(s.report()['confirmed_stopped'])
            self.assertEqual(s.report()['unconfirmed_pids'], [p.pid])
        self.assertEqual(len(s._records), 1)
        p.is_running.return_value = False
        self.assertTrue(s.report()['confirmed_stopped'])

    def test_unknown_process_state_blocks_cleanup(self):
        s, p = self.registered()
        p.is_running.side_effect = psutil.AccessDenied(p.pid)
        self.assertFalse(s.confirm_clean()['confirmed_stopped'])
        self.assertEqual(s.report()['process_states'][0]['state'], 'uncertain')

    def test_reused_pid_is_not_signalled(self):
        s, p = self.registered()
        p.is_running.return_value = False  # psutil detects create_time mismatch
        s.terminate_tree(p.pid, graceful_seconds=0, kill_seconds=0)
        p.terminate.assert_not_called(); p.kill.assert_not_called()

    def test_tracked_child_survives_root_exit_and_blocks_success(self):
        s, p = self.registered()
        child = Mock(); child.pid = 123457; child.create_time.return_value = 101.
        child.is_running.return_value = True; child.children.return_value = []
        s._remember(child, p.pid)
        p.is_running.return_value = False
        s.terminate_tree(p.pid, graceful_seconds=0, kill_seconds=0)
        self.assertFalse(s.confirm_clean()['confirmed_stopped'])
        self.assertIn(child.pid, s.report()['unconfirmed_pids'])

    def test_cancel_blocks_future_launch(self):
        s = TrackedProcessSupervisor(); s.terminate_all()
        with self.assertRaises(RuntimeError):
            s.spawn([sys.executable, '-c', 'pass'])

class TrackedProcessTests(unittest.TestCase):
    def test_normal_process_is_confirmed_clean(self):
        supervisor = TrackedProcessSupervisor()
        process = supervisor.spawn([sys.executable, "-c", "print('ok')"])
        stdout, _ = supervisor.communicate(process, timeout=2)
        self.assertEqual(stdout.strip(), b"ok")
        self.assertTrue(supervisor.confirm_clean()["confirmed_stopped"])

    def test_timeout_kills_root_and_persistent_child(self):
        supervisor = TrackedProcessSupervisor()
        code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); time.sleep(30)"
        process = supervisor.spawn([sys.executable, "-c", code])
        with self.assertRaises(TimeoutError):
            supervisor.communicate(process, timeout=.15)
        self.assertTrue(supervisor.confirm_clean()["confirmed_stopped"])
        event = supervisor.report()["events"][-1]
        self.assertTrue(event["confirmed_stopped"])
        self.assertGreaterEqual(len(event["tracked_pids"]), 1)

    def test_global_timeout_invokes_cleanup_before_return(self):
        supervisor = TrackedProcessSupervisor()

        def worker(_: str):
            process = supervisor.spawn([sys.executable, "-c", "import time;time.sleep(30)"])
            stdout, stderr = supervisor.communicate(process, timeout=20)
            if process.returncode: raise RuntimeError("terminated")
            return (stdout, stderr)

        activity = [{"activity_key": "slow", "execution_order": 1,
                     "planned_offset_seconds": 0, "maximum_duration_seconds": .05}]
        with self.assertRaises(TimeoutError):
            run_concurrent_schedule(
                activity, worker, maximum_start_lateness_seconds=.1,
                global_grace_seconds=0, cleanup_wait_seconds=2,
                critical_failure_callback=supervisor.terminate_all,
            )
        self.assertTrue(supervisor.confirm_clean()["confirmed_stopped"])

    def test_unconfirmed_cleanup_is_explicit(self):
        class FakeSupervisor(TrackedProcessSupervisor):
            def confirm_clean(self):
                return {"confirmed_stopped": False, "alive_tracked_root_pids": [12345]}
        self.assertFalse(FakeSupervisor().report()["confirmed_stopped"])
