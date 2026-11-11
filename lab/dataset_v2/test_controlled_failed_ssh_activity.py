from __future__ import annotations

import unittest

from lab.dataset_v2.run_controlled_failed_ssh_activity import FIXED_INVALID_USER, build_failed_ssh_command, select_process_tuple


class ControlledFailedSSHCommandTests(unittest.TestCase):
    def test_command_is_single_noninteractive_public_key_attempt(self):
        command = build_failed_ssh_command("192.168.122.130", "test-key")
        joined = " ".join(command)
        self.assertIn("ConnectionAttempts=1", joined)
        self.assertIn("PasswordAuthentication=no", joined)
        self.assertIn("NumberOfPasswordPrompts=0", joined)
        self.assertIn(f"{FIXED_INVALID_USER}@192.168.122.130", joined)
        self.assertNotIn("StrictHostKeyChecking=no", joined)

    def test_another_invalid_username_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "fixe préenregistré"):
            build_failed_ssh_command("192.168.122.130", "test-key", invalid_user="other")

    def test_tuple_selection_requires_one_exact_pid_tuple(self):
        observations = [
            {"pid": 10, "source_ip": "192.168.122.1", "source_port": 50000, "target_ip": "192.168.122.130", "target_port": 22},
            {"pid": 20, "source_ip": "192.168.122.1", "source_port": 50001, "target_ip": "192.168.122.130", "target_port": 22},
        ]
        selected = select_process_tuple(observations, pid=10, target_ip="192.168.122.130")
        self.assertEqual(selected["source_port"], 50000)

    def test_ambiguous_pid_tuples_are_rejected(self):
        observations = [
            {"pid": 10, "source_ip": "192.168.122.1", "source_port": 50000, "target_ip": "192.168.122.130", "target_port": 22},
            {"pid": 10, "source_ip": "192.168.122.1", "source_port": 50001, "target_ip": "192.168.122.130", "target_port": 22},
        ]
        self.assertIsNone(select_process_tuple(observations, pid=10, target_ip="192.168.122.130"))


if __name__ == "__main__":
    unittest.main()
