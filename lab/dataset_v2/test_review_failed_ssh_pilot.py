from __future__ import annotations

import unittest

from lab.dataset_v2.review_failed_ssh_pilot import exact_failed_ssh_identity


class FailedSSHPilotIdentityTests(unittest.TestCase):
    def test_missing_controller_socket_never_becomes_verified_identity(self):
        self.assertIsNone(exact_failed_ssh_identity(
            {"controller_socket": None, "identity_capture_complete": False},
            source_ip="192.168.122.1", source_port=63286,
            target_ip="192.168.122.130", pid="5322", boot_id="boot",
        ))

    def test_exact_controller_tuple_produces_identity(self):
        result = {"identity_capture_complete": True, "controller_socket": {
            "source_ip": "192.168.122.1", "source_port": 63286,
            "target_ip": "192.168.122.130", "target_port": 22,
        }}
        identity = exact_failed_ssh_identity(
            result, source_ip="192.168.122.1", source_port=63286,
            target_ip="192.168.122.130", pid="5322", boot_id="boot",
        )
        self.assertEqual(identity, "ssh-failed:boot:5322:192.168.122.1:63286:192.168.122.130:22")

    def test_mismatched_port_is_rejected(self):
        result = {"identity_capture_complete": True, "controller_socket": {
            "source_ip": "192.168.122.1", "source_port": 60000,
            "target_ip": "192.168.122.130", "target_port": 22,
        }}
        self.assertIsNone(exact_failed_ssh_identity(
            result, source_ip="192.168.122.1", source_port=63286,
            target_ip="192.168.122.130", pid="5322", boot_id="boot",
        ))


if __name__ == "__main__":
    unittest.main()
