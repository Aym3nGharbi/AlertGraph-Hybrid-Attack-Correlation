from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lab.dataset_v2.a1_campaign_preflight import validate_a1_preflight
from lab.dataset_v2.prepare_campaign import prepare_campaign
from lab.dataset_v2.verify_ssh_activity_stage import _matching_wazuh_lines


def _synthetic_a1_plan() -> dict[str, object]:
    activities = []
    for key, role in (
        ("a1-failed-1", "failed-authentication"),
        ("a1-failed-2", "failed-authentication"),
        ("a1-success", "authorized-login-in-simulation"),
    ):
        activities.append({
            "key": key,
            "class": "attack",
            "attack_instance_key": "a1",
            "platform": "linux",
            "activity_role": role,
            "command_template": f"synthetic command for {key}",
            "proof_requirements": ["synthetic-proof"],
        })
    return {
        "scenario_template": "synthetic-a1-test",
        "machines": [
            {"role": "linux-target", "host": "192.0.2.20", "agent_name": "ubuntu-agent"}
        ],
        "activities": activities,
        "supervision_policy": {
            "version": "strict-verified-only-v2",
            "time_or_host_alone_is_sufficient": False,
            "absence_of_match_is_negative": False,
        },
        "pair_label_policy": {"supervision_fields_are_features": False},
        "safety_policy": {
            "maximum_failed_attempts_total": 2,
            "stop_conditions": ["synthetic-stop"],
        },
    }


class A1PreflightTests(unittest.TestCase):
    def test_a1_plan_has_one_instance_three_ordered_activities_and_no_a2_b1(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan = _synthetic_a1_plan()
            result = prepare_campaign(
                temporary, campaign_id="dev-a1-test", run_id="dev-a1-test-r01",
                partition="development", scenario_plan=plan, parameter_seed=4,
            )
            report = validate_a1_preflight(result["campaign_directory"])
            self.assertEqual(len(report["ordered_activities"]), 3)
            self.assertFalse(report["a2_or_b1_execution_allowed"])
            self.assertFalse(report["training_ready"])


class StageMatchingTests(unittest.TestCase):
    @staticmethod
    def _line(alert_id: str, port: int) -> bytes:
        value = {
            "timestamp": "2026-11-11T20:00:00.000+0000",
            "id": alert_id, "agent": {"name": "ubuntu-agent"},
            "data": {"srcip": "192.0.2.1", "srcport": str(port)},
            "full_log": f"host sshd[42]: Invalid user x from 192.0.2.1 port {port}",
        }
        return (json.dumps(value) + "\n").encode()

    def test_exact_tuple_matches_and_nearby_port_is_rejected(self):
        payload = self._line("one", 50001) + self._line("two", 50002)
        matches = _matching_wazuh_lines(
            payload, agent="ubuntu-agent", source_ip="192.0.2.1",
            source_port=50001, started=1794427199.0, ended=1794427201.0,
        )
        self.assertEqual(len(matches), 1)
        self.assertIn(b'"one"', matches[0])


if __name__ == "__main__":
    unittest.main()
