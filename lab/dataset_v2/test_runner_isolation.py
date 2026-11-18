from __future__ import annotations

import unittest

from lab.dataset_v2.runner_isolation import (
    classify_meta_provenance,
    default_runner_isolation_policy,
    technical_session_receipt,
    validate_runner_isolation_policy,
)


class RunnerIsolationTests(unittest.TestCase):
    def test_default_policy_preserves_compression_and_requires_stabilization(self):
        result = validate_runner_isolation_policy(default_runner_isolation_policy())
        self.assertEqual(result["collapse_seconds"], 2.0)
        self.assertEqual(result["stabilization_seconds"], 3.0)
        self.assertFalse(result["training_ready"])

    def test_stabilization_not_beyond_compression_is_rejected(self):
        policy = default_runner_isolation_policy()
        policy["stabilization_after_ready_seconds"] = 2.0
        with self.assertRaisesRegex(ValueError, "dépasser strictement"):
            validate_runner_isolation_policy(policy)

    def test_mixed_technical_and_activity_meta_is_excluded(self):
        result = classify_meta_provenance(
            ["activity-event", "collector-event"],
            {
                "activity-event": {"decision": "member-verified", "activity_id": "activity:a1"},
                "collector-event": {"decision": "nonmember-verified", "activity_id": None},
            },
        )
        self.assertFalse(result["eligible"])
        self.assertIn("technical", result["reason"])

    def test_same_verified_activity_meta_is_eligible(self):
        result = classify_meta_provenance(
            ["e1", "e2"],
            {
                "e1": {"decision": "member-verified", "activity_id": "activity:a1"},
                "e2": {"decision": "member-verified", "activity_id": "activity:a1"},
            },
        )
        self.assertTrue(result["eligible"])
        self.assertEqual(result["activity_id"], "activity:a1")

    def test_technical_session_requires_tuple_and_pre_window_open(self):
        values = {"source_ip": "192.0.2.1", "source_port": 50000, "target_ip": "192.0.2.2", "target_port": 22}
        receipt = technical_session_receipt(
            role="journal-collector", process_id=10, connection_tuple=values,
            opened_before_experimental_window=True,
        )
        self.assertFalse(receipt["eligible_for_supervision"])
        with self.assertRaisesRegex(ValueError, "fenêtre"):
            technical_session_receipt(
                role="diagnostic", process_id=11, connection_tuple=values,
                opened_before_experimental_window=False,
            )


if __name__ == "__main__":
    unittest.main()
