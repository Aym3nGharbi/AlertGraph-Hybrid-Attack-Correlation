from __future__ import annotations

import unittest

from lab.dataset_v2.strict_verified_pairs import derive_verified_meta_truth, label_verified_candidates


class StrictVerifiedPairTests(unittest.TestCase):
    def setUp(self):
        self.activities = {
            "a1-step1": {"class": "attack", "attack_instance_id": "attack:a1"},
            "a1-step2": {"class": "attack", "attack_instance_id": "attack:a1"},
            "a2": {"class": "attack", "attack_instance_id": "attack:a2"},
            "b1": {"class": "benign", "benign_activity_id": "benign:b1"},
            "b2": {"class": "benign", "benign_activity_id": "benign:b2"},
        }

    def test_meta_alert_accepts_multiple_activities_of_same_verified_attack(self):
        meta = [{"meta_id": "m1", "member_alert_ids": ["e1", "e2"]}]
        truth, excluded = derive_verified_meta_truth(meta, {"e1": "a1-step1", "e2": "a1-step2"}, self.activities)
        self.assertEqual(truth["m1"]["attack_instance_id"], "attack:a1")
        self.assertFalse(excluded)

    def test_mixed_attack_instances_are_excluded(self):
        meta = [{"meta_id": "m1", "member_alert_ids": ["e1", "e2"]}]
        truth, excluded = derive_verified_meta_truth(meta, {"e1": "a1-step1", "e2": "a2"}, self.activities)
        self.assertNotIn("m1", truth)
        self.assertEqual(excluded["m1"], "mixed-or-invalid-provenance")

    def test_only_strict_binary_cases_are_exported(self):
        truth = {
            "m1": {"class": "attack", "attack_instance_id": "attack:a1"},
            "m2": {"class": "attack", "attack_instance_id": "attack:a1"},
            "m3": {"class": "attack", "attack_instance_id": "attack:a2"},
            "m4": {"class": "benign", "benign_activity_id": "benign:b1"},
            "m5": {"class": "benign", "benign_activity_id": "benign:b2"},
        }
        candidates = [
            {"earlier_meta_id": "m1", "later_meta_id": "m2"},
            {"earlier_meta_id": "m1", "later_meta_id": "m3"},
            {"earlier_meta_id": "m1", "later_meta_id": "m4"},
            {"earlier_meta_id": "m4", "later_meta_id": "m5"},
            {"earlier_meta_id": "m1", "later_meta_id": "missing"},
        ]
        labels, excluded = label_verified_candidates(candidates, truth)
        self.assertEqual([x["target"] for x in labels], [1, 0, 0])
        self.assertEqual({x["reason"] for x in excluded}, {"benign-benign-not-supervised", "unverified-endpoint"})
        self.assertTrue(all(x["confidence"] == "verified" for x in labels))


if __name__ == "__main__":
    unittest.main()
