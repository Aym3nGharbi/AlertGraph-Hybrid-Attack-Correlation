from __future__ import annotations

import unittest

from lab.dataset_v2.candidate_generator_scaling import benchmark, synthetic_metas


class CandidateGeneratorScalingTests(unittest.TestCase):
    def test_fixture_is_observable_and_has_no_supervision(self):
        row = synthetic_metas(1, "partitioned")[0]
        self.assertNotIn("attack_instance_id", row)
        self.assertNotIn("target", row)

    def test_benchmark_is_marked_synthetic_and_training_disabled(self):
        report = benchmark([10, 20])
        self.assertTrue(report["synthetic_only"])
        self.assertFalse(report["real_experimental_result"])
        self.assertFalse(report["training_ready"])
        self.assertEqual(len(report["rows"]), 4)

    def test_invalid_fixture_is_rejected(self):
        with self.assertRaises(ValueError):
            synthetic_metas(0, "partitioned")


if __name__ == "__main__":
    unittest.main()
