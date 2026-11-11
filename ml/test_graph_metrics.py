import unittest

import numpy as np

from graph_metrics import attack_group_diagnostics, clustering_metrics


class GraphMetricsTest(unittest.TestCase):
    def test_perfect_partition_scores_one(self) -> None:
        result = clustering_metrics(np.array(["a", "a", "b"]), np.array([0, 0, 1]))
        self.assertAlmostEqual(result["bcubed_f1"], 1.0)
        self.assertAlmostEqual(result["ari"], 1.0)

    def test_merge_lowers_precision_and_split_lowers_recall(self) -> None:
        gold = np.array(["a", "a", "b", "b"])
        merged = clustering_metrics(gold, np.array([0, 0, 0, 0]))
        split = clustering_metrics(gold, np.array([0, 1, 2, 3]))
        self.assertLess(merged["bcubed_precision"], 1.0)
        self.assertAlmostEqual(merged["bcubed_recall"], 1.0)
        self.assertAlmostEqual(split["bcubed_precision"], 1.0)
        self.assertLess(split["bcubed_recall"], 1.0)

    def test_raw_weights_match_expanded_partition(self) -> None:
        weighted = clustering_metrics(
            np.array(["a", "b"]), np.array([0, 0]), np.array([2, 1])
        )
        expanded = clustering_metrics(
            np.array(["a", "a", "b"]), np.array([0, 0, 0])
        )
        for key in weighted:
            self.assertAlmostEqual(weighted[key], expanded[key])

    def test_attack_diagnostics_detect_fusion_and_fragmentation(self) -> None:
        result = attack_group_diagnostics(
            np.array(["a", "a", "b"]), np.array([0, 1, 1]), np.ones(3)
        )
        self.assertEqual(result["max_fragments_per_attack"], 2)
        self.assertEqual(result["fused_attack_clusters"], 1)


if __name__ == "__main__":
    unittest.main()
