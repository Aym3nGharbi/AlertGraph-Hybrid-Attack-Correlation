import unittest

import pandas as pd
import numpy as np

from evaluate_attack_graphs import _edge_diagnostics
from optimize_graph_thresholds import (
    fast_graph_validation_metrics,
    prepare_fast_graph_truth,
    select_graph_threshold,
)


class GraphThresholdSelectionTest(unittest.TestCase):
    def test_empty_edge_diagnostics_has_selection_metrics(self) -> None:
        result = _edge_diagnostics(pd.DataFrame(), pd.DataFrame())
        self.assertEqual(result["predicted_edges"], 0)
        self.assertEqual(result["edge_precision_known"], 0.0)

    def test_fast_metrics_detect_attack_fusion(self) -> None:
        meta = pd.DataFrame(
            {
                "is_attack": [True, True],
                "attack_instance_id": ["A", "B"],
                "member_count": [2, 1],
                "ground_truth_phases": [["dirb"], ["dnsteal"]],
            }
        )
        prepared = prepare_fast_graph_truth(meta)
        result = fast_graph_validation_metrics(
            prepared, np.array([0, 0]), np.array([1, 0], dtype=np.int8)
        )
        self.assertEqual(result["fused_attack_clusters"], 1)
        self.assertEqual(result["edge_precision"], 0.5)

    def test_fusion_is_penalized_before_bcubed(self) -> None:
        selected = select_graph_threshold(
            [
                {"threshold": 0.5, "fused_scenarios": 1, "total_fused_clusters": 1, "macro_meta_bcubed_f1": 0.9, "macro_phase_recall": 0.9, "macro_edge_precision": 0.9},
                {"threshold": 0.8, "fused_scenarios": 0, "total_fused_clusters": 0, "macro_meta_bcubed_f1": 0.5, "macro_phase_recall": 0.5, "macro_edge_precision": 0.9},
            ]
        )
        self.assertEqual(selected["threshold"], 0.8)

    def test_bcubed_breaks_tie_before_phase_recall(self) -> None:
        selected = select_graph_threshold(
            [
                {"threshold": 0.7, "fused_scenarios": 0, "total_fused_clusters": 0, "macro_meta_bcubed_f1": 0.6, "macro_phase_recall": 0.9, "macro_edge_precision": 0.9},
                {"threshold": 0.8, "fused_scenarios": 0, "total_fused_clusters": 0, "macro_meta_bcubed_f1": 0.7, "macro_phase_recall": 0.5, "macro_edge_precision": 0.9},
            ]
        )
        self.assertEqual(selected["threshold"], 0.8)


if __name__ == "__main__":
    unittest.main()
