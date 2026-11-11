import unittest

import numpy as np
import pandas as pd

from graph_reconstruction import (
    aggregate_graph_votes,
    bridge_prediction,
    legacy_mean_bridge_prediction,
)


class GraphReconstructionTests(unittest.TestCase):
    def setUp(self):
        self.meta = pd.DataFrame({"meta_id": ["a", "b", "c"]})
        self.pairs = pd.DataFrame(
            {
                "earlier_meta_id": ["a", "b", "a"],
                "later_meta_id": ["b", "c", "c"],
            }
        )
        self.scores = {
            "similarity": np.array([1.0, 1.0, 1.0]),
            "causality": np.array([1.0, 1.0, 1.0]),
            "stage_known": np.array([False, False, False]),
            "same_stage": np.array([False, False, False]),
            "compatible": np.array([False, False, False]),
        }

    def test_bridge_prediction_keeps_core_and_adds_only_connecting_bridges(self):
        result = bridge_prediction(
            self.meta,
            self.pairs,
            np.array([0.90, 0.80, 0.70]),
            self.scores,
            pair_threshold=0.85,
            bridge_threshold=0.50,
        )
        np.testing.assert_array_equal(result, [True, True, False])

    def test_vote_does_not_remove_cycle_after_aggregation(self):
        # Chaque fold produit une forêt différente; le vote final scientifique
        # peut former un cycle et ne doit pas être filtré une seconde fois.
        folds = [
            np.array([True, True, False]),
            np.array([True, False, True]),
            np.array([False, True, True]),
            np.array([True, True, False]),
            np.array([True, False, True]),
            np.array([False, True, True]),
        ]
        counts, result = aggregate_graph_votes(folds, quorum=4)
        np.testing.assert_array_equal(counts, [4, 4, 4])
        np.testing.assert_array_equal(result, [True, True, True])

    def test_legacy_mean_is_preserved_as_a_separate_strategy(self):
        result = legacy_mean_bridge_prediction(
            self.meta,
            self.pairs,
            np.array([0.90, 0.80, 0.70]),
            np.array([True, False, False]),
            self.scores,
            bridge_threshold=0.75,
        )
        np.testing.assert_array_equal(result, [True, True, False])

    def test_invalid_vote_quorum_is_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_graph_votes([np.array([True])], quorum=2)


if __name__ == "__main__":
    unittest.main()
