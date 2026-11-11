import unittest

import numpy as np
import pandas as pd

from experiment_consensus_before_forest import consensus_before_forest


class ConsensusBeforeForestTests(unittest.TestCase):
    def setUp(self):
        self.meta = pd.DataFrame({"meta_id": ["a", "b", "c"]})
        self.pairs = pd.DataFrame(
            {
                "earlier_meta_id": ["a", "b", "a"],
                "later_meta_id": ["b", "c", "c"],
            }
        )

    def test_alternative_fold_bridges_are_recovered_before_forest(self):
        # Deux forêts choisissent des ponts alternatifs. Leur vote exact ne
        # conserve que a-b et fragmente c; le consensus d'admissibilité garde
        # les trois candidats puis une forêt unique reconnecte c.
        fold_one = np.array([True, True, False])
        fold_two = np.array([True, False, True])
        baseline = (fold_one.astype(int) + fold_two.astype(int)) >= 2
        np.testing.assert_array_equal(baseline, [True, False, False])
        result = consensus_before_forest(
            self.meta,
            self.pairs,
            core_votes=np.zeros(3, dtype=int),
            admissible_votes=np.array([2, 2, 2]),
            mean_probability=np.array([0.9, 0.8, 0.7]),
            quorum=2,
        )
        np.testing.assert_array_equal(result, [True, True, False])

    def test_consensus_core_is_preserved_and_bridge_does_not_create_cycle(self):
        result = consensus_before_forest(
            self.meta,
            self.pairs,
            core_votes=np.array([4, 0, 0]),
            admissible_votes=np.array([4, 4, 4]),
            mean_probability=np.array([0.7, 0.8, 0.9]),
            quorum=4,
        )
        np.testing.assert_array_equal(result, [True, False, True])

    def test_vote_count_precedes_mean_probability(self):
        result = consensus_before_forest(
            self.meta,
            self.pairs,
            core_votes=np.zeros(3, dtype=int),
            admissible_votes=np.array([8, 4, 4]),
            mean_probability=np.array([0.51, 0.99, 0.98]),
            quorum=4,
        )
        np.testing.assert_array_equal(result, [True, True, False])

    def test_below_quorum_cross_candidate_is_excluded(self):
        result = consensus_before_forest(
            self.meta.iloc[:2],
            self.pairs.iloc[:1],
            core_votes=np.array([0]),
            admissible_votes=np.array([3]),
            mean_probability=np.array([0.99]),
            quorum=4,
        )
        np.testing.assert_array_equal(result, [False])

    def test_at_quorum_cross_candidate_has_no_implicit_safety_gate(self):
        # Le consensus n'utilise aucune vérité A/B. Une relation erronée qui
        # atteint le quorum reste donc un risque à mesurer expérimentalement.
        result = consensus_before_forest(
            self.meta.iloc[:2],
            self.pairs.iloc[:1],
            core_votes=np.array([0]),
            admissible_votes=np.array([4]),
            mean_probability=np.array([0.99]),
            quorum=4,
        )
        np.testing.assert_array_equal(result, [True])

    def test_invalid_alignment_is_rejected(self):
        with self.assertRaises(ValueError):
            consensus_before_forest(
                self.meta,
                self.pairs,
                core_votes=np.array([1]),
                admissible_votes=np.array([1, 1, 1]),
                mean_probability=np.array([0.5, 0.5, 0.5]),
            )


if __name__ == "__main__":
    unittest.main()
