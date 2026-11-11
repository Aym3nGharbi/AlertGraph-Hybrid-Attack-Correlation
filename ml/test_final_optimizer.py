import unittest

from optimize_final_nested_ml import (
    FINAL_SEARCH_CONFIGURATIONS,
    configuration_features,
)


class FinalOptimizerTest(unittest.TestCase):
    def test_search_is_bounded_and_uses_authorized_values(self) -> None:
        self.assertGreaterEqual(len(FINAL_SEARCH_CONFIGURATIONS), 10)
        self.assertLessEqual(len(FINAL_SEARCH_CONFIGURATIONS), 15)
        for item in FINAL_SEARCH_CONFIGURATIONS:
            self.assertIn(item.learning_rate, {0.03, 0.05, 0.08})
            self.assertIn(item.max_leaf_nodes, {7, 15, 31})
            self.assertIn(item.min_samples_leaf, {50, 200})
            self.assertIn(item.l2_regularization, {1.0, 5.0, 10.0})
            self.assertIn(item.max_features, {0.7, 1.0})

    def test_rarity_and_mitre_variants_are_explicit(self) -> None:
        available = (
            "base",
            "tactic_known_both",
            "tactic_jaccard",
            "earlier_log1p_prior_candidate_degree",
        )
        rarity = next(item for item in FINAL_SEARCH_CONFIGURATIONS if item.name == "rarity-current")
        no_mitre = next(item for item in FINAL_SEARCH_CONFIGURATIONS if item.name == "no-mitre-current")
        self.assertIn("earlier_signature_train_idf", configuration_features(available, rarity))
        self.assertNotIn("tactic_jaccard", configuration_features(available, no_mitre))


if __name__ == "__main__":
    unittest.main()
