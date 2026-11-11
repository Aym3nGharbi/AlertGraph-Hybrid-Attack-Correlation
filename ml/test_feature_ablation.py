import unittest

from feature_sets import (
    CAUSALITY_FEATURES,
    CONTEXT_FEATURES,
    DIRECTION_FEATURES,
    GRAPH_CONTEXT_FEATURES,
    MITRE_FEATURES,
    SIGNATURE_TEXT_FEATURES,
    select_feature_profile,
    select_scientific_ablation_profile,
)


class FeatureAblationTest(unittest.TestCase):
    def test_groups_are_nonempty_and_disjoint(self) -> None:
        self.assertTrue(DIRECTION_FEATURES)
        self.assertTrue(CONTEXT_FEATURES)
        self.assertFalse(DIRECTION_FEATURES & CONTEXT_FEATURES)
        self.assertFalse(DIRECTION_FEATURES & GRAPH_CONTEXT_FEATURES)
        self.assertFalse(CONTEXT_FEATURES & GRAPH_CONTEXT_FEATURES)

    def test_directional_profile_excludes_context_only(self) -> None:
        available = (
            "base",
            *sorted(DIRECTION_FEATURES),
            *sorted(CONTEXT_FEATURES),
            *sorted(GRAPH_CONTEXT_FEATURES),
        )
        selected = select_feature_profile(available, "directional")
        self.assertIn("base", selected)
        self.assertTrue(DIRECTION_FEATURES <= set(selected))
        self.assertFalse(CONTEXT_FEATURES & set(selected))
        self.assertFalse(GRAPH_CONTEXT_FEATURES & set(selected))

    def test_directional_graph_adds_only_graph_context(self) -> None:
        available = (
            "base",
            *sorted(DIRECTION_FEATURES),
            *sorted(CONTEXT_FEATURES),
            *sorted(GRAPH_CONTEXT_FEATURES),
        )
        selected = set(select_feature_profile(available, "directional_graph"))
        self.assertIn("base", selected)
        self.assertTrue(DIRECTION_FEATURES <= selected)
        self.assertTrue(GRAPH_CONTEXT_FEATURES <= selected)
        self.assertFalse(CONTEXT_FEATURES & selected)

    def test_scientific_ablation_profiles_are_explicit(self) -> None:
        available = tuple(
            sorted(
                {
                    "delta_seconds",
                    "same_signature",
                    "signature_text_jaccard",
                    *CAUSALITY_FEATURES,
                    *DIRECTION_FEATURES,
                    *CONTEXT_FEATURES,
                }
            )
        )
        hybrid = set(select_scientific_ablation_profile(available, "hybrid"))
        similarity = set(
            select_scientific_ablation_profile(available, "similarity_only")
        )
        causality = set(
            select_scientific_ablation_profile(available, "causality_only")
        )

        self.assertFalse(hybrid & CONTEXT_FEATURES)
        self.assertEqual(causality, hybrid & CAUSALITY_FEATURES)
        self.assertEqual(similarity, hybrid - CAUSALITY_FEATURES)
        self.assertTrue(DIRECTION_FEATURES <= similarity)

    def test_mitre_and_signature_text_ablate_only_their_group(self) -> None:
        available = tuple(
            sorted(
                {
                    "delta_seconds",
                    "same_signature",
                    "signature_text_jaccard",
                    *CAUSALITY_FEATURES,
                }
            )
        )
        hybrid = set(select_scientific_ablation_profile(available, "hybrid"))
        without_mitre = set(
            select_scientific_ablation_profile(
                available, "hybrid_without_mitre"
            )
        )
        without_text = set(
            select_scientific_ablation_profile(
                available, "hybrid_without_signature_text"
            )
        )

        self.assertEqual(hybrid - without_mitre, hybrid & MITRE_FEATURES)
        self.assertEqual(
            hybrid - without_text, hybrid & SIGNATURE_TEXT_FEATURES
        )

    def test_unknown_scientific_ablation_profile_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            select_scientific_ablation_profile(("base",), "unknown")


if __name__ == "__main__":
    unittest.main()
