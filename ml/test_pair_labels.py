import unittest

from ait_labels import adapt_label
from pair_labels import make_pair_label


class PairLabelsTest(unittest.TestCase):
    def test_same_scenario_and_family_is_positive(self) -> None:
        left = adapt_label("fox", "dirb", "dirb")
        right = adapt_label("fox", "webshell", "webshell_cmd")

        pair = make_pair_label(left, right)

        self.assertEqual(pair.target, 1)
        self.assertEqual(pair.confidence, "high")

    def test_two_attack_families_in_same_scenario_are_negative(self) -> None:
        left = adapt_label("santos", "dirb", "dirb")
        right = adapt_label("santos", "false_positive", "dnsteal")

        pair = make_pair_label(left, right)

        self.assertEqual(pair.target, 0)
        self.assertEqual(pair.reason, "different-attack-instances")

    def test_repeated_plan_in_different_scenarios_is_negative(self) -> None:
        left = adapt_label("fox", "dirb", "dirb")
        right = adapt_label("wilson", "dirb", "dirb")

        self.assertEqual(make_pair_label(left, right).target, 0)

    def test_temporal_benign_pair_is_weak_negative(self) -> None:
        left = adapt_label("fox", "false_positive", "-")
        right = adapt_label("fox", "dirb", "dirb")

        pair = make_pair_label(left, right)

        self.assertEqual(pair.target, 0)
        self.assertEqual(pair.confidence, "weak")
        self.assertEqual(pair.reason, "attack-versus-benign")

    def test_unknown_label_is_excluded(self) -> None:
        left = adapt_label("fox", "dirb", "unmapped")
        right = adapt_label("fox", "dirb", "dirb")

        self.assertIsNone(make_pair_label(left, right).target)


if __name__ == "__main__":
    unittest.main()

