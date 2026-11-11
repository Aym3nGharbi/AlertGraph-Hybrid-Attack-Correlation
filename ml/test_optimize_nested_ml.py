import unittest

from optimize_nested_ml import select_configuration


class OptimizeNestedMlTest(unittest.TestCase):
    def test_selection_uses_f1_within_ap_tolerance(self) -> None:
        evaluations = [
            {
                "name": "highest-ap",
                "macro_average_precision": 0.80,
                "macro_f1": 0.60,
                "worst_scenario_average_precision": 0.20,
                "std_average_precision": 0.2,
                "feature_count": 20,
            },
            {
                "name": "robust-f1",
                "macro_average_precision": 0.795,
                "macro_f1": 0.70,
                "worst_scenario_average_precision": 0.30,
                "std_average_precision": 0.1,
                "feature_count": 15,
            },
        ]
        self.assertEqual(
            select_configuration(evaluations)["name"], "robust-f1"
        )

    def test_selection_rejects_large_ap_loss(self) -> None:
        evaluations = [
            {
                "name": "best-ap",
                "macro_average_precision": 0.80,
                "macro_f1": 0.60,
                "worst_scenario_average_precision": 0.20,
                "std_average_precision": 0.2,
                "feature_count": 20,
            },
            {
                "name": "too-far",
                "macro_average_precision": 0.78,
                "macro_f1": 0.90,
                "worst_scenario_average_precision": 0.50,
                "std_average_precision": 0.1,
                "feature_count": 10,
            },
        ]
        self.assertEqual(select_configuration(evaluations)["name"], "best-ap")


if __name__ == "__main__":
    unittest.main()
