import unittest

import numpy as np

from evaluate_nested_ml import (
    assemble_weighted_training,
    deterministic_indices,
    select_macro_threshold,
)


class EvaluateNestedMlTest(unittest.TestCase):
    def test_sampling_is_deterministic_and_caps_each_class(self) -> None:
        y = np.array([0] * 20 + [1] * 10, dtype=np.int8)
        first = deterministic_indices(y, 5, 123)
        second = deterministic_indices(y, 5, 123)
        self.assertTrue(np.array_equal(first, second))
        self.assertEqual(np.count_nonzero(y[first] == 0), 5)
        self.assertEqual(np.count_nonzero(y[first] == 1), 5)

    def test_training_weights_equalize_scenario_class_mass(self) -> None:
        data = {
            "a": (np.arange(12).reshape(6, 2), np.array([0, 0, 0, 0, 1, 1])),
            "b": (np.arange(8).reshape(4, 2), np.array([0, 0, 1, 1])),
        }
        _, y, weights = assemble_weighted_training(data, ("a", "b"), 10)
        # Quatre blocs scénario/classe reçoivent chacun la même masse.
        expected_mass = weights.sum() / 4
        offset = 0
        for scenario in ("a", "b"):
            scenario_y = data[scenario][1]
            for target in (0, 1):
                count = np.count_nonzero(scenario_y == target)
                block_y = y[offset : offset + count]
                block_weights = weights[offset : offset + count]
                self.assertTrue(np.all(block_y == target))
                self.assertAlmostEqual(float(block_weights.sum()), expected_mass)
                offset += count

    def test_macro_threshold_does_not_pool_scenario_sizes(self) -> None:
        predictions = {
            "small": (np.array([0, 1]), np.array([0.1, 0.9])),
            "large": (np.array([0, 0, 1, 1]), np.array([0.2, 0.3, 0.7, 0.8])),
        }
        threshold, macro_f1 = select_macro_threshold(predictions)
        self.assertGreater(threshold, 0.3)
        self.assertEqual(macro_f1, 1.0)


if __name__ == "__main__":
    unittest.main()
