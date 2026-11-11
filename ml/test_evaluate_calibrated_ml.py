import unittest

import numpy as np

from evaluate_calibrated_ml import mean_positive_probability


class _FakeModel:
    def __init__(self, positive_probability):
        self.positive_probability = positive_probability

    def predict_proba(self, x):
        positive = np.full(len(x), self.positive_probability)
        return np.column_stack((1 - positive, positive))


class EvaluateCalibratedMlTest(unittest.TestCase):
    def test_averages_probabilities_from_group_models(self) -> None:
        x = np.zeros((3, 2))
        probability = mean_positive_probability(
            [_FakeModel(0.2), _FakeModel(0.8)], x
        )
        self.assertTrue(np.allclose(probability, 0.5))

    def test_requires_at_least_one_model(self) -> None:
        with self.assertRaises(ValueError):
            mean_positive_probability([], np.zeros((1, 2)))


if __name__ == "__main__":
    unittest.main()
