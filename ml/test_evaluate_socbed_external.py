import unittest

import numpy as np

from evaluate_socbed_external import ensemble_metrics


class ExternalEnsembleTests(unittest.TestCase):
    def test_four_votes_are_positive_without_external_threshold(self):
        y = np.array([1, 0], dtype=np.int8)
        scores = np.array([[0.8, 0.2]] * 8)
        votes = np.array(
            [[True, False]] * 4 + [[False, False]] * 4,
            dtype=bool,
        )
        result = ensemble_metrics(y, scores, votes)
        self.assertEqual(result["predicted_positive"], 1)
        self.assertEqual(result["f1"], 1.0)


if __name__ == "__main__":
    unittest.main()
