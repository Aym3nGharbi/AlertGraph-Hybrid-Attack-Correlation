import unittest

import numpy as np

from rarity_features import append_pair_rarity, signature_idf


class RarityFeaturesTest(unittest.TestCase):
    def test_unseen_signature_receives_maximum_rarity(self) -> None:
        values = signature_idf(np.array([100, 10, 0]))
        self.assertLess(values[0], values[1])
        self.assertLess(values[1], values[2])

    def test_append_pair_rarity_respects_sample_indices(self) -> None:
        x = np.array([[1.0], [2.0]], dtype=np.float32)
        result = append_pair_rarity(
            x,
            np.array([0, 1]),
            np.array([1, 0]),
            np.array([3.0, 5.0], dtype=np.float32),
            np.array([1]),
        )
        np.testing.assert_array_equal(result, [[2.0, 5.0, 3.0]])

    def test_negative_counts_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            signature_idf(np.array([1, -1]))


if __name__ == "__main__":
    unittest.main()
