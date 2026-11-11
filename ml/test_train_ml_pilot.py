import unittest

import numpy as np
import pandas as pd

from train_ml_pilot import best_f1_threshold, scenario_class_weights


class TrainMlPilotTest(unittest.TestCase):
    def test_weights_equalize_scenario_and_class_mass(self) -> None:
        frame = pd.DataFrame(
            {
                "scenario": ["a", "a", "a", "b", "b"],
                "target": [0, 0, 1, 0, 1],
            }
        )
        frame["weight"] = scenario_class_weights(frame)
        masses = frame.groupby(["scenario", "target"])["weight"].sum()
        self.assertTrue(np.allclose(masses.to_numpy(), masses.iloc[0]))

    def test_threshold_is_selected_on_given_validation_scores(self) -> None:
        threshold, f1 = best_f1_threshold(
            np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.8, 0.9])
        )
        self.assertGreaterEqual(threshold, 0.2)
        self.assertEqual(f1, 1.0)


if __name__ == "__main__":
    unittest.main()
