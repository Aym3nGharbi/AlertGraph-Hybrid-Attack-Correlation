import unittest

from split_protocol import (
    AIT_SCENARIOS,
    nested_leave_one_scenario_out,
    validate_folds,
)


class SplitProtocolTest(unittest.TestCase):
    def test_every_scenario_is_held_out_once_without_overlap(self) -> None:
        folds = nested_leave_one_scenario_out()
        validate_folds(folds)

        self.assertEqual(len(folds), 8)
        self.assertEqual({fold.test_scenario for fold in folds}, set(AIT_SCENARIOS))
        for outer in folds:
            self.assertEqual(len(outer.development_scenarios), 7)
            self.assertEqual(len(outer.inner_folds), 7)
            for inner in outer.inner_folds:
                self.assertEqual(len(inner.train_scenarios), 6)

    def test_requires_at_least_three_groups(self) -> None:
        with self.assertRaises(ValueError):
            nested_leave_one_scenario_out(("one", "two"))


if __name__ == "__main__":
    unittest.main()
