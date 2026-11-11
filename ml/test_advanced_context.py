import unittest

import pandas as pd

from advanced_context import activity_accelerations, meta_advanced_context


class AdvancedContextTest(unittest.TestCase):
    def test_acceleration_is_positive_for_recent_burst(self) -> None:
        values = activity_accelerations(4, 4, 4, 4)
        self.assertGreater(values[0], 0)
        self.assertGreater(values[1], 0)
        self.assertGreater(values[2], 0)

    def test_history_uses_only_previous_compatible_stage(self) -> None:
        frame = pd.DataFrame(
            [
                {
                    "meta_id": "a",
                    "first_timestamp": 1.0,
                    "observed_stage": "HOST_DISC",
                    "entities": ["host:x"],
                    "member_alert_ids": ["1", "2"],
                    "prior_entity_density_2s": 0,
                    "prior_entity_density_10s": 0,
                    "prior_entity_density_60s": 0,
                    "prior_entity_density_150s": 0,
                },
                {
                    "meta_id": "b",
                    "first_timestamp": 2.0,
                    "observed_stage": "PUBLIC_APP_EXP",
                    "entities": ["host:x"],
                    "member_alert_ids": ["3"],
                    "prior_entity_density_2s": 1,
                    "prior_entity_density_10s": 1,
                    "prior_entity_density_60s": 1,
                    "prior_entity_density_150s": 1,
                },
            ]
        )
        context = meta_advanced_context(frame)
        self.assertEqual(context["a"]["log1p_compatible_history_count"], 0.0)
        self.assertGreater(context["b"]["log1p_compatible_history_count"], 0.0)
        self.assertEqual(context["b"]["compatible_history_distinct_stages"], 1)


if __name__ == "__main__":
    unittest.main()
