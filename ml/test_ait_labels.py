import unittest

from ait_labels import adapt_label


class AitLabelsTest(unittest.TestCase):
    def test_event_label_creates_high_confidence_attack_instance(self) -> None:
        label = adapt_label("fox", "service_scans", "service_scan")

        self.assertEqual(label.selected_phase, "service_scans")
        self.assertEqual(label.attack_instance_id, "fox:A")
        self.assertEqual(label.label_confidence, "high")
        self.assertFalse(label.label_conflict)

    def test_event_label_overrides_conflicting_time_window(self) -> None:
        label = adapt_label("santos", "false_positive", "dnsteal")

        self.assertEqual(label.attack_instance_id, "santos:B")
        self.assertEqual(label.selected_phase, "dnsteal")
        self.assertTrue(label.label_conflict)

    def test_time_only_attack_is_weak(self) -> None:
        label = adapt_label("shaw", "reverse_shell", "-")

        self.assertEqual(label.attack_instance_id, "shaw:A")
        self.assertEqual(label.label_source, "time")
        self.assertEqual(label.label_confidence, "weak")

    def test_time_false_positive_is_not_high_confidence_benign(self) -> None:
        label = adapt_label("wardbeck", "false_positive", "-")

        self.assertFalse(label.is_attack)
        self.assertEqual(label.label_confidence, "weak")
        self.assertIsNone(label.attack_instance_id)

    def test_unknown_event_label_is_not_guessed(self) -> None:
        label = adapt_label("wilson", "dirb", "new_unmapped_label")

        self.assertIsNone(label.is_attack)
        self.assertEqual(label.label_confidence, "unknown")
        self.assertIsNone(label.attack_instance_id)


if __name__ == "__main__":
    unittest.main()

