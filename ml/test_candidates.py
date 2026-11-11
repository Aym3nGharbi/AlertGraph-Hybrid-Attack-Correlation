import unittest

from candidates import (
    ObservableAlert,
    collapse_repeated_alerts,
    generate_local_candidates,
    iter_local_candidates,
)


class CandidatesTest(unittest.TestCase):
    def test_collapse_is_reversible_through_member_ids(self) -> None:
        alerts = [
            ObservableAlert("a1", 0, "suricata", "scan", ("host:web",)),
            ObservableAlert("a2", 1, "suricata", "scan", ("host:web",)),
            ObservableAlert("a3", 4, "suricata", "scan", ("host:web",)),
        ]

        meta = collapse_repeated_alerts(alerts, max_gap_seconds=2)

        self.assertEqual(len(meta), 2)
        self.assertEqual(meta[0].member_alert_ids, ("a1", "a2"))
        self.assertEqual(meta[0].count, 2)
        self.assertEqual(meta[1].member_alert_ids, ("a3",))

    def test_different_sensors_are_not_collapsed(self) -> None:
        alerts = [
            ObservableAlert("a1", 0, "suricata", "scan", ("host:web",)),
            ObservableAlert("a2", 1, "wazuh", "scan", ("host:web",)),
        ]

        self.assertEqual(len(collapse_repeated_alerts(alerts)), 2)

    def test_candidates_require_shared_entity_and_time_window(self) -> None:
        alerts = [
            ObservableAlert("a1", 0, "suricata", "scan", ("host:web",)),
            ObservableAlert("a2", 10, "wazuh", "shell", ("host:web",)),
            ObservableAlert("a3", 20, "wazuh", "login", ("host:mail",)),
            ObservableAlert("a4", 100, "wazuh", "sudo", ("host:web",)),
        ]
        meta = collapse_repeated_alerts(alerts)

        pairs = generate_local_candidates(meta, window_seconds=60)

        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0].shared_entities, ("host:web",))

    def test_candidate_cap_keeps_most_recent(self) -> None:
        alerts = [
            ObservableAlert(f"a{i}", i, "wazuh", f"sig-{i}", ("host:web",))
            for i in range(4)
        ]
        meta = collapse_repeated_alerts(alerts)

        pairs = generate_local_candidates(meta, window_seconds=60, max_candidates_per_alert=1)

        self.assertEqual(len(pairs), 3)
        self.assertEqual(pairs[-1].earlier_meta_id, "meta-3")
        self.assertEqual(pairs[-1].later_meta_id, "meta-4")

    def test_streaming_and_materialized_generators_match(self) -> None:
        alerts = [
            ObservableAlert(f"a{i}", i, "wazuh", f"sig-{i}", ("host:web",))
            for i in range(4)
        ]
        meta = collapse_repeated_alerts(alerts)

        self.assertEqual(
            list(iter_local_candidates(meta, 60, 2)),
            generate_local_candidates(meta, 60, 2),
        )


if __name__ == "__main__":
    unittest.main()

