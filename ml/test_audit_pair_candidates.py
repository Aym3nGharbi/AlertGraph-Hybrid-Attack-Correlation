import unittest

from ait_dataset import CanonicalAlertRecord
from ait_labels import adapt_label
from audit_pair_candidates import (
    add_observable_context,
    audit_meta_candidates,
    collapse_labeled_records,
)


def record(
    alert_id: str,
    timestamp: float,
    signature: str,
    truth,
    entities=("host:web",),
) -> CanonicalAlertRecord:
    return CanonicalAlertRecord(
        alert_id=alert_id,
        source_id=None,
        timestamp=timestamp,
        sensor="wazuh",
        host="web",
        sensor_ip=None,
        src_ip=None,
        src_port=None,
        dst_ip=None,
        dst_port=None,
        protocol=None,
        service=None,
        signature_id=signature,
        signature_text=signature,
        severity=3,
        observed_tactics=(),
        observed_stage=None,
        entities=entities,
        ground_truth=truth,
    )


class AuditPairCandidatesTest(unittest.TestCase):
    def test_compression_keeps_members_and_detects_mixed_truth(self) -> None:
        attack = adapt_label("demo", "dirb", "dirb")
        benign = adapt_label("demo", "false_positive", "-")
        meta = collapse_labeled_records(
            [
                record("a1", 0, "repeat", attack),
                record("a2", 1, "repeat", benign),
            ]
        )

        self.assertEqual(len(meta), 1)
        self.assertEqual(meta[0].member_alert_ids, ("a1", "a2"))
        self.assertTrue(meta[0].truth_is_mixed)

    def test_counts_positive_and_negative_candidates(self) -> None:
        attack_a = adapt_label("demo", "dirb", "dirb")
        attack_b = adapt_label("demo", "dnsteal", "dnsteal")
        benign = adapt_label("demo", "false_positive", "-")
        meta = collapse_labeled_records(
            [
                record("a1", 0, "s1", attack_a),
                record("a2", 5, "s2", attack_a),
                record("a3", 6, "s3", attack_b),
                record("a4", 7, "s4", benign),
            ]
        )

        report = audit_meta_candidates(meta, window_seconds=10, max_candidates_per_alert=10)

        self.assertEqual(report["candidate_pairs"], 6)
        self.assertEqual(report["labeled_positive_pairs"], 1)
        self.assertEqual(report["labeled_negative_pairs"], 5)
        self.assertEqual(report["prior_positive_coverage_pct"], 100.0)

    def test_context_uses_only_prior_observable_activity(self) -> None:
        attack = adapt_label("demo", "dirb", "dirb")
        meta = collapse_labeled_records(
            [
                record("a1", 0, "s1", attack),
                record("a2", 5, "s2", attack),
                record("a3", 20, "s1", attack),
            ],
            max_gap_seconds=0,
        )
        enriched = add_observable_context(meta)

        self.assertEqual(enriched[0].prior_entity_density_10s, 0)
        self.assertEqual(enriched[1].prior_entity_density_10s, 1)
        self.assertEqual(enriched[2].prior_entity_density_10s, 0)
        self.assertEqual(
            enriched[2].seconds_since_same_signature_entity, 20
        )

    def test_overlapping_meta_alerts_have_zero_not_negative_gap(self) -> None:
        attack = adapt_label("demo", "dirb", "dirb")
        meta = collapse_labeled_records(
            [
                record("a1", 0, "same", attack, ("host:web", "ip:1")),
                record("a2", 1, "same", attack, ("host:web", "ip:2")),
                record("a3", 2, "same", attack, ("host:web", "ip:1")),
            ]
        )
        enriched = add_observable_context(meta)

        self.assertEqual(len(enriched), 2)
        self.assertEqual(enriched[1].seconds_since_same_signature_entity, 0)


if __name__ == "__main__":
    unittest.main()
