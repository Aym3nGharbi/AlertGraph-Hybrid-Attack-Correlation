import unittest

from ait_labels import adapt_label
from audit_pair_candidates import AuditedMetaAlert
from candidates import PairCandidate
from pair_features import make_pair_example


def meta(meta_id, time, stage, instance="A", confidence="high"):
    truth = adapt_label("demo", "dirb", "dirb")
    return AuditedMetaAlert(
        meta_id=meta_id,
        first_timestamp=time,
        last_timestamp=time,
        sensor="suricata",
        signature=f"sig-{meta_id}",
        signature_text="CMS login attempt",
        entities=("host:web", "ip:10.0.0.1"),
        member_alert_ids=(f"alert-{meta_id}",),
        observed_stage=stage,
        protocols=("tcp",),
        services=("http",),
        observed_tactics=("Initial Access",),
        src_ips=("10.0.0.8",),
        dst_ips=("10.0.0.1",),
        min_severity=3,
        max_severity=3,
        is_attack=True,
        attack_instance_id=f"demo:{instance}",
        ground_truth_phases=("dirb",),
        truth_confidence=confidence,
    )


class PairFeaturesTest(unittest.TestCase):
    def test_keeps_observable_features_separate_from_target(self) -> None:
        earlier = meta("m1", 0, "SERVICE_DISC")
        later = meta("m2", 10, "PUBLIC_APP_EXP")
        candidate = PairCandidate(
            "m1", "m2", 10, ("host:web", "ip:10.0.0.1"),
            "causal-bridge+local-window"
        )

        example = make_pair_example(earlier, later, candidate)

        self.assertEqual(example.supervision.target, 1)
        self.assertNotIn("target", example.features.to_dict())
        self.assertEqual(example.features.shared_entity_count, 2)
        self.assertEqual(example.features.forward_progression_compatible, 1)
        self.assertEqual(example.features.causal_bridge_evidence, 1)
        self.assertEqual(example.features.local_window_evidence, 1)

    def test_different_attack_instances_are_hard_negatives(self) -> None:
        earlier = meta("m1", 0, "SERVICE_DISC", instance="A")
        later = meta("m2", 10, "DATA_EXFILTRATION", instance="B")
        candidate = PairCandidate("m1", "m2", 10, ("host:web",))

        example = make_pair_example(earlier, later, candidate)

        self.assertEqual(example.supervision.target, 0)
        self.assertEqual(
            example.supervision.reason, "different-attack-instances"
        )


if __name__ == "__main__":
    unittest.main()
