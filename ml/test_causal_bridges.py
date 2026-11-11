import unittest

from ait_observable_stages import observable_stage
from candidates import MetaAlert
from causal_bridges import (
    generate_causal_bridges,
    merge_candidate_sources,
    progression_compatible,
)


def meta(meta_id: str, time: float, stage: str | None, entity: str = "host:web") -> MetaAlert:
    return MetaAlert(
        meta_id=meta_id,
        first_timestamp=time,
        last_timestamp=time,
        sensor="test",
        signature=meta_id,
        entities=(entity,),
        member_alert_ids=(f"alert-{meta_id}",),
        observed_stage=stage,
    )


class CausalBridgesTest(unittest.TestCase):
    def test_maps_exact_observable_signature_without_ground_truth(self) -> None:
        self.assertEqual(
            observable_stage("Wazuh: Successful sudo to ROOT executed."), "PRIV_ESC"
        )
        self.assertIsNone(observable_stage("unknown signature"))

    def test_attack_stages_are_not_treated_as_global_linear_order(self) -> None:
        self.assertTrue(progression_compatible("SERVICE_DISC", "PUBLIC_APP_EXP"))
        self.assertTrue(progression_compatible("PUBLIC_APP_EXP", "PRIV_ESC"))
        self.assertFalse(progression_compatible("DATA_EXFILTRATION", "HOST_DISC"))
        self.assertFalse(progression_compatible("HOST_DISC", "DATA_EXFILTRATION"))

    def test_bridge_can_connect_slow_compatible_steps(self) -> None:
        alerts = [
            meta("m1", 0, "SERVICE_DISC"),
            meta("m2", 3600, "PUBLIC_APP_EXP"),
            meta("m3", 7200, "PRIV_ESC"),
        ]

        bridges = generate_causal_bridges(alerts)

        self.assertEqual(
            [(bridge.earlier_meta_id, bridge.later_meta_id) for bridge in bridges],
            [("m1", "m2"), ("m2", "m3")],
        )

    def test_bridge_requires_shared_entity(self) -> None:
        alerts = [
            meta("m1", 0, "SERVICE_DISC", "host:web"),
            meta("m2", 10, "PUBLIC_APP_EXP", "host:mail"),
        ]

        self.assertEqual(generate_causal_bridges(alerts), [])

    def test_non_malicious_stage_does_not_create_bridge(self) -> None:
        alerts = [meta("m1", 0, "NON_MALICIOUS"), meta("m2", 10, "PRIV_ESC")]

        self.assertEqual(generate_causal_bridges(alerts), [])

    def test_merges_local_and_causal_evidence_for_same_pair(self) -> None:
        alerts = [meta("m1", 0, "SERVICE_DISC"), meta("m2", 10, "PUBLIC_APP_EXP")]
        causal = generate_causal_bridges(alerts)
        local = [causal[0].__class__("m1", "m2", 10, ("host:web",), "local-window")]

        merged = merge_candidate_sources(local, causal)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].source, "causal-bridge+local-window")


if __name__ == "__main__":
    unittest.main()

