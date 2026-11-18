from __future__ import annotations

import unittest

from lab.dataset_v2.experimental_candidate_generators import (
    corroborated_long_candidates, evidence_bundles, local_candidates, merge_candidates,
)


def meta(meta_id: str, timestamp: float, *, signature: str = "wazuh:5710", sensor: str = "wazuh:sshd"):
    return {
        "meta_id": meta_id, "first_timestamp": timestamp, "last_timestamp": timestamp,
        "sensor": sensor, "signature": signature, "signature_text": signature,
        "entities": ["host:h", "ip:1", "user:u"], "observed_stage": "LATERAL_MOVEMENT",
        "src_ips": ["1"], "dst_ips": [], "protocols": [], "services": [],
    }


class ExperimentalCandidateGeneratorTests(unittest.TestCase):
    def test_local_window_and_cap_are_deterministic(self):
        rows = [meta("m1", 0), meta("m2", 10), meta("m3", 20)]
        candidates = local_candidates(rows, 60, 1)
        self.assertEqual([(x.earlier_meta_id, x.later_meta_id) for x in candidates], [("m1", "m2"), ("m2", "m3")])

    def test_long_bridge_uses_only_observable_bundles(self):
        rows = [meta("m1", 0), meta("m2", 90)]
        candidates = corroborated_long_candidates(rows, min_bundles=2, per_alert_cap=3)
        self.assertEqual(len(candidates), 1)
        self.assertIn("semantic-continuity", candidates[0].evidence_bundles)
        self.assertNotIn("attack-instance", candidates[0].evidence_bundles)

    def test_sparse_cap_limits_long_bridges_per_later_alert(self):
        rows = [meta("m1", 0), meta("m2", 1), meta("m3", 100)]
        candidates = corroborated_long_candidates(rows, min_bundles=2, per_alert_cap=1)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].later_meta_id, "m3")

    def test_long_index_ignores_pairs_without_shared_entity(self):
        left = meta("m1", 0)
        right = {**meta("m2", 90), "entities": ["host:other", "ip:2", "user:v"], "src_ips": ["2"]}
        self.assertEqual(corroborated_long_candidates([left, right], min_bundles=1), [])

    def test_merge_preserves_provenance_without_duplicates(self):
        rows = [meta("m1", 0), meta("m2", 70)]
        left = local_candidates(rows, 120, 50)
        right = corroborated_long_candidates(rows, min_bundles=2)
        merged = merge_candidates(left, right)
        self.assertEqual(len(merged), 1)
        self.assertEqual(set(merged[0].sources), {"local-window-120s", "corroborated-long-bridge"})

    def test_evidence_groups_do_not_contain_supervision_fields(self):
        bundles = evidence_bundles(meta("m1", 0), meta("m2", 90))
        self.assertTrue(bundles)
        self.assertFalse(any("campaign" in value or "instance" in value for value in bundles))


if __name__ == "__main__":
    unittest.main()
