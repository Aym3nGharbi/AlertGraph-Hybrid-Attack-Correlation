import json
import tempfile
import unittest
from pathlib import Path

from wazuh_dataset import load_stage_mapping, mapping_audit, normalize_wazuh_alert


ROOT = Path(__file__).resolve().parents[1]


class WazuhDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mapping = load_stage_mapping(ROOT / "config" / "wazuh-stage-mapping.json")

    def test_known_mitre_technique_maps_to_observable_stage(self):
        raw = {
            "timestamp": "2026-10-31T23:11:05.834+0000",
            "id": "1",
            "rule": {"id": "100", "level": 7, "description": "scan", "mitre": {"id": ["T1046"], "tactic": ["Discovery"]}},
            "agent": {"id": "002", "name": "ubuntu-agent", "ip": "192.0.2.20"},
            "data": {"srcip": "192.168.122.10", "dstip": "192.168.122.130"},
        }
        record = normalize_wazuh_alert(raw, self.mapping, run_id="dev-1")
        self.assertEqual(record.observed_stage, "SERVICE_DISC")
        self.assertIn("host:ubuntu-agent", record.entities)
        self.assertEqual(record.ground_truth.is_attack, None)

    def test_unknown_is_neutral_not_non_malicious(self):
        raw = {
            "timestamp": "2026-10-31T23:11:05+00:00",
            "rule": {"id": "92910", "level": 12, "description": "unknown mapping"},
            "agent": {"id": "001", "name": "windows"},
        }
        record = normalize_wazuh_alert(raw, self.mapping)
        self.assertIsNone(record.observed_stage)
        audit = mapping_audit([record])
        self.assertEqual(audit["coverage"], 0.0)
        self.assertEqual(audit["unknown_policy"], "neutral")

    def test_subtechnique_inherits_explicit_parent_mapping(self):
        raw = {
            "timestamp": "2026-10-31T23:11:05+00:00",
            "rule": {
                "id": "5402", "level": 3, "description": "sudo",
                "mitre": {"id": ["T1548.003"]},
            },
            "agent": {"id": "002", "name": "linux"},
        }
        record = normalize_wazuh_alert(raw, self.mapping)
        self.assertEqual(record.observed_stage, "PRIV_ESC")

    def test_fim_path_is_an_observable_entity(self):
        raw = {
            "timestamp": "2026-10-31T23:11:05+00:00",
            "rule": {"id": "554", "level": 5, "description": "file added"},
            "agent": {"id": "002", "name": "linux"},
            "syscheck": {"path": "/opt/wazuh-lab/monitored/run-a.sh"},
        }
        record = normalize_wazuh_alert(raw, self.mapping)
        self.assertIn(
            "artifact:/opt/wazuh-lab/monitored/run-a.sh", record.entities
        )


if __name__ == "__main__":
    unittest.main()
