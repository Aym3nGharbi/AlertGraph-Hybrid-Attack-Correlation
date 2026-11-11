import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from ait_dataset import (
    DatasetAlignmentError,
    iter_ait_scenario,
    iter_ait_scenario_chronological,
)


class AitDatasetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.raw_path = root / "raw.zip"
        self.compact_path = root / "compact.zip"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_archives(
        self,
        compact_name: str = "Wazuh: Login failed",
        wazuh_time: int = 10,
        aminer_time: int = 11,
    ) -> None:
        wazuh = {
            "id": "source-1",
            "agent": {"ip": "10.0.0.2"},
            "rule": {
                "description": "Login failed",
                "id": "5710",
                "level": 5,
                "mitre": {"tactic": ["Credential Access", "Discovery"]},
            },
            "data": {"srcip": "10.0.0.8", "dstip": "10.0.0.2"},
        }
        aminer = {
            "AMiner": {"ID": "10.0.0.3"},
            "AnalysisComponent": {
                "AnalysisComponentIdentifier": 7,
                "AnalysisComponentName": "AMiner: New event type.",
            },
        }
        with zipfile.ZipFile(self.raw_path, "w") as archive:
            archive.writestr("demo_wazuh.json", json.dumps(wazuh) + "\n")
            archive.writestr("demo_aminer.json", json.dumps(aminer) + "\n")
        header = "time,name,ip,host,short,time_label,event_label\n"
        rows = (
            f"{wazuh_time},{compact_name},10.0.0.2,web,W-Login,network_scans,dns_scan\n"
            f"{aminer_time},AMiner: New event type.,10.0.0.3,dns,A-New,false_positive,-\n"
        )
        with zipfile.ZipFile(self.compact_path, "w") as archive:
            archive.writestr("alerts_csv/demo_alerts.txt", header + rows)

    def test_streams_observations_and_keeps_truth_separate(self) -> None:
        self._write_archives()
        records = list(iter_ait_scenario(self.raw_path, self.compact_path, "demo"))

        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first.sensor, "wazuh")
        self.assertEqual(first.signature_id, "W-Login")
        self.assertEqual(first.observed_tactics, ("Credential Access", "Discovery"))
        self.assertEqual(first.entities, ("host:web", "ip:10.0.0.2", "ip:10.0.0.8"))
        self.assertEqual(first.ground_truth.selected_phase, "network_scans")

        observable = first.to_observable_alert()
        self.assertFalse(hasattr(observable, "ground_truth"))
        self.assertEqual(observable.signature, "W-Login")

        second = records[1]
        self.assertEqual(second.sensor, "aminer")
        self.assertEqual(second.observed_stage, "SERVICE_SPECIFIC")
        self.assertFalse(second.ground_truth.is_attack)

    def test_rejects_misaligned_compact_stream(self) -> None:
        self._write_archives(compact_name="Wazuh: Wrong alert")
        with self.assertRaises(DatasetAlignmentError):
            list(iter_ait_scenario(self.raw_path, self.compact_path, "demo"))

    def test_merges_overlapping_sources_chronologically(self) -> None:
        self._write_archives(wazuh_time=12, aminer_time=11)
        records = list(
            iter_ait_scenario_chronological(
                self.raw_path, self.compact_path, "demo"
            )
        )

        self.assertEqual([record.timestamp for record in records], [11.0, 12.0])
        self.assertEqual([record.sensor for record in records], ["aminer", "wazuh"])


if __name__ == "__main__":
    unittest.main()
