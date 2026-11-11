from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import pyarrow.parquet as pq

from lab.collect_wazuh import instant
from lab.dataset_v2.collect_campaign import collect_local_export, verify_collection
from lab.dataset_v2.io_utils import sha256_file
from lab.dataset_v2.marker_normalization import (
    assert_feature_record_has_no_supervision,
    normalize_instrumentation_markers,
)
from lab.dataset_v2.orchestrator_adapters import (
    emit_orchestrator_records,
    verify_orchestrator_records,
)
from lab.dataset_v2.prepare_campaign import (
    FINAL_SENTINEL,
    prepare_campaign,
    verify_campaign_reservation,
)


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = Path(__file__).with_name("examples")


def example_plan() -> dict[str, object]:
    return json.loads((EXAMPLES / "scenario-plan.json").read_text(encoding="utf-8"))


class CampaignPreparationTests(unittest.TestCase):
    def test_prepares_schema_conformant_campaign_and_reproducible_markers(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left = prepare_campaign(
                first,
                campaign_id="dev-example-01",
                run_id="dev-example-01-r01",
                partition="development",
                scenario_plan=example_plan(),
                parameter_seed=42,
            )
            right = prepare_campaign(
                second,
                campaign_id="dev-example-01",
                run_id="dev-example-01-r01",
                partition="development",
                scenario_plan=example_plan(),
                parameter_seed=42,
            )
            self.assertEqual(left["markers"], right["markers"])
            self.assertEqual(len(set(left["markers"])), 2)
            manifest = verify_campaign_reservation(left["campaign_directory"])
            self.assertEqual(manifest["partition"], "development")
            self.assertEqual(manifest["status"], "planned")

    def test_invalid_partition_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                prepare_campaign(
                    temporary,
                    campaign_id="invalid-partition-01",
                    run_id="invalid-partition-01-r01",
                    partition="training",
                    scenario_plan=example_plan(),
                    parameter_seed=1,
                )

    def test_campaign_and_run_reuse_are_rejected_without_changing_old_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preserved = root / "existing-academic-result.txt"
            preserved.write_bytes(b"must remain unchanged")
            first = prepare_campaign(
                root,
                campaign_id="dev-first-01",
                run_id="reserved-run-01",
                partition="development",
                scenario_plan=example_plan(),
                parameter_seed=1,
            )
            registry_hash = sha256_file(root / "campaign-registry.json")
            with self.assertRaises((ValueError, FileExistsError)):
                prepare_campaign(
                    root,
                    campaign_id="dev-first-01",
                    run_id="other-run-01",
                    partition="development",
                    scenario_plan=example_plan(),
                    parameter_seed=2,
                )
            with self.assertRaises(ValueError):
                prepare_campaign(
                    root,
                    campaign_id="dev-second-01",
                    run_id="reserved-run-01",
                    partition="validation",
                    scenario_plan=example_plan(),
                    parameter_seed=2,
                )
            self.assertEqual(registry_hash, sha256_file(root / "campaign-registry.json"))
            self.assertEqual(preserved.read_bytes(), b"must remain unchanged")
            verify_campaign_reservation(first["campaign_directory"])

    def test_manifest_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary,
                campaign_id="dev-tamper-01",
                run_id="dev-tamper-01-r01",
                partition="development",
                scenario_plan=example_plan(),
                parameter_seed=3,
            )
            manifest = Path(result["campaign_directory"]) / "campaign-manifest.json"
            manifest.write_bytes(manifest.read_bytes() + b" ")
            with self.assertRaises(ValueError):
                verify_campaign_reservation(result["campaign_directory"])

    def test_final_test_requires_explicit_reservation_and_remains_non_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(PermissionError):
                prepare_campaign(
                    temporary,
                    campaign_id="final-example-01",
                    run_id="final-example-01-r01",
                    partition="final-test",
                    scenario_plan=example_plan(),
                    parameter_seed=99,
                )
            result = prepare_campaign(
                temporary,
                campaign_id="final-example-01",
                run_id="final-example-01-r01",
                partition="final-test",
                scenario_plan=example_plan(),
                parameter_seed=99,
                reserve_final_test=True,
            )
            directory = Path(result["campaign_directory"])
            self.assertTrue((directory / FINAL_SENTINEL).is_file())
            with self.assertRaises(PermissionError):
                emit_orchestrator_records(directory, dry_run=True)


class OrchestratorAdapterTests(unittest.TestCase):
    def test_dry_run_emits_linux_and_windows_activities_and_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary,
                campaign_id="dev-orchestrator-01",
                run_id="dev-orchestrator-01-r01",
                partition="development",
                scenario_plan=example_plan(),
                parameter_seed=11,
            )
            report = emit_orchestrator_records(
                result["campaign_directory"], platform="all", dry_run=True
            )
            execution = Path(result["campaign_directory"]) / "execution"
            activities = [
                json.loads(line)
                for line in (execution / "activities.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            evidence = [
                json.loads(line)
                for line in (execution / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(report["activity_count"], 2)
            self.assertEqual(report["evidence_count"], 4)
            self.assertEqual({x["platform"] for x in activities}, {"linux", "windows"})
            self.assertEqual({x["status"] for x in activities}, {"dry-run"})
            self.assertTrue(all(x["result"]["technical_evidence_pending_collection"] for x in activities))
            self.assertEqual(
                {x["kind"] for x in evidence}, {"command-hash", "execution-receipt"}
            )
            verify_orchestrator_records(result["campaign_directory"])
            with self.assertRaises(FileExistsError):
                emit_orchestrator_records(
                    result["campaign_directory"], platform="all", dry_run=True
                )


class VersionedCollectionTests(unittest.TestCase):
    def _campaign(self, root: Path, suffix: str) -> Path:
        result = prepare_campaign(
            root,
            campaign_id=f"dev-collection-{suffix}",
            run_id=f"dev-collection-{suffix}-r01",
            partition="development",
            scenario_plan=example_plan(),
            parameter_seed=21,
        )
        return Path(result["campaign_directory"])

    def test_simulated_collection_preserves_exact_raw_lines_and_builds_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = self._campaign(root, "exact")
            source = EXAMPLES / "wazuh-export.jsonl"
            source_lines = source.read_bytes().splitlines(keepends=True)
            manifest = collect_local_export(
                campaign,
                source,
                since=instant("2026-11-10T09:00:00+00:00"),
                until=instant("2026-11-10T09:05:00+00:00"),
                agents={"synthetic-linux-agent", "synthetic-windows-agent"},
                dry_run=True,
            )
            copied = (campaign / "raw" / "alerts.jsonl").read_bytes()
            self.assertEqual(copied, b"".join(source_lines[:2]))
            self.assertIn(b"agv2-example-linux", copied)
            index = pq.read_table(campaign / "raw" / "alert-index.parquet").to_pandas()
            self.assertEqual(index["wazuh_alert_id"].tolist(), ["dry-w1", "dry-w2"])
            self.assertEqual(manifest["alerts_written"], 2)
            verify_collection(campaign)
            with self.assertRaises(FileExistsError):
                collect_local_export(
                    campaign,
                    source,
                    since=instant("2026-11-10T09:00:00+00:00"),
                    until=instant("2026-11-10T09:05:00+00:00"),
                    agents=set(),
                    dry_run=True,
                )

    def test_modified_file_is_detected_after_hashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = self._campaign(root, "hash")
            collect_local_export(
                campaign,
                EXAMPLES / "wazuh-export.jsonl",
                since=instant("2026-11-10T09:00:00+00:00"),
                until=instant("2026-11-10T09:05:00+00:00"),
                agents=set(),
                dry_run=True,
            )
            alerts = campaign / "raw" / "alerts.jsonl"
            alerts.write_bytes(alerts.read_bytes() + b"tampered")
            with self.assertRaises(ValueError):
                verify_collection(campaign)

    def test_duplicate_wazuh_id_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = self._campaign(root, "duplicate")
            source = root / "duplicates.jsonl"
            event = {
                "timestamp": "2026-11-10T09:00:01+00:00",
                "id": "duplicate-id",
                "agent": {"name": "synthetic-linux-agent"},
                "rule": {"id": "1"},
            }
            line = (json.dumps(event, separators=(",", ":")) + "\n").encode()
            source.write_bytes(line + line)
            with self.assertRaises(ValueError):
                collect_local_export(
                    campaign,
                    source,
                    since=instant("2026-11-10T09:00:00+00:00"),
                    until=instant("2026-11-10T09:05:00+00:00"),
                    agents=set(),
                    dry_run=True,
                )
            self.assertFalse((campaign / "raw").exists())


class CampaignLeakageTests(unittest.TestCase):
    def test_raw_marker_is_preserved_but_derived_text_is_neutralized(self):
        raw_text = "alert for agv2-example-linux in campaign dev-secret"
        derived = normalize_instrumentation_markers(
            raw_text, ["agv2-example-linux", "dev-secret"]
        )
        self.assertIn("agv2-example-linux", raw_text)
        self.assertNotIn("agv2-example-linux", derived)
        self.assertNotIn("dev-secret", derived)
        assert_feature_record_has_no_supervision(
            {"signature_text": derived, "shared_entity_count": 1},
            forbidden_values=["agv2-example-linux", "dev-secret"],
        )
        with self.assertRaises(ValueError):
            assert_feature_record_has_no_supervision(
                {"activity_id": "activity:dev-secret:test"}
            )


if __name__ == "__main__":
    unittest.main()
