from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from lab.dataset_v2.marker_normalization import (
    assert_feature_record_has_no_supervision,
    normalize_instrumentation_markers,
)
from lab.dataset_v2.synthetic_fixture import (
    reused_identity_bundle,
    synthetic_bundle,
)
from lab.dataset_v2.validators import (
    DatasetValidationError,
    SCHEMA_DIR,
    derive_pair_supervision,
    validate_bundle,
    validate_dataset_bundles,
)


class V2SchemaTests(unittest.TestCase):
    def test_every_versioned_schema_is_valid_draft_2020_12(self):
        schemas = sorted(SCHEMA_DIR.glob("*.schema.json"))
        self.assertEqual(len(schemas), 13)
        for path in schemas:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
            )
            Draft202012Validator.check_schema(schema)

    def test_complete_synthetic_bundle_is_accepted(self):
        bundle = synthetic_bundle()
        raw_before = json.dumps(bundle["raw_events"], sort_keys=True)
        self.assertEqual(validate_bundle(bundle), [])
        self.assertEqual(len(bundle["raw_events"]), 8)
        self.assertEqual(json.dumps(bundle["raw_events"], sort_keys=True), raw_before)


class V2ConfidenceRuleTests(unittest.TestCase):
    def setUp(self):
        self.bundle = synthetic_bundle()
        self.annotations = {
            value["wazuh_alert_id"]: value
            for value in self.bundle["annotations"]
        }

    def test_requested_pair_cases(self):
        same = derive_pair_supervision(self.annotations["w1"], self.annotations["w2"])
        distinct = derive_pair_supervision(self.annotations["w1"], self.annotations["w3"])
        attack_benign = derive_pair_supervision(self.annotations["w1"], self.annotations["w4"])
        benign_benign = derive_pair_supervision(self.annotations["w4"], self.annotations["w5"])
        weak = derive_pair_supervision(self.annotations["w1"], self.annotations["w6"])
        conflict = derive_pair_supervision(self.annotations["w1"], self.annotations["w7"])
        unknown = derive_pair_supervision(self.annotations["w1"], self.annotations["w8"])

        self.assertEqual((same["target"], same["confidence"]), (1, "verified"))
        self.assertEqual((distinct["target"], distinct["confidence"]), (0, "verified"))
        self.assertEqual(attack_benign["label_reason"], "attack-versus-benign")
        self.assertEqual(benign_benign["label_reason"], "independent-benign-activities")
        self.assertEqual((weak["target"], weak["confidence"]), (1, "weak"))
        self.assertIsNone(conflict["target"])
        self.assertIsNone(unknown["target"])

    def test_time_and_host_never_make_verified(self):
        invalid = copy.deepcopy(self.bundle)
        annotation = next(x for x in invalid["annotations"] if x["wazuh_alert_id"] == "w6")
        annotation.update(confidence="verified", review_status="accepted", reviewer_id="reviewer", reviewed_at_utc="2026-11-10T09:00:00+00:00")
        issues = validate_bundle(invalid, raise_on_error=False)
        codes = {issue.code for issue in issues}
        self.assertIn("verified-without-identity-proof", codes)
        self.assertIn("verified-without-technical-proof", codes)

    def test_verified_proof_must_reference_the_annotated_event(self):
        invalid = copy.deepcopy(self.bundle)
        annotation = next(x for x in invalid["annotations"] if x["wazuh_alert_id"] == "w1")
        annotation["wazuh_alert_id"] = "w1-not-in-evidence"
        codes = {issue.code for issue in validate_bundle(invalid, raise_on_error=False)}
        self.assertIn("verified-proof-not-bound-to-alert", codes)

    def test_conflict_requires_a_tracked_conflict_document(self):
        invalid = copy.deepcopy(self.bundle)
        invalid["conflicts"] = []
        codes = {issue.code for issue in validate_bundle(invalid, raise_on_error=False)}
        self.assertIn("untracked-conflict", codes)

    def test_conflict_claims_must_really_disagree(self):
        invalid = copy.deepcopy(self.bundle)
        invalid["conflicts"][0]["claims"][1] = copy.deepcopy(
            invalid["conflicts"][0]["claims"][0]
        )
        codes = {issue.code for issue in validate_bundle(invalid, raise_on_error=False)}
        self.assertIn("identical-conflict-claims", codes)

    def test_marker_cannot_be_shared_by_two_activities(self):
        invalid = copy.deepcopy(self.bundle)
        invalid["activities"][1]["marker_id"] = invalid["activities"][0]["marker_id"]
        codes = {issue.code for issue in validate_bundle(invalid, raise_on_error=False)}
        self.assertIn("duplicate-id", codes)

    def test_missing_evidence_is_rejected(self):
        invalid = copy.deepcopy(self.bundle)
        invalid["evidence"] = [x for x in invalid["evidence"] if x["evidence_id"] != "ev-alpha-tech"]
        codes = {issue.code for issue in validate_bundle(invalid, raise_on_error=False)}
        self.assertIn("unknown-evidence", codes)

    def test_non_utc_timestamp_is_rejected(self):
        invalid = copy.deepcopy(self.bundle)
        invalid["activities"][0]["started_at_utc"] = "2026-11-10T10:00:00+01:00"
        codes = {issue.code for issue in validate_bundle(invalid, raise_on_error=False)}
        self.assertIn("timestamp-not-utc", codes)


class V2PartitionTests(unittest.TestCase):
    def test_identity_reuse_between_partitions_is_rejected(self):
        issues = validate_dataset_bundles(
            [synthetic_bundle(), reused_identity_bundle()], raise_on_error=False
        )
        reuse = [issue for issue in issues if issue.code == "cross-campaign-id-reuse"]
        self.assertTrue(reuse)
        self.assertTrue(any("attack-alpha" in issue.message for issue in reuse))

    def test_manifest_partition_must_match_registry(self):
        invalid = synthetic_bundle()
        invalid["campaign_manifest"]["partition"] = "validation"
        codes = {issue.code for issue in validate_bundle(invalid, raise_on_error=False)}
        self.assertIn("partition-mismatch", codes)


class V2HashTests(unittest.TestCase):
    def test_existing_file_hash_and_size_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "alerts.jsonl"
            payload = b'{"id":"synthetic"}\n'
            raw.write_bytes(payload)
            bundle = synthetic_bundle()
            entry = {
                "role": "raw-alerts",
                "path": "alerts.jsonl",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
            bundle["collection_manifest"]["files"] = [entry]
            self.assertEqual(validate_bundle(bundle, base_dir=root), [])
            bundle["collection_manifest"]["files"][0]["sha256"] = "f" * 64
            codes = {
                issue.code
                for issue in validate_bundle(bundle, base_dir=root, raise_on_error=False)
            }
            self.assertIn("sha256-mismatch", codes)


class V2LeakageTests(unittest.TestCase):
    def test_marker_is_removed_only_from_derived_text(self):
        raw = "File C:/lab/agv2-alpha0001/payload.ps1 created"
        cleaned = normalize_instrumentation_markers(raw, ["agv2-alpha0001"])
        self.assertIn("agv2-alpha0001", raw)
        self.assertNotIn("agv2-alpha0001", cleaned)
        self.assertIn("instrumentation_marker", cleaned)

    def test_supervision_fields_and_values_are_rejected_from_ml_features(self):
        with self.assertRaises(ValueError):
            assert_feature_record_has_no_supervision(
                {"shared_entity_count": 1, "campaign_id": "dev-secret"}
            )
        with self.assertRaises(ValueError):
            assert_feature_record_has_no_supervision(
                {"signature_text": "execution for attack-alpha"},
                forbidden_values=["attack-alpha"],
            )
        assert_feature_record_has_no_supervision(
            {"signature_text_jaccard": 0.5, "shared_entity_count": 2},
            forbidden_values=["attack-alpha"],
        )


if __name__ == "__main__":
    unittest.main()
