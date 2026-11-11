from __future__ import annotations

import unittest

from lab.dataset_v2.membership_supervision import (
    validate_event_activity_matrix,
    validate_membership_decisions,
    strong_pair_label,
)


def decision(alert: str, activity: str | None, status: str = "member-verified"):
    unresolved = status == "unresolved"
    return {
        "schema_version": "alertgraph-membership-decision/2.0",
        "decision_id": f"decision:{alert}", "wazuh_alert_id": alert,
        "decision": status, "activity_id": None if unresolved else activity,
        "other_activity_id": None, "evidence_ids": [] if unresolved else ["e1"],
        "proof_families": ["wazuh-transport"] if unresolved else ["execution-receipt", "windows-sysmon"],
        "relation_keys": {}, "reason_codes": ["test"], "explanation": "preuve de test",
        "ml_use": "excluded-unresolved" if unresolved else "verified-benign-negative-only",
        "created_at_utc": "2026-11-11T00:00:00+00:00",
    }


class MembershipDecisionTests(unittest.TestCase):
    def test_verified_member_requires_independent_receipt_and_target_telemetry(self):
        item = decision("a1", "activity:a")
        item["proof_families"] = ["windows-sysmon", "wazuh-transport"]
        with self.assertRaisesRegex(ValueError, "reçu indépendant"):
            validate_membership_decisions([item], raw_alert_ids={"a1"},
                                          activity_ids={"activity:a"}, evidence_ids={"e1"})

    def test_unresolved_is_explicitly_excluded(self):
        item = decision("a1", None, "unresolved")
        validate_membership_decisions([item], raw_alert_ids={"a1"},
                                      activity_ids={"activity:a"}, evidence_ids=set())

    def test_every_raw_event_requires_one_decision(self):
        with self.assertRaisesRegex(ValueError, "Chaque événement brut"):
            validate_membership_decisions([decision("a1", "activity:a")],
                                          raw_alert_ids={"a1", "a2"},
                                          activity_ids={"activity:a"}, evidence_ids={"e1"})


class StrongPairPolicyTests(unittest.TestCase):
    def setUp(self):
        self.activities = {
            "attack:a1": {"class": "attack", "attack_instance_id": "instance:a"},
            "attack:a2": {"class": "attack", "attack_instance_id": "instance:a"},
            "attack:b": {"class": "attack", "attack_instance_id": "instance:b"},
            "benign:x": {"class": "benign", "benign_activity_id": "benign:x"},
            "benign:y": {"class": "benign", "benign_activity_id": "benign:y"},
        }

    def test_same_attack_instance_is_positive(self):
        self.assertEqual(strong_pair_label(decision("1", "attack:a1"), decision("2", "attack:a2"), self.activities), 1)

    def test_distinct_attack_instances_are_negative(self):
        self.assertEqual(strong_pair_label(decision("1", "attack:a1"), decision("2", "attack:b"), self.activities), 0)

    def test_distinct_verified_benign_activities_are_negative(self):
        self.assertEqual(strong_pair_label(decision("1", "benign:x"), decision("2", "benign:y"), self.activities), 0)

    def test_same_benign_activity_is_not_automatically_positive(self):
        self.assertIsNone(strong_pair_label(decision("1", "benign:x"), decision("2", "benign:x"), self.activities))

    def test_unresolved_event_never_gets_a_pair_label(self):
        self.assertIsNone(strong_pair_label(decision("1", None, "unresolved"), decision("2", "attack:a1"), self.activities))


def matrix_decision(
    alert: str,
    studied: str,
    status: str,
    provenance: str | None,
    identity: str | None,
):
    member = status == "member-verified"
    nonmember = status == "nonmember-verified"
    return {
        "schema_version": "alertgraph-event-activity-decision/2.0",
        "decision_id": f"matrix:{alert}:{studied}",
        "wazuh_alert_id": alert,
        "studied_activity_id": studied,
        "decision": status,
        "provenance_activity_id": provenance,
        "exclusive_identity_key": identity,
        "evidence_ids": ["receipt", "target"] if (member or nonmember) else [],
        "proof_families": ["execution-receipt", "linux-journal"] if member else [],
        "reason_codes": ["test"],
        "explanation": "Décision synthétique de test.",
        "ml_use": (
            "verified-member" if member else
            "verified-nonmember" if nonmember else
            "excluded"
        ),
        "created_at_utc": "2026-11-11T00:00:00+00:00",
    }


class EventActivityMatrixTests(unittest.TestCase):
    def setUp(self):
        self.raw = {"event:1"}
        self.activities = {"activity:a", "activity:b"}
        self.evidence = {"receipt", "target"}
        self.identities = {"activity:a": "ssh:boot:pid-a", "activity:b": "ssh:boot:pid-b"}

    def test_verified_member_and_proven_nonmember_are_accepted(self):
        decisions = [
            matrix_decision("event:1", "activity:a", "member-verified", "activity:a", "ssh:boot:pid-a"),
            matrix_decision("event:1", "activity:b", "nonmember-verified", "activity:a", "ssh:boot:pid-a"),
        ]
        validate_event_activity_matrix(
            decisions, raw_alert_ids=self.raw, activity_ids=self.activities,
            evidence_ids=self.evidence, activity_identity_keys=self.identities,
        )

    def test_nonmember_without_alternative_member_is_rejected(self):
        decisions = [
            matrix_decision("event:1", "activity:a", "excluded", None, None),
            matrix_decision("event:1", "activity:b", "nonmember-verified", "activity:a", "ssh:boot:pid-a"),
        ]
        with self.assertRaisesRegex(ValueError, "sans appartenance alternative"):
            validate_event_activity_matrix(
                decisions, raw_alert_ids=self.raw, activity_ids=self.activities,
                evidence_ids=self.evidence, activity_identity_keys=self.identities,
            )

    def test_nonexclusive_activity_identities_reject_nonmember(self):
        identities = {"activity:a": "shared", "activity:b": "shared"}
        decisions = [
            matrix_decision("event:1", "activity:a", "member-verified", "activity:a", "shared"),
            matrix_decision("event:1", "activity:b", "nonmember-verified", "activity:a", "shared"),
        ]
        with self.assertRaisesRegex(ValueError, "activités non exclusives"):
            validate_event_activity_matrix(
                decisions, raw_alert_ids=self.raw, activity_ids=self.activities,
                evidence_ids=self.evidence, activity_identity_keys=identities,
            )

    def test_cartesian_matrix_must_be_complete(self):
        decisions = [
            matrix_decision("event:1", "activity:a", "member-verified", "activity:a", "ssh:boot:pid-a"),
        ]
        with self.assertRaisesRegex(ValueError, "doit être complète"):
            validate_event_activity_matrix(
                decisions, raw_alert_ids=self.raw, activity_ids=self.activities,
                evidence_ids=self.evidence, activity_identity_keys=self.identities,
            )


if __name__ == "__main__":
    unittest.main()
