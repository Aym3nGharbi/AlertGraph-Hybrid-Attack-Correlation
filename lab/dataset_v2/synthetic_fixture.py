"""Jeu synthétique minimal couvrant les décisions de supervision V2."""

from __future__ import annotations

from copy import deepcopy


UTC = "2026-11-10T09:00:00+00:00"
SHA = "0" * 64


def synthetic_bundle() -> dict[str, object]:
    campaign = "dev-synthetic-01"
    run = "dev-synthetic-01-r01"

    activities = [
        _activity(campaign, run, "act-alpha", "attack", "attack-alpha", None, "agv2-alpha0001", ["ev-alpha-id", "ev-alpha-tech"]),
        _activity(campaign, run, "act-beta", "attack", "attack-beta", None, "agv2-beta00001", ["ev-beta-id", "ev-beta-tech"]),
        _activity(campaign, run, "act-benign-1", "benign", None, "benign-1", "agv2-benign001", ["ev-benign1-id", "ev-benign1-tech"]),
        _activity(campaign, run, "act-benign-2", "benign", None, "benign-2", "agv2-benign002", ["ev-benign2-id", "ev-benign2-tech"]),
    ]
    evidence = [
        _evidence(campaign, run, "ev-alpha-id", "act-alpha", "unique-marker", ["w1", "w2"]),
        _evidence(campaign, run, "ev-alpha-tech", "act-alpha", "file-telemetry", ["w1", "w2"]),
        _evidence(campaign, run, "ev-beta-id", "act-beta", "process-guid", ["w3"]),
        _evidence(campaign, run, "ev-beta-tech", "act-beta", "process-lineage", ["w3"]),
        _evidence(campaign, run, "ev-benign1-id", "act-benign-1", "artifact-identity", ["w4"]),
        _evidence(campaign, run, "ev-benign1-tech", "act-benign-1", "file-telemetry", ["w4"]),
        _evidence(campaign, run, "ev-benign2-id", "act-benign-2", "command-hash", ["w5"]),
        _evidence(campaign, run, "ev-benign2-tech", "act-benign-2", "wazuh-rule-semantic", ["w5"]),
        _evidence(campaign, run, "ev-alpha-time", "act-alpha", "time-window", ["w6"]),
        _evidence(campaign, run, "ev-alpha-host", "act-alpha", "host-match", ["w6"]),
    ]
    annotations = [
        _annotation("ann-w1", "w1", "attack", "verified", "act-alpha", "attack-alpha", None, ["ev-alpha-id", "ev-alpha-tech"]),
        _annotation("ann-w2", "w2", "attack", "verified", "act-alpha", "attack-alpha", None, ["ev-alpha-id", "ev-alpha-tech"]),
        _annotation("ann-w3", "w3", "attack", "verified", "act-beta", "attack-beta", None, ["ev-beta-id", "ev-beta-tech"]),
        _annotation("ann-w4", "w4", "benign", "verified", "act-benign-1", None, "benign-1", ["ev-benign1-id", "ev-benign1-tech"]),
        _annotation("ann-w5", "w5", "benign", "verified", "act-benign-2", None, "benign-2", ["ev-benign2-id", "ev-benign2-tech"]),
        _annotation("ann-w6", "w6", "attack", "weak", "act-alpha", "attack-alpha", None, ["ev-alpha-time", "ev-alpha-host"], review="unreviewed"),
        _annotation("ann-w7", "w7", "unknown", "conflict", None, None, None, ["ev-alpha-id", "ev-benign1-id"], conflict_id="conflict-w7"),
        _annotation("ann-w8", "w8", "unknown", "unknown", None, None, None, [], review="unreviewed"),
    ]
    conflicts = [{
        "schema_version": "alertgraph-annotation-conflict/2.0",
        "conflict_id": "conflict-w7",
        "annotation_id": "ann-w7",
        "wazuh_alert_id": "w7",
        "created_at_utc": UTC,
        "status": "unresolved",
        "claims": [
            {"source": "marker-link", "class": "attack", "attack_instance_id": "attack-alpha", "benign_activity_id": None, "activity_id": "act-alpha", "evidence_ids": ["ev-alpha-id"]},
            {"source": "manual-observation", "class": "benign", "attack_instance_id": None, "benign_activity_id": "benign-1", "activity_id": "act-benign-1", "evidence_ids": ["ev-benign1-id"]}
        ],
        "resolution_revision_id": None,
        "resolved_at_utc": None,
        "reviewer_id": None
    }]
    return {
        "raw_events": [
            _raw_event("w1", "agv2-alpha0001", "550"),
            _raw_event("w2", "agv2-alpha0001", "554"),
            _raw_event("w3", "agv2-beta00001", "1"),
            _raw_event("w4", "agv2-benign001", "550"),
            _raw_event("w5", "agv2-benign002", "5402"),
            _raw_event("w6", "unmarked plausible event", "550"),
            _raw_event("w7", "contradictory evidence", "554"),
            _raw_event("w8", "unrelated unknown event", "100001"),
        ],
        "registry": {
            "schema_version": "alertgraph-campaign-registry/2.0",
            "dataset_version": "wazuh-supervised-v2-synthetic",
            "frozen_at_utc": UTC,
            "campaigns": [{"campaign_id": campaign, "partition": "development", "scenario_template": "synthetic-supervision", "parameter_seed": 7, "status": "frozen"}],
        },
        "campaign_manifest": {
            "schema_version": "alertgraph-campaign-manifest/2.0",
            "campaign_id": campaign,
            "run_id": run,
            "partition": "development",
            "parameter_seed": 7,
            "created_at_utc": UTC,
            "started_at_utc": UTC,
            "ended_at_utc": "2026-11-10T09:05:00+00:00",
            "status": "frozen",
            "machines": [{"role": "linux-target", "host": "synthetic-linux", "agent_name": "synthetic-agent", "clock_audited_at_utc": UTC, "clock_offset_ms": 0}],
            "configuration_hashes": {"scenario": SHA},
        },
        "activities": activities,
        "evidence": evidence,
        "annotations": annotations,
        "conflicts": conflicts,
        "revisions": [],
        "collection_manifest": {
            "schema_version": "alertgraph-collection-manifest/2.0",
            "campaign_id": campaign,
            "run_id": run,
            "created_at_utc": UTC,
            "since_utc": UTC,
            "until_utc": "2026-11-10T09:05:00+00:00",
            "source": "synthetic",
            "agent_filter": ["synthetic-agent"],
            "lines_read": 8,
            "alerts_written": 8,
            "malformed_lines": 0,
            "files": [],
        },
        "release_manifest": {
            "schema_version": "alertgraph-release-manifest/2.0",
            "dataset_version": "wazuh-supervised-v2-synthetic",
            "release_id": "synthetic-release-01",
            "campaign_id": campaign,
            "created_at_utc": UTC,
            "frozen_at_utc": UTC,
            "campaign_ids": [campaign],
            "partition_counts": {"development": 1, "validation": 0, "final-test": 0},
            "files": [],
            "training_ready": False,
            "limitations": ["synthetic validation fixture; no real Wazuh collection"],
        },
    }


def reused_identity_bundle() -> dict[str, object]:
    """Copie invalide : une identité de développement est réutilisée en validation."""

    bundle = deepcopy(synthetic_bundle())
    old_campaign = bundle["campaign_manifest"]["campaign_id"]
    old_run = bundle["campaign_manifest"]["run_id"]
    new_campaign, new_run = "validation-synthetic-01", "validation-synthetic-01-r01"
    bundle["registry"]["campaigns"][0].update(campaign_id=new_campaign, partition="validation")
    bundle["campaign_manifest"].update(campaign_id=new_campaign, run_id=new_run, partition="validation")
    bundle["collection_manifest"].update(campaign_id=new_campaign, run_id=new_run)
    bundle["release_manifest"].update(campaign_id=new_campaign, campaign_ids=[new_campaign], partition_counts={"development": 0, "validation": 1, "final-test": 0})
    for section in ("activities", "evidence"):
        for item in bundle[section]:
            if item.get("campaign_id") == old_campaign:
                item["campaign_id"] = new_campaign
            if item.get("run_id") == old_run:
                item["run_id"] = new_run
    return bundle


def _activity(campaign, run, activity_id, label_class, attack_id, benign_id, marker, evidence_ids):
    return {
        "schema_version": "alertgraph-activity/2.0", "campaign_id": campaign, "run_id": run,
        "activity_id": activity_id, "class": label_class, "attack_instance_id": attack_id,
        "benign_activity_id": benign_id, "activity_name": activity_id, "platform": "linux",
        "status": "dry-run", "result": {"synthetic": True},
        "true_activity_phase": "execution" if label_class == "attack" else None,
        "started_at_utc": UTC, "ended_at_utc": "2026-11-10T09:00:10+00:00",
        "controller_started_at_utc": UTC, "controller_ended_at_utc": "2026-11-10T09:00:10+00:00",
        "target_started_at_utc": UTC, "target_ended_at_utc": "2026-11-10T09:00:10+00:00",
        "target_agents": ["synthetic-agent"], "target_hosts": ["synthetic-linux"],
        "marker_id": marker, "command_spec_sha256": SHA, "exit_code": 0, "evidence_ids": evidence_ids,
    }


def _evidence(campaign, run, evidence_id, activity_id, kind, alert_ids):
    return {
        "schema_version": "alertgraph-evidence/2.0", "evidence_id": evidence_id,
        "campaign_id": campaign, "run_id": run, "activity_id": activity_id, "kind": kind,
        "recorded_at_utc": UTC, "source": "synthetic-fixture", "payload_sha256": SHA,
        "observed_in_alert_ids": alert_ids,
    }


def _annotation(annotation_id, alert_id, label_class, confidence, activity_id, attack_id, benign_id, evidence_ids, *, review="accepted", conflict_id=None):
    return {
        "schema_version": "alertgraph-event-annotation/2.0", "annotation_id": annotation_id,
        "wazuh_alert_id": alert_id, "class": label_class, "attack_instance_id": attack_id,
        "benign_activity_id": benign_id, "activity_id": activity_id,
        "true_activity_phase": "execution" if label_class == "attack" else None,
        "confidence": confidence, "annotation_source": "synthetic-fixture", "evidence_ids": evidence_ids,
        "review_status": review, "reviewer_id": "synthetic-reviewer" if review == "accepted" else None,
        "reviewed_at_utc": UTC if review == "accepted" else None,
        "label_conflict": confidence == "conflict", "conflict_id": conflict_id,
        "conflict_reasons": ["contradictory synthetic claims"] if confidence == "conflict" else [],
        "created_at_utc": UTC, "revision": 1,
    }


def _raw_event(alert_id, message, rule_id):
    return {
        "timestamp": UTC,
        "id": alert_id,
        "agent": {"id": "synthetic-001", "name": "synthetic-agent", "ip": "192.0.2.10"},
        "rule": {"id": rule_id, "level": 5, "description": "Synthetic Wazuh event"},
        "data": {"message": message},
    }
