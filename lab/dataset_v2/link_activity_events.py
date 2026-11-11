"""Lie une activité SSH contrôlée à ses alertes Wazuh sans modifier le brut."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from .collect_campaign import verify_collection
from .io_utils import (
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
    utc_now,
    write_new_bytes,
    write_new_json,
)
from .orchestrator_adapters import verify_orchestrator_records
from .prepare_campaign import verify_campaign_reservation
from .validators import validate_bundle


SSHD_PID = re.compile(r"\bsshd\[(\d+)\]")


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _jsonl(items: Iterable[Mapping[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        for item in items
    )


def extract_sshd_pid(event: Mapping[str, object]) -> str | None:
    match = SSHD_PID.search(str(event.get("full_log") or ""))
    return match.group(1) if match else None


def _event_rule(event: Mapping[str, object]) -> str:
    rule = event.get("rule")
    return str(rule.get("id", "")) if isinstance(rule, Mapping) else ""


def _event_agent(event: Mapping[str, object]) -> str:
    agent = event.get("agent")
    return str(agent.get("name", "")) if isinstance(agent, Mapping) else ""


def _event_data(event: Mapping[str, object]) -> Mapping[str, object]:
    value = event.get("data")
    return value if isinstance(value, Mapping) else {}


def _evidence(
    *,
    evidence_id: str,
    campaign_id: str,
    run_id: str,
    activity_id: str,
    kind: str,
    source: str,
    payload: object,
    alert_ids: list[str],
    recorded_at: str,
) -> dict[str, object]:
    return {
        "schema_version": "alertgraph-evidence/2.0",
        "evidence_id": evidence_id,
        "campaign_id": campaign_id,
        "run_id": run_id,
        "activity_id": activity_id,
        "kind": kind,
        "recorded_at_utc": recorded_at,
        "source": source,
        "payload_sha256": sha256_bytes(canonical_json_bytes(payload)),
        "observed_in_alert_ids": alert_ids,
    }


def _annotation(
    *,
    event: Mapping[str, object],
    confidence: str,
    activity: Mapping[str, object] | None,
    evidence_ids: list[str],
    now: str,
) -> dict[str, object]:
    alert_id = str(event["id"])
    assigned = activity is not None and confidence in {"verified", "weak"}
    accepted = confidence == "verified"
    return {
        "schema_version": "alertgraph-event-annotation/2.0",
        "annotation_id": f"annotation:{alert_id}",
        "wazuh_alert_id": alert_id,
        "class": "benign" if assigned else "unknown",
        "attack_instance_id": None,
        "benign_activity_id": activity.get("benign_activity_id") if assigned else None,
        "activity_id": activity.get("activity_id") if assigned else None,
        "true_activity_phase": activity.get("true_activity_phase") if assigned else None,
        "confidence": confidence,
        "annotation_source": "controlled-ssh-two-proof-linker-v2",
        "evidence_ids": evidence_ids,
        "review_status": "accepted" if accepted else "unreviewed",
        "reviewer_id": "automatic-preregistered-two-proof-policy-v2" if accepted else None,
        "reviewed_at_utc": now if accepted else None,
        "label_conflict": False,
        "conflict_id": None,
        "conflict_reasons": [],
        "created_at_utc": now,
        "revision": 1,
    }


def link_controlled_ssh(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    verify_orchestrator_records(campaign_dir)
    collection = verify_collection(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("Le lieur pilote exige development")
    if (campaign_dir / "association").exists():
        raise FileExistsError("Une association existe déjà")

    activities = _load_jsonl(campaign_dir / "execution" / "activities.jsonl")
    execution_evidence = _load_jsonl(campaign_dir / "execution" / "evidence.jsonl")
    if len(activities) != 1:
        raise ValueError("Une activité unique est requise pour ce pilote")
    activity = activities[0]
    if activity["class"] != "benign" or activity["status"] != "completed":
        raise ValueError("L'activité bénigne doit être terminée")
    receipt = load_json(campaign_dir / "receipts" / "v1-truth.json")
    step = receipt["steps"][0]
    result = step["result"]
    if step["exit_code"] != 0 or not result.get("connection_tuple_match"):
        raise ValueError("Le reçu ne prouve pas un tuple SSH concordant")
    controller_tuple = result["controller_socket"]
    target_tuple = result["target_ssh_connection"]

    raw_path = campaign_dir / "raw" / "alerts.jsonl"
    raw_lines = raw_path.read_bytes().splitlines(keepends=True)
    events = [json.loads(line) for line in raw_lines]
    expected_agent = str(activity["target_agents"][0])
    expected_user = "labuser"
    auth_candidates = []
    for event, raw_line in zip(events, raw_lines):
        data = _event_data(event)
        if (
            _event_agent(event) == expected_agent
            and _event_rule(event) == "5715"
            and str(data.get("srcip")) == str(controller_tuple["source_ip"])
            and str(data.get("srcport")) == str(controller_tuple["source_port"])
            and str(data.get("dstuser")) == expected_user
        ):
            auth_candidates.append((event, raw_line))
    if len(auth_candidates) != 1:
        raise ValueError(f"Nombre d'alertes SSH exactes inattendu: {len(auth_candidates)}")
    auth_event, auth_line = auth_candidates[0]
    auth_id = str(auth_event["id"])
    server_pid = extract_sshd_pid(auth_event)
    if not server_pid:
        raise ValueError("PID sshd absent de l'alerte d'authentification")

    now = utc_now()
    campaign_id = str(manifest["campaign_id"])
    run_id = str(manifest["run_id"])
    activity_id = str(activity["activity_id"])
    association_evidence = [
        _evidence(
            evidence_id=f"evidence:{activity_id}:exact-ssh-identity",
            campaign_id=campaign_id,
            run_id=run_id,
            activity_id=activity_id,
            kind="artifact-identity",
            source="controller-socket+target-ssh-connection:execution-receipt",
            payload={
                "controller_socket": controller_tuple,
                "target_ssh_connection": target_tuple,
                "connection_tuple_match": True,
            },
            alert_ids=[auth_id],
            recorded_at=now,
        ),
        _evidence(
            evidence_id=f"evidence:{activity_id}:ssh-authentication-telemetry",
            campaign_id=campaign_id,
            run_id=run_id,
            activity_id=activity_id,
            kind="authentication-telemetry",
            source="wazuh-raw:sshd-authentication-success",
            payload={"raw_line_sha256": hashlib.sha256(auth_line).hexdigest()},
            alert_ids=[auth_id],
            recorded_at=now,
        ),
    ]
    annotations = []
    for event, raw_line in zip(events, raw_lines):
        alert_id = str(event["id"])
        if alert_id == auth_id:
            annotations.append(
                _annotation(
                    event=event,
                    confidence="verified",
                    activity=activity,
                    evidence_ids=[x["evidence_id"] for x in association_evidence[:2]],
                    now=now,
                )
            )
            continue
        pid = extract_sshd_pid(event)
        data = _event_data(event)
        pam_user = str(data.get("srcuser") or data.get("dstuser") or "")
        if (
            _event_agent(event) == expected_agent
            and _event_rule(event) in {"5501", "5502"}
            and pid == server_pid
            and pam_user == expected_user
        ):
            evidence_id = f"evidence:{activity_id}:sshd-pid-{server_pid}:{alert_id}"
            association_evidence.append(
                _evidence(
                    evidence_id=evidence_id,
                    campaign_id=campaign_id,
                    run_id=run_id,
                    activity_id=activity_id,
                    kind="process-lineage",
                    source="wazuh-raw:sshd-pid-chain",
                    payload={
                        "anchor_alert_id": auth_id,
                        "linked_alert_id": alert_id,
                        "sshd_pid": server_pid,
                        "raw_line_sha256": hashlib.sha256(raw_line).hexdigest(),
                    },
                    alert_ids=[alert_id],
                    recorded_at=now,
                )
            )
            annotations.append(
                _annotation(
                    event=event,
                    confidence="weak",
                    activity=activity,
                    evidence_ids=[evidence_id],
                    now=now,
                )
            )
        else:
            annotations.append(
                _annotation(
                    event=event,
                    confidence="unknown",
                    activity=None,
                    evidence_ids=[],
                    now=now,
                )
            )

    association_dir = campaign_dir / "association"
    evidence_path = association_dir / "evidence.jsonl"
    annotations_path = association_dir / "annotations.jsonl"
    write_new_bytes(evidence_path, _jsonl(association_evidence))
    write_new_bytes(annotations_path, _jsonl(annotations))
    association_manifest = {
        "schema_version": "alertgraph-association-manifest/2.0-experimental",
        "campaign_id": campaign_id,
        "run_id": run_id,
        "created_at_utc": now,
        "method": "controlled-ssh-two-proof-linker-v2",
        "verified": sum(x["confidence"] == "verified" for x in annotations),
        "weak": sum(x["confidence"] == "weak" for x in annotations),
        "unknown": sum(x["confidence"] == "unknown" for x in annotations),
        "conflict": sum(x["confidence"] == "conflict" for x in annotations),
        "files": {
            "evidence.jsonl": sha256_file(evidence_path),
            "annotations.jsonl": sha256_file(annotations_path),
        },
    }
    association_manifest_path = association_dir / "association-manifest.json"
    write_new_json(association_manifest_path, association_manifest)

    release_files = []
    for role, relative in (
        ("raw-alerts", "raw/alerts.jsonl"),
        ("alert-index", "raw/alert-index.parquet"),
        ("activities", "execution/activities.jsonl"),
        ("execution-evidence", "execution/evidence.jsonl"),
        ("association-evidence", "association/evidence.jsonl"),
        ("annotations", "association/annotations.jsonl"),
        ("association-manifest", "association/association-manifest.json"),
    ):
        path = campaign_dir / relative
        release_files.append(
            {"role": role, "path": relative, "sha256": sha256_file(path), "bytes": path.stat().st_size}
        )
    release = {
        "schema_version": "alertgraph-release-manifest/2.0",
        "dataset_version": "wazuh-supervised-v2",
        "release_id": f"pilot-association:{run_id}",
        "campaign_id": campaign_id,
        "created_at_utc": now,
        "frozen_at_utc": now,
        "campaign_ids": [campaign_id],
        "partition_counts": {"development": 1, "validation": 0, "final-test": 0},
        "files": release_files,
        "training_ready": False,
        "limitations": [
            "single controlled benign SSH activity",
            "only the exact sshd tuple match is verified",
            "PAM links remain weak because they use a derived server-PID chain",
            "development evidence only; not an independent final evaluation",
        ],
    }
    root = campaign_dir.parents[2]
    bundle = {
        "registry": load_json(root / "campaign-registry.json"),
        "campaign_manifest": manifest,
        "activities": activities,
        "evidence": [*execution_evidence, *association_evidence],
        "annotations": annotations,
        "conflicts": [],
        "revisions": [],
        "collection_manifest": collection,
        "release_manifest": release,
        "raw_events": events,
    }
    validate_bundle(bundle, base_dir=campaign_dir)
    write_new_json(association_dir / "release-manifest.json", release)
    write_new_json(association_dir / "validation-bundle.json", bundle)
    return association_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(link_controlled_ssh(args.campaign_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
