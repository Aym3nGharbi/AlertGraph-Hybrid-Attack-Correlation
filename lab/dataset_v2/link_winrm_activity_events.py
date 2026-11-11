"""Lie une activité WinRM contrôlée à la télémétrie Sysmon Wazuh."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .collect_campaign import verify_collection
from .io_utils import canonical_json_bytes, load_json, sha256_bytes, sha256_file, utc_now, write_new_bytes, write_new_json
from .orchestrator_adapters import verify_orchestrator_records
from .prepare_campaign import verify_campaign_reservation
from .validators import validate_bundle


def _jsonl(items: Iterable[Mapping[str, object]]) -> bytes:
    return b"".join((json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for x in items)


def _win_event(event: Mapping[str, object]) -> tuple[Mapping[str, object], Mapping[str, object]]:
    data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
    win = data.get("win") if isinstance(data.get("win"), Mapping) else {}
    system = win.get("system") if isinstance(win.get("system"), Mapping) else {}
    eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), Mapping) else {}
    return system, eventdata


def _evidence(*, evidence_id: str, manifest: Mapping[str, object], activity_id: str,
              kind: str, source: str, payload: object, alert_id: str, now: str) -> dict[str, object]:
    return {
        "schema_version": "alertgraph-evidence/2.0", "evidence_id": evidence_id,
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "activity_id": activity_id, "kind": kind, "recorded_at_utc": now,
        "source": source, "payload_sha256": sha256_bytes(canonical_json_bytes(payload)),
        "observed_in_alert_ids": [alert_id],
    }


def _annotation(event: Mapping[str, object], activity: Mapping[str, object] | None,
                confidence: str, evidence_ids: list[str], now: str) -> dict[str, object]:
    assigned = activity is not None and confidence in {"verified", "weak"}
    alert_id = str(event["id"])
    return {
        "schema_version": "alertgraph-event-annotation/2.0", "annotation_id": f"annotation:{alert_id}",
        "wazuh_alert_id": alert_id, "class": "benign" if assigned else "unknown",
        "attack_instance_id": None,
        "benign_activity_id": activity.get("benign_activity_id") if assigned else None,
        "activity_id": activity.get("activity_id") if assigned else None,
        "true_activity_phase": None, "confidence": confidence,
        "annotation_source": "controlled-winrm-sysmon-linker-v1", "evidence_ids": evidence_ids,
        "review_status": "accepted" if confidence == "verified" else "unreviewed",
        "reviewer_id": "automatic-preregistered-winrm-policy-v1" if confidence == "verified" else None,
        "reviewed_at_utc": now if confidence == "verified" else None,
        "label_conflict": False, "conflict_id": None, "conflict_reasons": [],
        "created_at_utc": now, "revision": 1,
    }


def link_controlled_winrm(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    verify_orchestrator_records(campaign_dir)
    collection = verify_collection(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("Le lieur pilote exige development")
    if (campaign_dir / "association").exists():
        raise FileExistsError("Une association existe déjà")
    activities = [json.loads(x) for x in (campaign_dir / "execution" / "activities.jsonl").read_text(encoding="utf-8").splitlines()]
    execution_evidence = [json.loads(x) for x in (campaign_dir / "execution" / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
    if len(activities) != 1 or activities[0]["class"] != "benign" or activities[0]["status"] != "completed":
        raise ValueError("Une activité Windows bénigne terminée est requise")
    activity = activities[0]
    receipt = load_json(campaign_dir / "receipts" / "v1-truth.json")
    step = receipt["steps"][0]
    result = step["result"]
    if step["exit_code"] != 0 or not result.get("marker_echoed"):
        raise ValueError("Le reçu WinRM n'est pas concluant")
    marker = str(activity["marker_id"])
    process_id = str(result["target_process_id"])
    raw_path = campaign_dir / "raw" / "alerts.jsonl"
    raw_lines = raw_path.read_bytes().splitlines(keepends=True)
    events = [json.loads(line) for line in raw_lines]
    exact: list[tuple[dict[str, object], bytes, Mapping[str, object]]] = []
    for event, raw_line in zip(events, raw_lines):
        system, eventdata = _win_event(event)
        agent = event.get("agent") if isinstance(event.get("agent"), Mapping) else {}
        if (agent.get("name") == "windows-agent" and str(system.get("eventID")) == "1"
                and str(eventdata.get("processId")) == process_id
                and marker in str(eventdata.get("commandLine") or "")
                and str(eventdata.get("image") or "").lower().endswith("\\cmd.exe")):
            exact.append((event, raw_line, eventdata))
    if len(exact) != 1:
        raise ValueError(f"Nombre d'événements Sysmon exacts inattendu: {len(exact)}")
    exact_event, exact_line, exact_data = exact[0]
    alert_id = str(exact_event["id"])
    process_guid = str(exact_data.get("processGuid") or "")
    if not process_guid:
        raise ValueError("ProcessGuid Sysmon absent")
    now = utc_now(); activity_id = str(activity["activity_id"])
    identity_id = f"evidence:{activity_id}:winrm-marker-process-identity"
    technical_id = f"evidence:{activity_id}:sysmon-process-guid"
    association_evidence = [
        _evidence(evidence_id=identity_id, manifest=manifest, activity_id=activity_id,
                  kind="unique-marker", source="sealed-marker+winrm-execution-receipt",
                  payload={"marker": marker, "process_id": process_id, "receipt_command_line": result["target_command_line"]},
                  alert_id=alert_id, now=now),
        _evidence(evidence_id=technical_id, manifest=manifest, activity_id=activity_id,
                  kind="process-lineage", source="wazuh-raw:sysmon-process-create",
                  payload={"process_guid": process_guid, "process_id": process_id,
                           "raw_line_sha256": hashlib.sha256(exact_line).hexdigest()},
                  alert_id=alert_id, now=now),
    ]
    annotations = []
    for event, raw_line in zip(events, raw_lines):
        event_id = str(event["id"])
        if event_id == alert_id:
            annotations.append(_annotation(event, activity, "verified", [identity_id, technical_id], now)); continue
        system, eventdata = _win_event(event)
        if str(system.get("eventID")) == "5" and str(eventdata.get("processGuid") or "") == process_guid:
            evidence_id = f"evidence:{activity_id}:sysmon-guid-chain:{event_id}"
            association_evidence.append(_evidence(
                evidence_id=evidence_id, manifest=manifest, activity_id=activity_id,
                kind="process-lineage", source="wazuh-raw:sysmon-process-guid-chain",
                payload={"anchor_alert_id": alert_id, "process_guid": process_guid,
                         "raw_line_sha256": hashlib.sha256(raw_line).hexdigest()},
                alert_id=event_id, now=now))
            annotations.append(_annotation(event, activity, "weak", [evidence_id], now))
        else:
            annotations.append(_annotation(event, None, "unknown", [], now))

    association_dir = campaign_dir / "association"
    evidence_path = association_dir / "evidence.jsonl"; annotations_path = association_dir / "annotations.jsonl"
    write_new_bytes(evidence_path, _jsonl(association_evidence)); write_new_bytes(annotations_path, _jsonl(annotations))
    association_manifest = {
        "schema_version": "alertgraph-association-manifest/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"], "created_at_utc": now,
        "method": "controlled-winrm-sysmon-linker-v1",
        **{name: sum(x["confidence"] == name for x in annotations) for name in ("verified", "weak", "unknown", "conflict")},
        "files": {"evidence.jsonl": sha256_file(evidence_path), "annotations.jsonl": sha256_file(annotations_path)},
    }
    write_new_json(association_dir / "association-manifest.json", association_manifest)
    release_files = []
    for role, relative in (("raw-alerts","raw/alerts.jsonl"),("alert-index","raw/alert-index.parquet"),
                           ("activities","execution/activities.jsonl"),("execution-evidence","execution/evidence.jsonl"),
                           ("association-evidence","association/evidence.jsonl"),("annotations","association/annotations.jsonl"),
                           ("association-manifest","association/association-manifest.json")):
        path=campaign_dir/relative;release_files.append({"role":role,"path":relative,"sha256":sha256_file(path),"bytes":path.stat().st_size})
    release = {"schema_version":"alertgraph-release-manifest/2.0","dataset_version":"wazuh-supervised-v2",
               "release_id":f"pilot-association:{manifest['run_id']}","campaign_id":manifest["campaign_id"],
               "created_at_utc":now,"frozen_at_utc":now,"campaign_ids":[manifest["campaign_id"]],
               "partition_counts":{"development":1,"validation":0,"final-test":0},"files":release_files,
               "training_ready":False,"limitations":["single controlled benign WinRM activity","only exact marker+PID Sysmon event is verified","development evidence only"]}
    root=campaign_dir.parents[2]
    bundle={"registry":load_json(root/"campaign-registry.json"),"campaign_manifest":manifest,"activities":activities,
            "evidence":[*execution_evidence,*association_evidence],"annotations":annotations,"conflicts":[],"revisions":[],
            "collection_manifest":collection,"release_manifest":release,"raw_events":events}
    validate_bundle(bundle,base_dir=campaign_dir)
    write_new_json(association_dir/"release-manifest.json",release);write_new_json(association_dir/"validation-bundle.json",bundle)
    return association_manifest


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("campaign_dir",type=Path);args=parser.parse_args()
    print(json.dumps(link_controlled_winrm(args.campaign_dir),ensure_ascii=False,indent=2))


if __name__ == "__main__":
    main()
