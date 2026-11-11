"""Construit une matrice événement × activité à partir de preuves exactes V2.

Le module ne modifie pas les annotations historiques. Il crée un artefact
expérimental séparé et refuse tout écrasement. L'absence de lien ne devient
jamais une preuve de non-appartenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

from .io_utils import canonical_json_bytes, load_json, sha256_bytes, sha256_file, utc_now, write_new_bytes, write_new_json
from .membership_supervision import validate_event_activity_matrix
from .prepare_campaign import verify_campaign_reservation


OUTPUT_DIR = "event-activity-matrix-v2"
SSHD_PID = re.compile(r"sshd\[(\d+)\]")


def _win(event: Mapping[str, object]) -> tuple[Mapping[str, object], Mapping[str, object]]:
    data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
    win = data.get("win") if isinstance(data.get("win"), Mapping) else {}
    system = win.get("system") if isinstance(win.get("system"), Mapping) else {}
    eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), Mapping) else {}
    return system, eventdata


def _receipt(campaign_dir: Path, activity: Mapping[str, object], activity_count: int) -> Mapping[str, object]:
    path = campaign_dir / "receipts" / f"{activity['activity_key']}.json"
    if not path.exists() and activity_count == 1:
        path = campaign_dir / "receipts" / "v1-truth.json"
    if not path.is_file():
        raise FileNotFoundError(f"Reçu absent pour {activity['activity_key']}")
    receipt = load_json(path)
    if receipt.get("status") != "completed" or len(receipt.get("steps", [])) != 1:
        raise ValueError(f"Reçu non concluant: {path}")
    return receipt


def _linux_memberships(events, activities, receipts):
    memberships: dict[str, str] = {}
    identities: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for activity in activities:
        activity_id = str(activity["activity_id"])
        result = receipts[activity_id]["steps"][0]["result"]
        port = str(result["target_ssh_connection"]["source_port"])
        boot = str(result.get("target_boot_id") or "boot-unavailable")
        anchors = []
        for event in events:
            rule = event.get("rule") if isinstance(event.get("rule"), Mapping) else {}
            data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
            if str(rule.get("id")) == "5715" and str(data.get("srcport")) == port:
                match = SSHD_PID.search(str(event.get("full_log") or ""))
                if match:
                    anchors.append((str(event["id"]), match.group(1)))
        if len(anchors) != 1:
            raise ValueError(f"Ancre SSH exacte inattendue pour {activity_id}: {len(anchors)}")
        _, pid = anchors[0]
        identity = f"ssh:{boot}:{pid}:{port}"
        identities[activity_id] = identity
        for event in events:
            match = SSHD_PID.search(str(event.get("full_log") or ""))
            if match and match.group(1) == pid:
                alert_id = str(event["id"])
                if alert_id in memberships and memberships[alert_id] != activity_id:
                    memberships[alert_id] = "__conflict__"
                else:
                    memberships[alert_id] = activity_id
                    reasons[alert_id] = "exact-ssh-port-to-sshd-process-instance"
    return memberships, identities, reasons


def _windows_memberships(events, activities, receipts):
    memberships: dict[str, str] = {}
    identities: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for activity in activities:
        activity_id = str(activity["activity_id"])
        result = receipts[activity_id]["steps"][0]["result"]
        marker = str(activity["marker_id"])
        pid = str(result["target_process_id"])
        anchors = []
        for event in events:
            system, data = _win(event)
            if (str(system.get("eventID")) == "1" and str(data.get("processId")) == pid
                    and marker in str(data.get("commandLine") or "")):
                anchors.append((event, data))
        if len(anchors) != 1:
            raise ValueError(f"Ancre Windows exacte inattendue pour {activity_id}: {len(anchors)}")
        anchor, data = anchors[0]
        process_guid = str(data.get("processGuid") or "").lower()
        parent_guid = str(data.get("parentProcessGuid") or "").lower()
        parent_pid = str(data.get("parentProcessId") or "")
        logon_id = str(data.get("logonId") or "").lower()
        if not process_guid:
            raise ValueError(f"ProcessGuid absent pour {activity_id}")
        identity = f"win:{process_guid}:{pid}"
        identities[activity_id] = identity
        for event in events:
            alert_id = str(event["id"])
            system, candidate = _win(event)
            event_id = str(system.get("eventID") or "")
            relation = None
            if alert_id == str(anchor["id"]):
                relation = "exact-marker-pid-processguid"
            elif (event_id == "7" and parent_guid and
                  str(candidate.get("processGuid") or "").lower() == parent_guid and
                  str(candidate.get("processId") or "") == parent_pid):
                relation = "exact-parent-processguid-pid"
            elif (event_id in {"4624", "4634"} and logon_id and
                  str(candidate.get("targetLogonId") or "").lower() == logon_id):
                relation = "exact-logon-session"
            if relation:
                if alert_id in memberships and memberships[alert_id] != activity_id:
                    memberships[alert_id] = "__conflict__"
                    reasons[alert_id] = "multiple-exclusive-activity-paths"
                else:
                    memberships[alert_id] = activity_id
                    reasons[alert_id] = relation
    return memberships, identities, reasons


def build_event_activity_matrix(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("La matrice expérimentale exige development")
    output = campaign_dir / OUTPUT_DIR
    if output.exists():
        raise FileExistsError("La matrice existe déjà")
    plan = load_json(campaign_dir / "campaign-plan.json")
    activities = plan["activities"]
    receipts = {str(a["activity_id"]): _receipt(campaign_dir, a, len(activities)) for a in activities}
    lines = (campaign_dir / "raw" / "alerts.jsonl").read_bytes().splitlines()
    events = [json.loads(line) for line in lines]
    platforms = {str(a["platform"]) for a in activities}
    if platforms == {"linux"}:
        memberships, identities, reasons = _linux_memberships(events, activities, receipts)
        telemetry = "linux-journal"
    elif platforms == {"windows"}:
        memberships, identities, reasons = _windows_memberships(events, activities, receipts)
        telemetry = "windows-sysmon"
    else:
        raise ValueError("Une campagne de matrice doit cibler une seule plateforme")

    now = utc_now(); decisions = []; evidence = []
    by_activity = {str(a["activity_id"]): a for a in activities}
    member_evidence: dict[tuple[str, str], list[str]] = {}
    for event in events:
        alert_id = str(event["id"]); provenance = memberships.get(alert_id)
        if provenance in by_activity:
            receipt_id = f"evidence:{provenance}:matrix-receipt:{alert_id}"
            target_id = f"evidence:{provenance}:matrix-target:{alert_id}"
            member_evidence[(alert_id, provenance)] = [receipt_id, target_id]
            for evidence_id, kind, source in (
                (receipt_id, "execution-receipt", "sealed-orchestrator-receipt"),
                (target_id, "artifact-identity", "wazuh-raw-exact-identity-chain"),
            ):
                evidence.append({
                    "schema_version": "alertgraph-evidence/2.0", "evidence_id": evidence_id,
                    "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
                    "activity_id": provenance, "kind": kind, "recorded_at_utc": now,
                    "source": source,
                    "payload_sha256": sha256_bytes(canonical_json_bytes({"alert_id": alert_id, "identity": identities[provenance], "reason": reasons[alert_id]})),
                    "observed_in_alert_ids": [alert_id],
                })
    for event in events:
        alert_id = str(event["id"]); provenance = memberships.get(alert_id)
        for studied in by_activity:
            if provenance == studied:
                status = "member-verified"; ml_use = "verified-member"; identity = identities[provenance]
                evidence_ids = member_evidence[(alert_id, provenance)]
                families = ["execution-receipt", telemetry, "wazuh-transport"]
                reason_codes = [reasons[alert_id]]
                explanation = "L'événement est relié au reçu par une identité d'exécution exacte."
            elif provenance in by_activity and identities[provenance] != identities[studied]:
                status = "nonmember-verified"; ml_use = "verified-nonmember"; identity = identities[provenance]
                evidence_ids = member_evidence[(alert_id, provenance)]
                families = []
                reason_codes = ["verified-member-of-mutually-exclusive-activity"]
                explanation = "L'événement appartient à une autre instance d'exécution techniquement exclusive."
            else:
                status = "excluded"; ml_use = "excluded"; provenance = None; identity = None
                evidence_ids = []; families = []
                reason_codes = ["no-conclusive-exclusive-provenance"] if memberships.get(alert_id) != "__conflict__" else ["conflicting-identity-paths"]
                explanation = "Les preuves disponibles ne permettent pas une décision forte."
            decisions.append({
                "schema_version": "alertgraph-event-activity-decision/2.0",
                "decision_id": f"matrix:{alert_id}:{studied}", "wazuh_alert_id": alert_id,
                "studied_activity_id": studied, "decision": status,
                "provenance_activity_id": provenance, "exclusive_identity_key": identity,
                "evidence_ids": evidence_ids, "proof_families": families,
                "reason_codes": reason_codes, "explanation": explanation,
                "ml_use": ml_use, "created_at_utc": now,
            })
    validate_event_activity_matrix(
        decisions, raw_alert_ids={str(x["id"]) for x in events},
        activity_ids=set(by_activity), evidence_ids={str(x["evidence_id"]) for x in evidence},
        activity_identity_keys=identities,
    )
    jsonl = lambda xs: b"".join((json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for x in xs)
    write_new_bytes(output / "evidence.jsonl", jsonl(evidence))
    write_new_bytes(output / "decisions.jsonl", jsonl(decisions))
    counts = {name: sum(x["decision"] == name for x in decisions) for name in ("member-verified", "nonmember-verified", "excluded")}
    report = {
        "schema_version": "alertgraph-event-activity-matrix-report/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "created_at_utc": now, "raw_events": len(events), "activities": len(activities),
        "matrix_cells": len(decisions), **counts,
        "resolved_cells_percent": round(100 * (counts["member-verified"] + counts["nonmember-verified"]) / len(decisions), 3),
        "cross_associations": sum(v == "__conflict__" for v in memberships.values()),
        "training_ready": False, "activity_identity_keys": identities,
        "files": {"evidence.jsonl": sha256_file(output / "evidence.jsonl"), "decisions.jsonl": sha256_file(output / "decisions.jsonl")},
    }
    write_new_json(output / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(build_event_activity_matrix(args.campaign_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
