"""Revue stricte d'une tentative SSH échouée contrôlée."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

from .collect_campaign import verify_collection
from .io_utils import canonical_json_bytes, load_json, sha256_bytes, sha256_file, utc_now, write_new_bytes, write_new_json
from .membership_supervision import validate_event_activity_matrix
from .prepare_campaign import verify_campaign_reservation


PID = re.compile(r"sshd\[(\d+)\]")


def exact_failed_ssh_identity(
    receipt_result: Mapping[str, object], *, source_ip: str, source_port: int,
    target_ip: str, pid: str, boot_id: str,
) -> str | None:
    """Retourne l'identité seulement si le tuple contrôleur est complet."""

    socket = receipt_result.get("controller_socket")
    if not isinstance(socket, Mapping):
        return None
    if not receipt_result.get("identity_capture_complete"):
        return None
    expected = {
        "source_ip": source_ip, "source_port": source_port,
        "target_ip": target_ip, "target_port": 22,
    }
    if any(socket.get(k) != v for k, v in expected.items()):
        return None
    return f"ssh-failed:{boot_id}:{pid}:{source_ip}:{source_port}:{target_ip}:22"


def review_failed_ssh_pilot(campaign_dir: str | Path, *, activity_key: str, pid: str) -> dict[str, object]:
    campaign_dir = Path(campaign_dir); manifest = verify_campaign_reservation(campaign_dir)
    collection = verify_collection(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json")
    activity = next(x for x in plan["activities"] if x["activity_key"] == activity_key)
    receipt = load_json(campaign_dir / "receipts" / f"{activity_key}.json")
    result = receipt["steps"][0]["result"]
    raw_lines = (campaign_dir / "raw" / "alerts.jsonl").read_bytes().splitlines()
    events = [json.loads(x) for x in raw_lines]
    journal_path = campaign_dir / "supplementary" / f"linux-journal-pid-{pid}.jsonl"
    journal_lines = journal_path.read_bytes().splitlines(); journal = [json.loads(x) for x in journal_lines]
    from .boot_id import canonical_boot_id
    boot_ids = {canonical_boot_id(x.get("_BOOT_ID")) for x in journal}; journal_pids = {str(x.get("_PID")) for x in journal}
    if len(boot_ids) != 1 or journal_pids != {pid}:
        raise ValueError("Identité journald non unique")
    boot_id = next(iter(boot_ids)); now = utc_now()
    activity_id = str(activity["activity_id"]); all_activity_ids = {str(x["activity_id"]) for x in plan["activities"]}
    evidence = []; matched = []; identities: dict[str, str] = {}
    for event, raw_line in zip(events, raw_lines):
        full_log = str(event.get("full_log") or "")
        match = PID.search(full_log)
        data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
        candidates = [x for x in journal if str(x.get("MESSAGE") or "") in full_log]
        if match and match.group(1) == pid and len(candidates) == 1:
            matched.append(event)
            identity = exact_failed_ssh_identity(
                result, source_ip=str(data.get("srcip") or ""),
                source_port=int(data.get("srcport")),
                target_ip=str(plan["safety_policy"]["authorized_target"]),
                pid=pid, boot_id=boot_id,
            )
            if identity:
                identities[str(event["id"])] = identity
            chain_state = "complete-failed-ssh-path" if identity else "incomplete-failed-ssh-path"
            evidence_id = f"evidence:{activity_id}:{chain_state}:{event['id']}"
            payload = {
                "receipt_exit_code": receipt["steps"][0]["exit_code"],
                "controller_socket_captured": result.get("controller_socket") is not None,
                "controller_socket_evidence_sha256": result.get("controller_socket_evidence_sha256"),
                "exact_identity_verified": identity,
                "source_ip": data.get("srcip"), "source_port": data.get("srcport"),
                "target_ip": plan["safety_policy"]["authorized_target"],
                "pid": pid, "boot_id": boot_id, "cursor": candidates[0].get("__CURSOR"),
                "raw_sha256": hashlib.sha256(raw_line).hexdigest(),
            }
            evidence.append({
                "schema_version": "alertgraph-evidence/2.0", "evidence_id": evidence_id,
                "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
                "activity_id": activity_id, "kind": "artifact-identity", "recorded_at_utc": now,
                "source": (
                    "receipt+controller-network+target-journald+wazuh-raw"
                    if identity else "receipt+target-journald+wazuh-raw-incomplete-controller-tuple"
                ),
                "payload_sha256": sha256_bytes(canonical_json_bytes(payload)),
                "observed_in_alert_ids": [str(event["id"])],
            })
    decisions = []
    for event in events:
        alert_id = str(event["id"])
        for studied in sorted(all_activity_ids):
            targeted = studied == activity_id
            verified_identity = identities.get(alert_id) if targeted else None
            verified = verified_identity is not None
            decisions.append({
                "schema_version": "alertgraph-event-activity-decision/2.0",
                "decision_id": f"matrix:{alert_id}:{studied}:failed-ssh-pilot",
                "wazuh_alert_id": alert_id, "studied_activity_id": studied,
                "decision": "member-verified" if verified else "excluded",
                "provenance_activity_id": activity_id if verified else None,
                "exclusive_identity_key": verified_identity,
                "evidence_ids": ([f"evidence:{activity_id}:complete-failed-ssh-path:{alert_id}"]
                                 if verified else
                                 [f"evidence:{activity_id}:incomplete-failed-ssh-path:{alert_id}"]
                                 if targeted and event in matched else []),
                "proof_families": (["execution-receipt", "controller-network", "linux-journal", "wazuh-transport"]
                                   if verified else
                                   ["execution-receipt", "linux-journal", "wazuh-transport"]
                                   if targeted and event in matched else []),
                "reason_codes": (["exact-controller-target-journal-wazuh-chain"] if verified else
                                 ["controller-network-tuple-not-captured"] if targeted else
                                 ["activity-not-executed"]),
                "explanation": (
                    "Le tuple contrôleur, le PID sshd, BootId, journald et Wazuh concordent exactement."
                    if verified else
                    "La chaîne cible est cohérente mais le tuple réseau indépendant du contrôleur manque."
                    if targeted else "Cette activité planifiée n'a pas été exécutée."
                ),
                "ml_use": "verified-member" if verified else "excluded", "created_at_utc": now,
            })
    validate_event_activity_matrix(
        decisions, raw_alert_ids={str(x["id"]) for x in events},
        activity_ids=all_activity_ids, evidence_ids={str(x["evidence_id"]) for x in evidence},
        activity_identity_keys={activity_id: next(iter(set(identities.values())))} if identities else {},
    )
    output = campaign_dir / "failed-ssh-pilot-review-v2"
    jsonl = lambda xs: b"".join((json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for x in xs)
    write_new_bytes(output / "evidence.jsonl", jsonl(evidence)); write_new_bytes(output / "decisions.jsonl", jsonl(decisions))
    report = {
        "schema_version": "alertgraph-failed-ssh-pilot-review/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"], "activity_id": activity_id,
        "created_at_utc": now, "raw_events": len(events), "journal_entries": len(journal),
        "target_chain_matches": len(matched), "member_verified": len(identities), "nonmember_verified": 0,
        "excluded_events": len(events) - len(identities),
        "matrix_excluded_cells": sum(x["decision"] == "excluded" for x in decisions),
        "blocking_reason": (None if len(identities) == len(events) and events else
                            "no-wazuh-event" if not events else
                            "incomplete-independent-proof-chain"),
        "can_proceed_to_next_offensive_activity": bool(events) and len(identities) == len(events), "training_ready": False,
        "collection_sha256": collection["files"][0]["sha256"],
        "journal_sha256": sha256_file(journal_path),
        "files": {"evidence.jsonl": sha256_file(output / "evidence.jsonl"), "decisions.jsonl": sha256_file(output / "decisions.jsonl")},
    }
    write_new_json(output / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--activity-key", required=True); parser.add_argument("--pid", required=True)
    args = parser.parse_args(); print(json.dumps(review_failed_ssh_pilot(args.campaign_dir, activity_key=args.activity_key, pid=args.pid), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
