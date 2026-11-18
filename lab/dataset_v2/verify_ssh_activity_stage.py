"""Vérifie et conserve la chaîne de preuves d'une étape SSH A1."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from lab.collect_wazuh import instant

from .io_utils import load_json, sha256_bytes, utc_now, write_new_bytes, write_new_json
from .prepare_campaign import verify_campaign_reservation


PID = re.compile(r"sshd\[(\d+)\]")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _remote(command: list[str], *, timeout: int = 30) -> bytes:
    result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError("Lecture distante de preuve échouée")
    return result.stdout


def _matching_wazuh_lines(payload: bytes, *, agent: str, source_ip: str,
                          source_port: int, started: float, ended: float) -> list[bytes]:
    rows: list[bytes] = []
    for line in payload.splitlines(keepends=True):
        try:
            event = json.loads(line)
            timestamp = instant(str(event["timestamp"]))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        if not started <= timestamp <= ended or event.get("agent", {}).get("name") != agent:
            continue
        data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
        full_log = str(event.get("full_log") or "")
        direct = (str(data.get("srcip") or "") == source_ip
                  and str(data.get("srcport") or "") == str(source_port))
        textual = source_ip in full_log and f"port {source_port}" in full_log
        if (direct or textual) and PID.search(full_log):
            rows.append(line)
    return rows


def verify_stage(
    campaign_dir: str | Path, *, activity_key: str,
    manager_host: str, manager_user: str, target_host: str, target_user: str,
    key: str | Path, wait_seconds: int = 12,
) -> dict[str, object]:
    campaign_dir = Path(campaign_dir); manifest = verify_campaign_reservation(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json")
    activities = [x for x in plan["activities"] if x["activity_key"] == activity_key]
    if len(activities) != 1:
        raise ValueError("Activité absente ou ambiguë")
    activity = activities[0]
    receipt = load_json(campaign_dir / "receipts" / f"{activity_key}.json")
    step = receipt["steps"][0]; result = step["result"]
    socket = result.get("controller_socket")
    if not isinstance(socket, Mapping) or not result.get("identity_capture_complete"):
        raise ValueError("Tuple contrôleur incomplet")
    source_ip = str(socket["source_ip"]); source_port = int(socket["source_port"])
    if (source_ip != plan["safety_policy"]["authorized_source"]
            or socket["target_ip"] != target_host or int(socket["target_port"]) != 22):
        raise ValueError("Tuple hors du plan scellé")
    started_dt = datetime.fromisoformat(str(step["started_at"])) - timedelta(seconds=3)
    ended_dt = datetime.fromisoformat(str(step["ended_at"])) + timedelta(seconds=wait_seconds)
    started = started_dt.timestamp(); ended = ended_dt.timestamp()
    base = ["ssh", "-T", "-i", str(Path(key)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    manager_payload = b""; matched_lines: list[bytes] = []
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() <= deadline:
        manager_payload = _remote(base + [f"{manager_user}@{manager_host}", "cat -- /var/ossec/logs/alerts/alerts.json"])
        matched_lines = _matching_wazuh_lines(
            manager_payload, agent=str(activity["target_agents"][0]),
            source_ip=source_ip, source_port=source_port, started=started, ended=ended,
        )
        if matched_lines:
            break
        time.sleep(2)
    if not matched_lines:
        raise RuntimeError("Aucune alerte Wazuh avec le tuple contrôleur exact")
    direct_events = [json.loads(x) for x in matched_lines]
    pids = {PID.search(str(x.get("full_log") or "")).group(1) for x in direct_events}
    if len(pids) != 1:
        raise ValueError("PID sshd absent ou ambigu")
    pid = next(iter(pids))
    journal_command = (
        "journalctl --utc --since " + repr(_iso(started_dt))
        + " --until " + repr(_iso(ended_dt)) + f" -o json _PID={pid} --no-pager"
    )
    journal_payload = _remote(base + [f"{target_user}@{target_host}", journal_command])
    journal = [json.loads(x) for x in journal_payload.splitlines() if x.strip()]
    from .boot_id import canonical_boot_id, same_boot_id
    boot_ids = {canonical_boot_id(x.get("_BOOT_ID")) for x in journal}
    if len(boot_ids) != 1 or any(str(x.get("_PID")) != pid for x in journal):
        raise ValueError("Identité journald absente ou ambiguë")
    boot_id = next(iter(boot_ids))
    if result.get("target_boot_id") and not same_boot_id(result["target_boot_id"], boot_id):
        raise ValueError("BootId reçu/journald incohérent")
    journal_messages = {str(x.get("MESSAGE") or "") for x in journal}
    if any(not any(message and message in str(event.get("full_log") or "") for message in journal_messages)
           for event in direct_events):
        raise ValueError("Une alerte Wazuh n'a pas de ligne journald exacte")
    operation = str(result.get("operation") or "")
    if "invalid-user" in operation and int(step["exit_code"]) == 0:
        raise ValueError("Échec SSH prévu mais succès observé")
    if "authorized" in operation:
        if int(step["exit_code"]) != 0 or not result.get("connection_tuple_match"):
            raise ValueError("Succès SSH ou tuple cible non confirmé")

    output = campaign_dir / "stages" / activity_key
    write_new_bytes(output / "wazuh-matches.jsonl", b"".join(matched_lines))
    write_new_bytes(output / "journal-pid.jsonl", journal_payload)
    report = {
        "schema_version": "alertgraph-a1-stage-verification/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "activity_id": activity["activity_id"], "attack_instance_id": activity["attack_instance_id"],
        "verified_at_utc": utc_now(), "status": "member-verified",
        "controller_tuple": dict(socket), "sshd_pid": int(pid), "boot_id": boot_id,
        "post_auth_parent_pid": result.get("target_parent_process_id"),
        "sshd_process_transition_note": (
            "Le PID Wazuh/journald identifie le processus d'authentification; "
            "le parent du processus distant peut être un descendant post-authentification."
            if result.get("target_parent_process_id") else None
        ),
        "wazuh_alert_ids": [str(x["id"]) for x in direct_events],
        "wazuh_rules": [str(x.get("rule", {}).get("id", "")) for x in direct_events],
        "journal_cursors": [str(x.get("__CURSOR")) for x in journal],
        "proof_families": ["sealed-receipt", "controller-network", "target-journald", "wazuh-raw"],
        "files": {
            "wazuh-matches.jsonl": sha256_bytes(b"".join(matched_lines)),
            "journal-pid.jsonl": sha256_bytes(journal_payload),
        },
        "time_only_used_as_membership_proof": False, "training_ready": False,
    }
    write_new_json(output / "verification.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--activity-key", required=True); parser.add_argument("--manager-host", required=True)
    parser.add_argument("--manager-user", required=True); parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-user", required=True); parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--wait-seconds", type=int, default=12)
    args = parser.parse_args(); print(json.dumps(verify_stage(
        args.campaign_dir, activity_key=args.activity_key, manager_host=args.manager_host,
        manager_user=args.manager_user, target_host=args.target_host, target_user=args.target_user,
        key=args.key, wait_seconds=args.wait_seconds,
    ), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
