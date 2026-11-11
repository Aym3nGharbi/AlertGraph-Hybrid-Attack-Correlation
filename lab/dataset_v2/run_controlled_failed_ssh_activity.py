"""Orchestrateur V2 d'une unique tentative SSH invalide préenregistrée.

L'exécution réelle exige explicitement ``--execute-authorized``. Sans ce
drapeau, le programme produit seulement un aperçu local sans connexion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .clock_audit import require_clock_ready
from .io_utils import load_json, sha256_file, write_new_bytes, write_new_json
from .persistent_socket_observer import PersistentSocketObserver
from .prepare_campaign import verify_campaign_reservation


FIXED_INVALID_USER = "alertgraph_probe_noaccount"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_failed_ssh_command(host: str, key: str | Path, *, invalid_user: str = FIXED_INVALID_USER) -> list[str]:
    if invalid_user != FIXED_INVALID_USER:
        raise ValueError("Le nom invalide fixe préenregistré est obligatoire")
    return [
        "ssh", "-T", "-i", str(Path(key)),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=0",
        "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=5",
        "-o", "ClearAllForwardings=yes", "-o", "StrictHostKeyChecking=yes",
        f"{invalid_user}@{host}", "true",
    ]


def _activity(plan: Mapping[str, object], activity_key: str) -> Mapping[str, object]:
    matches = [x for x in plan["activities"] if x["activity_key"] == activity_key]
    if len(matches) != 1:
        raise ValueError("Activité absente ou ambiguë")
    item = matches[0]
    if item["class"] != "attack" or item.get("activity_role") != "failed-authentication":
        raise ValueError("Le runner accepte uniquement une activité d'échec SSH préenregistrée")
    return item


def select_process_tuple(observations: list[Mapping[str, object]], *, pid: int,
                         target_ip: str, target_port: int = 22) -> dict[str, object] | None:
    tuples = {
        (str(x["source_ip"]), int(x["source_port"]), str(x["target_ip"]), int(x["target_port"]))
        for x in observations
        if x.get("pid") == pid and x.get("target_ip") == target_ip and int(x.get("target_port", -1)) == target_port
    }
    if len(tuples) != 1:
        return None
    source_ip, source_port, remote_ip, remote_port = next(iter(tuples))
    return {"source_ip": source_ip, "source_port": source_port, "target_ip": remote_ip,
            "target_port": remote_port, "owning_process": pid,
            "observer": "psutil-net-connections-persistent-v1"}


def preview_failed_ssh_activity(campaign_dir: str | Path, *, activity_key: str, host: str) -> dict[str, object]:
    campaign_dir = Path(campaign_dir); verify_campaign_reservation(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json"); activity = _activity(plan, activity_key)
    safety = plan.get("safety_policy") or {}
    if host != safety.get("authorized_target") or host not in activity["target_hosts"]:
        raise ValueError("Cible hors du plan scellé")
    return {
        "mode": "preview-only", "activity_id": activity["activity_id"],
        "attack_instance_id": activity["attack_instance_id"], "target": host,
        "invalid_user": safety["invalid_username"], "attempts": 1,
        "password_authentication": False, "connection_attempts": 1,
        "expected_exit": "nonzero", "network_action_executed": False,
    }


def run_failed_ssh_activity(
    campaign_dir: str | Path, *, activity_key: str, host: str, key: str | Path,
    receipt_filename: str, execute_authorized: bool,
) -> dict[str, object]:
    if not execute_authorized:
        return preview_failed_ssh_activity(campaign_dir, activity_key=activity_key, host=host)
    campaign_dir = Path(campaign_dir); manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("L'exécution exige development")
    require_clock_ready(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json"); activity = _activity(plan, activity_key)
    safety = plan.get("safety_policy") or {}
    if host != safety.get("authorized_target") or host not in activity["target_hosts"]:
        raise ValueError("Cible hors du plan scellé")
    if Path(receipt_filename).name != receipt_filename or not receipt_filename.endswith(".json"):
        raise ValueError("Nom de reçu invalide")
    command = build_failed_ssh_command(host, key, invalid_user=str(safety["invalid_username"]))
    observer = PersistentSocketObserver(host, 22)
    observer.start()
    if not observer.ready:
        raise RuntimeError("L'observateur TCP n'est pas prêt")
    started = _utc_now()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=10)
        time.sleep(0.15)
    finally:
        observer.stop()
    ended = _utc_now(); raw_observations = observer.observations()
    socket_capture = select_process_tuple(raw_observations, pid=process.pid, target_ip=host)
    if process.returncode == 0:
        raise RuntimeError("La tentative invalide a réussi de façon inattendue : arrêt obligatoire")
    evidence_relative = f"receipts/evidence/{activity_key}-controller-socket-observations.jsonl"
    evidence_path = campaign_dir / evidence_relative
    evidence_bytes = b"".join(
        (json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        for x in raw_observations
    )
    write_new_bytes(evidence_path, evidence_bytes)
    process_samples = sum(x.get("pid") == process.pid for x in raw_observations)
    step = {
        "name": activity["activity_name"], "ground_truth_phase": activity.get("true_activity_phase"),
        "started_at": started, "ended_at": ended, "target_started_at_utc": None,
        "target_ended_at_utc": None, "exit_code": int(process.returncode),
        "result": {
            "platform": "linux", "operation": "controlled-invalid-user-ssh-attempt",
            "ssh_pid": process.pid, "controller_socket": socket_capture,
            "controller_socket_evidence_path": evidence_relative,
            "controller_socket_evidence_sha256": sha256_file(evidence_path),
            "controller_socket_samples": process_samples,
            "controller_socket_observer_health": observer.health(),
            "expected_authentication_failure": True,
            "invalid_user_spec_sha256": hashlib.sha256(FIXED_INVALID_USER.encode()).hexdigest(),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "identity_capture_complete": socket_capture is not None and process_samples > 0,
        },
    }
    receipt = {"status": "completed", "steps": [step]}
    path = campaign_dir / "receipts" / receipt_filename; write_new_json(path, receipt)
    return {"receipt": str(path), "step": step}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path); parser.add_argument("--activity-key", required=True)
    parser.add_argument("--host", required=True); parser.add_argument("--key", type=Path)
    parser.add_argument("--receipt-filename", default="failed-ssh.json")
    parser.add_argument("--execute-authorized", action="store_true")
    args = parser.parse_args()
    if args.execute_authorized and args.key is None:
        parser.error("--key est obligatoire avec --execute-authorized")
    result = run_failed_ssh_activity(
        args.campaign_dir, activity_key=args.activity_key, host=args.host,
        key=args.key or Path("not-used-in-preview"), receipt_filename=args.receipt_filename,
        execute_authorized=args.execute_authorized,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
