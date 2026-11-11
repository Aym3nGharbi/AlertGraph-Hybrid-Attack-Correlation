"""Exécute une connexion SSH réussie d'attaque préenregistrée avec capture TCP persistante."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .clock_audit import require_clock_ready
from .io_utils import load_json, sha256_file, write_new_bytes, write_new_json
from .persistent_socket_observer import PersistentSocketObserver
from .prepare_campaign import verify_campaign_reservation
from .run_benign_ssh_activity import parse_ssh_connection
from .run_controlled_failed_ssh_activity import select_process_tuple


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _activity(plan: Mapping[str, object], activity_key: str) -> Mapping[str, object]:
    matches = [x for x in plan["activities"] if x["activity_key"] == activity_key]
    if len(matches) != 1:
        raise ValueError("Activité absente ou ambiguë")
    item = matches[0]
    if (item["class"] != "attack" or item.get("activity_role") != "authorized-login-in-simulation"
            or item.get("platform") != "linux"):
        raise ValueError("Le runner exige une connexion SSH réussie d'attaque Linux préenregistrée")
    return item


def run_successful_ssh_activity(
    campaign_dir: str | Path, *, activity_key: str, host: str, user: str,
    key: str | Path, receipt_filename: str, hold_seconds: int = 5,
) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("L'exécution exige development")
    require_clock_ready(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json")
    activity = _activity(plan, activity_key)
    safety = plan.get("safety_policy") or {}
    if host != safety.get("authorized_target") or host not in activity["target_hosts"]:
        raise ValueError("Cible hors du plan scellé")
    if user != safety.get("authorized_success_user"):
        raise ValueError("Compte de succès hors du plan scellé")
    if not 3 <= hold_seconds <= 15:
        raise ValueError("Durée de maintien hors limites")
    if Path(receipt_filename).name != receipt_filename or not receipt_filename.endswith(".json"):
        raise ValueError("Nom de reçu invalide")

    marker = str(activity["marker_id"])
    remote_code = (
        "import datetime,getpass,json,os,time;"
        "u=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();"
        "p=os.getpid();pp=os.getppid();"
        "b=open('/proc/sys/kernel/random/boot_id').read().strip();"
        "st=open('/proc/self/stat').read().split()[21];"
        "s=u();time.sleep(%d);"
        "print(json.dumps({'marker':%r,'target_started_at_utc':s,"
        "'target_ended_at_utc':u(),'ssh_connection':os.environ.get('SSH_CONNECTION'),"
        "'user':getpass.getuser(),'boot_id':b,'process_id':p,"
        "'parent_process_id':pp,'process_start_ticks':st}))"
    ) % (hold_seconds, marker)
    command = [
        "ssh", "-T", "-i", str(Path(key)),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=0",
        "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=10",
        "-o", "ClearAllForwardings=yes", "-o", "StrictHostKeyChecking=yes",
        f"{user}@{host}", f"python3 -c {shlex.quote(remote_code)}",
    ]

    observer = PersistentSocketObserver(host, 22)
    observer.start()
    if not observer.ready:
        raise RuntimeError("L'observateur TCP n'est pas prêt")
    started = _utc_now()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=hold_seconds + 20)
        time.sleep(0.15)
    finally:
        observer.stop()
    ended = _utc_now()
    observations = observer.observations()
    controller_tuple = select_process_tuple(observations, pid=process.pid, target_ip=host)
    if process.returncode != 0:
        raise RuntimeError("La connexion SSH autorisée a échoué")
    try:
        target = json.loads(stdout.decode("utf-8").strip())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Reçu JSON distant invalide") from exc
    if target.get("marker") != marker or target.get("user") != user:
        raise ValueError("Identité du reçu distant incohérente")
    target_tuple = parse_ssh_connection(str(target.get("ssh_connection") or ""))
    tuple_match = bool(
        controller_tuple and all(controller_tuple.get(k) == target_tuple.get(k)
                                 for k in ("source_ip", "source_port", "target_ip", "target_port"))
        and controller_tuple.get("owning_process") == process.pid
    )
    if not tuple_match:
        raise RuntimeError("Le tuple contrôleur ne correspond pas à SSH_CONNECTION")

    evidence_relative = f"receipts/evidence/{activity_key}-controller-socket-observations.jsonl"
    evidence_path = campaign_dir / evidence_relative
    evidence_bytes = b"".join(
        (json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        for x in observations
    )
    write_new_bytes(evidence_path, evidence_bytes)
    process_samples = sum(x.get("pid") == process.pid for x in observations)
    step = {
        "name": activity["activity_name"], "ground_truth_phase": activity.get("true_activity_phase"),
        "started_at": started, "ended_at": ended,
        "target_started_at_utc": target["target_started_at_utc"],
        "target_ended_at_utc": target["target_ended_at_utc"], "exit_code": 0,
        "result": {
            "platform": "linux", "operation": "controlled-authorized-ssh-login-in-simulation",
            "ssh_pid": process.pid, "controller_socket": controller_tuple,
            "target_ssh_connection": target_tuple, "connection_tuple_match": True,
            "target_boot_id": target["boot_id"], "target_process_id": int(target["process_id"]),
            "target_parent_process_id": int(target["parent_process_id"]),
            "target_process_start_ticks": str(target["process_start_ticks"]),
            "marker_echoed": True, "identity_capture_complete": process_samples > 0,
            "controller_socket_evidence_path": evidence_relative,
            "controller_socket_evidence_sha256": sha256_file(evidence_path),
            "controller_socket_samples": process_samples,
            "controller_socket_observer_health": observer.health(),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        },
    }
    receipt = {"status": "completed", "steps": [step]}
    path = campaign_dir / "receipts" / receipt_filename
    write_new_json(path, receipt)
    return {"receipt": str(path), "step": step}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path); parser.add_argument("--activity-key", required=True)
    parser.add_argument("--host", required=True); parser.add_argument("--user", required=True)
    parser.add_argument("--key", required=True, type=Path); parser.add_argument("--hold-seconds", type=int, default=5)
    parser.add_argument("--receipt-filename", required=True)
    args = parser.parse_args()
    print(json.dumps(run_successful_ssh_activity(
        args.campaign_dir, activity_key=args.activity_key, host=args.host, user=args.user,
        key=args.key, receipt_filename=args.receipt_filename, hold_seconds=args.hold_seconds,
    ), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
