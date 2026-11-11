"""Exécute une unique activité SSH bénigne V2 et produit un reçu V1 adaptable.

Le module n'altère pas la cible. La commande distante imprime un marqueur et
le tuple ``SSH_CONNECTION``, attend brièvement, puis se termine avec succès.
Le contrôleur capture en parallèle le socket appartenant au processus SSH.
"""

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
from .io_utils import load_json, write_new_json
from .prepare_campaign import verify_campaign_reservation


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ssh_connection(value: str) -> dict[str, object]:
    """Parse ``client_ip client_port server_ip server_port`` strictly."""

    parts = value.split()
    if len(parts) != 4:
        raise ValueError(f"SSH_CONNECTION invalide: {value!r}")
    client_ip, client_port, server_ip, server_port = parts
    return {
        "source_ip": client_ip,
        "source_port": int(client_port),
        "target_ip": server_ip,
        "target_port": int(server_port),
    }


def _capture_controller_socket(
    pid: int, target_ip: str, target_port: int
) -> dict[str, object] | None:
    script = (
        f"$c=Get-NetTCPConnection -OwningProcess {pid} -State Established "
        "-ErrorAction SilentlyContinue | "
        f"Where-Object {{$_.RemoteAddress -eq '{target_ip}' -and "
        f"$_.RemotePort -eq {target_port}}} | Select-Object -First 1; "
        "if($null -eq $c){exit 3}; "
        "[ordered]@{source_ip=$c.LocalAddress;source_port=[int]$c.LocalPort;"
        "target_ip=$c.RemoteAddress;target_port=[int]$c.RemotePort;"
        "owning_process=[int]$c.OwningProcess}|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return dict(value) if isinstance(value, Mapping) else None


def _planned_activity(plan: Mapping[str, object], activity_key: str) -> Mapping[str, object]:
    matches = [x for x in plan["activities"] if x["activity_key"] == activity_key]
    if len(matches) != 1:
        raise ValueError(f"Activité planifiée introuvable ou ambiguë: {activity_key}")
    activity = matches[0]
    if activity["class"] != "benign" or activity["platform"] != "linux":
        raise ValueError("Ce runner accepte uniquement une activité Linux bénigne")
    return activity


def run_benign_ssh_activity(
    campaign_dir: str | Path,
    *,
    activity_key: str,
    host: str,
    user: str,
    key: str | Path,
    hold_seconds: int = 8,
    receipt_filename: str = "v1-truth.json",
) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("Le runner pilote exige la partition development")
    require_clock_ready(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json")
    activity = _planned_activity(plan, activity_key)
    if host not in activity["target_hosts"]:
        raise ValueError("Hôte SSH absent du plan scellé")
    if hold_seconds < 3 or hold_seconds > 30:
        raise ValueError("hold_seconds doit être compris entre 3 et 30")
    if Path(receipt_filename).name != receipt_filename or not receipt_filename.endswith(".json"):
        raise ValueError("receipt_filename doit être un simple nom JSON")

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
    remote_command = f"python3 -c {shlex.quote(remote_code)}"
    command = [
        "ssh", "-T", "-i", str(Path(key)),
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1", "-o", "ClearAllForwardings=yes",
        f"{user}@{host}", remote_command,
    ]

    controller_started = _utc_now()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    socket_capture = None
    deadline = time.monotonic() + min(6, hold_seconds)
    while time.monotonic() < deadline and process.poll() is None:
        socket_capture = _capture_controller_socket(process.pid, host, 22)
        if socket_capture is not None:
            break
        time.sleep(0.2)
    try:
        stdout, stderr = process.communicate(timeout=hold_seconds + 15)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise TimeoutError("L'activité SSH contrôlée a dépassé son délai")
    controller_ended = _utc_now()

    target = None
    if process.returncode == 0:
        try:
            target = json.loads(stdout.decode("utf-8").strip())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Reçu JSON distant invalide") from exc
        if target.get("marker") != marker or target.get("user") != user:
            raise ValueError("Identité du reçu distant incohérente")
        target_tuple = parse_ssh_connection(str(target.get("ssh_connection") or ""))
    else:
        target_tuple = None

    tuple_match = bool(
        socket_capture
        and target_tuple
        and all(
            socket_capture.get(name) == target_tuple.get(name)
            for name in ("source_ip", "source_port", "target_ip", "target_port")
        )
        and socket_capture.get("owning_process") == process.pid
    )
    step = {
        "name": activity["activity_name"],
        "ground_truth_phase": activity.get("true_activity_phase"),
        "started_at": controller_started,
        "ended_at": controller_ended,
        "target_started_at_utc": target.get("target_started_at_utc") if target else None,
        "target_ended_at_utc": target.get("target_ended_at_utc") if target else None,
        "exit_code": int(process.returncode),
        "result": {
            "platform": "linux",
            "operation": "controlled-legitimate-ssh-login",
            "ssh_pid": process.pid,
            "controller_socket": socket_capture,
            "target_ssh_connection": target_tuple,
            "connection_tuple_match": tuple_match,
            "marker_echoed": bool(target and target.get("marker") == marker),
            "target_boot_id": target.get("boot_id") if target else None,
            "target_process_id": int(target["process_id"]) if target else None,
            "target_parent_process_id": int(target["parent_process_id"]) if target else None,
            "target_process_start_ticks": str(target.get("process_start_ticks")) if target else None,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        },
    }
    receipt = {
        "status": "completed" if process.returncode == 0 else "failed",
        "steps": [step],
    }
    receipt_path = campaign_dir / "receipts" / receipt_filename
    write_new_json(receipt_path, receipt)
    return {"receipt": str(receipt_path), "step": step}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--activity-key", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--hold-seconds", type=int, default=8)
    parser.add_argument("--receipt-filename", default="v1-truth.json")
    args = parser.parse_args()
    report = run_benign_ssh_activity(
        args.campaign_dir,
        activity_key=args.activity_key,
        host=args.host,
        user=args.user,
        key=args.key,
        hold_seconds=args.hold_seconds,
        receipt_filename=args.receipt_filename,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
