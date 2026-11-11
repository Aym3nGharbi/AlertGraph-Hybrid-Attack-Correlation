"""Valide l'observateur TCP avec des connexions SSH légitimes et bénignes."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .io_utils import sha256_file, utc_now, write_new_bytes, write_new_json
from .persistent_socket_observer import PersistentSocketObserver


def _jsonl(items):
    return b"".join((json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for x in items)


def _remote_command(hold_seconds: float, trial_id: str) -> str:
    code = (
        "import datetime,json,os,time;"
        "u=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();"
        "s=u();time.sleep(%r);"
        "print(json.dumps({'trial_id':%r,'ssh_connection':os.environ.get('SSH_CONNECTION'),"
        "'target_started_at_utc':s,'target_ended_at_utc':u(),'pid':os.getpid(),'ppid':os.getppid(),"
        "'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip()}))"
    ) % (hold_seconds, trial_id)
    return f"python3 -c {shlex.quote(code)}"


def _parse_tuple(value: str) -> dict[str, object]:
    parts = value.split()
    if len(parts) != 4:
        raise ValueError("SSH_CONNECTION invalide")
    return {"source_ip": parts[0], "source_port": int(parts[1]), "target_ip": parts[2], "target_port": int(parts[3])}


def _launch(host: str, user: str, key: Path, trial_id: str, hold: float):
    command = ["ssh", "-T", "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
               "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=10", "-o", "ClearAllForwardings=yes",
               f"{user}@{host}", _remote_command(hold, trial_id)]
    started = utc_now(); process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        create_time = psutil.Process(process.pid).create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        create_time = None
    return process, started, create_time


def _finish(process, started, create_time, trial_id):
    stdout, stderr = process.communicate(timeout=20); ended = utc_now()
    target = json.loads(stdout.decode("utf-8").strip()) if process.returncode == 0 else None
    return {
        "trial_id": trial_id, "controller_pid": process.pid, "controller_process_create_time": create_time,
        "controller_started_at_utc": started, "controller_ended_at_utc": ended,
        "exit_code": process.returncode, "target_receipt": target,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def run_validation(output_dir: Path, *, host: str, user: str, key: Path) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    suite_started = datetime.now(timezone.utc); observations=[]; receipts=[]; cycle_reports=[]
    plans = [
        [("isolated", 2.0)],
        [("successive-1", 0.15), ("successive-2", 0.15)],
        [("simultaneous-a", 0.75), ("simultaneous-b", 0.75)],
        [("very-short-1", 0.0), ("very-short-2", 0.0), ("very-short-3", 0.0)],
        [("after-restart-1", 0.05)],
        [("after-restart-2", 0.05)],
    ]
    for cycle_index, cycle in enumerate(plans, 1):
        observer = PersistentSocketObserver(host, 22); observer.start()
        if not observer.ready:
            raise RuntimeError("Observateur non prêt")
        if cycle_index == 3:
            running=[]
            for trial_id, hold in cycle:
                process, started, create_time = _launch(host, user, key, trial_id, hold)
                running.append((process, started, create_time, trial_id))
            for args in running:
                receipts.append(_finish(*args))
        else:
            for trial_id, hold in cycle:
                process, started, create_time = _launch(host, user, key, trial_id, hold)
                receipts.append(_finish(process, started, create_time, trial_id))
        time.sleep(0.15); observer.stop(); cycle_observations=observer.observations()
        observations.extend({**x, "observer_cycle": cycle_index} for x in cycle_observations)
        cycle_reports.append({"cycle": cycle_index, **observer.health()})
    suite_ended = datetime.now(timezone.utc)

    # Lecture journald après la borne finale : la connexion d'audit ne peut pas entrer dans la fenêtre.
    since=(suite_started.replace(microsecond=0)).isoformat(); until=(suite_ended.replace(microsecond=999999)).isoformat()
    remote=f"journalctl --utc --since {shlex.quote(since)} --until {shlex.quote(until)} -u ssh -o json --no-pager"
    journal_result=subprocess.run(["ssh","-T","-i",str(key),"-o","BatchMode=yes",f"{user}@{host}",remote],capture_output=True,timeout=30,check=False)
    if journal_result.returncode != 0:
        raise RuntimeError("Lecture journald de validation échouée")
    write_new_bytes(output_dir / "controller-observations.jsonl", _jsonl(observations))
    write_new_bytes(output_dir / "target-receipts.jsonl", _jsonl(receipts))
    write_new_bytes(output_dir / "ubuntu-journal.jsonl", journal_result.stdout)
    journal=[json.loads(x) for x in journal_result.stdout.splitlines() if x.strip()]

    trials=[]
    for receipt in receipts:
        pid=receipt["controller_pid"]; matched=[x for x in observations if x["pid"]==pid]
        tuples={(x["source_ip"],x["source_port"],x["target_ip"],x["target_port"]) for x in matched}
        target_tuple=_parse_tuple(receipt["target_receipt"]["ssh_connection"]) if receipt["target_receipt"] else None
        expected=(target_tuple["source_ip"],target_tuple["source_port"],target_tuple["target_ip"],target_tuple["target_port"]) if target_tuple else None
        correct=receipt["exit_code"]==0 and tuples=={expected}
        port=target_tuple["source_port"] if target_tuple else None
        journal_matches=[x for x in journal if port is not None and f"port {port}" in str(x.get("MESSAGE") or "")]
        trials.append({
            "trial_id": receipt["trial_id"], "controller_pid": pid, "target_tuple": target_tuple,
            "captured_tuples": [list(x) for x in sorted(tuples)], "observation_samples": len(matched),
            "journal_matches": len(journal_matches), "correct": correct,
            "missed": not matched, "incorrect": bool(matched) and not correct,
        })
    simultaneous=[x for x in trials if x["trial_id"].startswith("simultaneous-")]
    report={
        "schema_version":"alertgraph-socket-capture-validation/2.0-experimental",
        "created_at_utc":utc_now(), "partition":"development", "method":"persistent-psutil-net-connections-v1",
        "target":f"{host}:22", "trials":len(trials), "correct_captures":sum(x["correct"] for x in trials),
        "missed_captures":sum(x["missed"] for x in trials), "incorrect_captures":sum(x["incorrect"] for x in trials),
        "simultaneous_trials":len(simultaneous), "simultaneous_correct":sum(x["correct"] for x in simultaneous),
        "observer_cycles":cycle_reports, "trial_results":trials,
        "files":{}, "training_ready":False,
    }
    for name in ("controller-observations.jsonl","target-receipts.jsonl","ubuntu-journal.jsonl"):
        report["files"][name]={"sha256":sha256_file(output_dir/name),"bytes":(output_dir/name).stat().st_size}
    write_new_json(output_dir/"report.json",report); return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("output_dir",type=Path)
    parser.add_argument("--host",required=True);parser.add_argument("--user",required=True);parser.add_argument("--key",required=True,type=Path)
    args=parser.parse_args();print(json.dumps(run_validation(args.output_dir,host=args.host,user=args.user,key=args.key),ensure_ascii=False,indent=2))


if __name__=="__main__":main()
