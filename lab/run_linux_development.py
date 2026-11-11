#!/usr/bin/env python3
"""Exécute le scénario Linux contrôlé et journalise sa vérité d'activité."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(command: list[str], *, expected=(0,)) -> dict:
    started = now()
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    ended = now()
    if result.returncode not in expected:
        raise RuntimeError(
            f"Commande échouée ({result.returncode}): {' '.join(command)}\n{result.stderr}"
        )
    return {
        "started_at": started,
        "ended_at": ended,
        "exit_code": result.returncode,
    }


def ssh(key: Path, user: str, host: str, remote: str, *, expected=(0,)) -> dict:
    return run([
        "ssh", "-i", str(key), "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8", f"{user}@{host}", remote,
    ], expected=expected)


def execute(run_id: str, output: Path, host: str, user: str, key: Path) -> dict:
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", run_id):
        raise ValueError("run_id contient des caractères interdits")
    output.mkdir(parents=True, exist_ok=False)
    document = {
        "run_id": run_id,
        "partition": "development",
        "attack_instance_id": f"attack:{run_id}",
        "target_agent": "ubuntu-agent",
        "target_host": host,
        "started_at": now(),
        "steps": [],
    }

    def step(name: str, phase: str, action) -> None:
        item = {"name": name, "ground_truth_phase": phase, **action()}
        document["steps"].append(item)
        (output / "activity-truth.json").write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8"
        )

    ssh(key, user, host, f"logger -t wazuh-lab 'run={run_id} step=begin'")

    def failures():
        started = now()
        codes = []
        invalid_user = f"lab-{run_id}"[:31]
        for _ in range(5):
            result = subprocess.run([
                "ssh", "-i", str(key), "-o", "BatchMode=yes",
                "-o", "PreferredAuthentications=publickey",
                "-o", "ConnectTimeout=5", f"{invalid_user}@{host}", "true",
            ], capture_output=True, text=True, timeout=10)
            codes.append(result.returncode)
            time.sleep(0.6)
        return {"started_at": started, "ended_at": now(), "attempts": 5, "invalid_user": invalid_user, "exit_codes": codes}

    step("ssh-failed-authentication-burst", "initial_access", failures)
    step(
        "ssh-successful-login",
        "initial_access",
        lambda: ssh(key, user, host, f"logger -t wazuh-lab 'run={run_id} step=valid-login'; id >/dev/null"),
    )
    step(
        "privileged-command-attempt",
        "privilege_escalation",
        lambda: ssh(key, user, host, f"logger -t wazuh-lab 'run={run_id} step=sudo-attempt'; sudo -n id >/dev/null 2>&1", expected=(0, 1)),
    )
    canary = f"/opt/wazuh-lab/monitored/{run_id}.sh"
    step(
        "canary-create",
        "execution",
        lambda: ssh(key, user, host, f"umask 077; printf '#!/bin/sh\\nlogger -t wazuh-lab run={run_id}-executed\\n' > {canary}; chmod 700 {canary}; sleep 3"),
    )
    step(
        "canary-modify-and-execute",
        "execution",
        lambda: ssh(key, user, host, f"printf '# run={run_id}\\n' >> {canary}; {canary}; sleep 3"),
    )
    step(
        "canary-cleanup",
        "defense_evasion",
        lambda: ssh(key, user, host, f"rm -f -- {canary}; logger -t wazuh-lab 'run={run_id} step=cleanup'; sleep 3"),
    )
    document["ended_at"] = now()
    document["collection_not_before"] = datetime.now(timezone.utc).timestamp() + 20
    (output / "activity-truth.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--output-root", type=Path, default=Path("lab/runs"))
    parser.add_argument("--host", default="192.168.122.130")
    parser.add_argument("--user", default="labuser")
    parser.add_argument("--key", type=Path, default=Path.home() / ".ssh" / "wazuh_lab_ed25519")
    args = parser.parse_args()
    result = execute(args.run_id, args.output_root / args.run_id, args.host, args.user, args.key)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
