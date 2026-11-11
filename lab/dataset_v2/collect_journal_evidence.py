"""Capture en lecture seule une chaîne journald bornée pour une preuve V2."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from .io_utils import sha256_bytes, utc_now, write_new_bytes, write_new_json
from .prepare_campaign import verify_campaign_reservation


PID = re.compile(r"^[1-9][0-9]{0,9}$")


def collect_journal_pid(
    campaign_dir: str | Path,
    *, host: str,
    user: str,
    key: str | Path,
    pid: str,
    since: str,
    until: str,
    allow_remote_read: bool = False,
) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("La preuve journald pilote exige development")
    if not allow_remote_read:
        raise PermissionError("Confirmer explicitement la lecture distante")
    if not PID.fullmatch(pid):
        raise ValueError("PID journald invalide")
    output_dir = campaign_dir / "supplementary"
    output = output_dir / f"linux-journal-pid-{pid}.jsonl"
    evidence_manifest = output_dir / f"linux-journal-pid-{pid}-manifest.json"
    if output.exists() or evidence_manifest.exists():
        raise FileExistsError("La preuve journald existe déjà")
    remote = (
        "journalctl --utc --since " + repr(since) + " --until " + repr(until)
        + f" -o json _PID={pid} --no-pager"
    )
    completed = subprocess.run(
        ["ssh", "-T", "-i", str(Path(key)), "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", f"{user}@{host}", remote],
        capture_output=True, timeout=30, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("La lecture journald distante a échoué")
    lines = completed.stdout.splitlines(keepends=True)
    entries = []
    for line in lines:
        item = json.loads(line)
        if str(item.get("_PID")) != pid:
            raise ValueError("Entrée journald hors PID demandé")
        entries.append(item)
    if not entries:
        raise ValueError("Aucune entrée journald trouvée")
    write_new_bytes(output, completed.stdout)
    report = {
        "schema_version": "alertgraph-supplementary-journal/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "created_at_utc": utc_now(), "source": "target-journald:read-only-ssh",
        "pid": pid, "since_utc": since, "until_utc": until,
        "entries": len(entries), "bytes": len(completed.stdout),
        "sha256": sha256_bytes(completed.stdout),
        "contains_connection_identifiers": False,
    }
    write_new_json(evidence_manifest, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--host", required=True); parser.add_argument("--user", required=True)
    parser.add_argument("--key", required=True, type=Path); parser.add_argument("--pid", required=True)
    parser.add_argument("--since", required=True); parser.add_argument("--until", required=True)
    parser.add_argument("--allow-remote-read", action="store_true")
    args = parser.parse_args()
    print(json.dumps(collect_journal_pid(
        args.campaign_dir, host=args.host, user=args.user, key=args.key,
        pid=args.pid, since=args.since, until=args.until,
        allow_remote_read=args.allow_remote_read,
    ), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
