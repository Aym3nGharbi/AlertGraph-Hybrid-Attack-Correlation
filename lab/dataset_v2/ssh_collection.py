"""Transfert SSH V2 en lecture seule, avec injection de runner pour les tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from lab.collect_wazuh import instant

from .clock_audit import require_clock_ready
from .collect_campaign import collect_local_export
from .io_utils import sha256_file, utc_now, write_new_json
from .prepare_campaign import verify_campaign_reservation


WAZUH_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"


@dataclass(frozen=True)
class TransferResult:
    exit_code: int | None
    interrupted: bool
    stderr: bytes
    bytes_written: int


class SSHTransferRunner(Protocol):
    def transfer(
        self,
        *,
        host: str,
        user: str,
        key: Path,
        remote_path: str,
        destination: Path,
    ) -> TransferResult: ...


class SubprocessSSHRunner:
    """Runner réel. La commande distante statique est strictement en lecture."""

    def transfer(self, *, host, user, key, remote_path, destination) -> TransferResult:
        if remote_path != WAZUH_ALERTS_PATH:
            raise ValueError("Chemin distant non autorisé")
        command = [
            "ssh",
            "-i",
            str(key),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            f"{user}@{host}",
            "cat",
            "--",
            remote_path,
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        written = 0
        interrupted = False
        try:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(descriptor, "wb") as output:
                assert process.stdout is not None
                while True:
                    block = process.stdout.read(1024 * 1024)
                    if not block:
                        break
                    output.write(block)
                    written += len(block)
                output.flush()
                os.fsync(output.fileno())
            stderr = process.stderr.read() if process.stderr else b""
            exit_code = process.wait()
        except KeyboardInterrupt:
            interrupted = True
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            stderr = process.stderr.read() if process.stderr else b""
            exit_code = process.returncode
        return TransferResult(exit_code, interrupted, stderr, written)


def _attempt_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"ssh-{stamp}-{uuid.uuid4().hex[:8]}"


def _failure_document(
    campaign: dict[str, object],
    attempt_id: str,
    result: TransferResult,
    partial: Path,
    reason: str,
) -> dict[str, object]:
    stderr_hash = hashlib.sha256(result.stderr).hexdigest()
    return {
        "schema_version": "alertgraph-ssh-collection-failure/2.0",
        "campaign_id": campaign["campaign_id"],
        "run_id": campaign["run_id"],
        "attempt_id": attempt_id,
        "created_at_utc": utc_now(),
        "source_role": "wazuh-manager",
        "remote_resource": "alerts-json",
        "reason": reason,
        "exit_code": result.exit_code,
        "interrupted": result.interrupted,
        "partial_bytes": partial.stat().st_size if partial.exists() else 0,
        "partial_sha256": sha256_file(partial) if partial.exists() else None,
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": stderr_hash,
        "contains_connection_identifiers": False,
    }


def collect_ssh_campaign(
    campaign_dir: str | Path,
    *,
    host: str,
    user: str,
    key: str | Path,
    since: float,
    until: float,
    agents: set[str],
    runner: SSHTransferRunner,
    allow_remote_read: bool,
) -> dict[str, object]:
    """Lit le manager par SSH sans inscrire user, clé ou commande au manifeste."""

    if not allow_remote_read:
        raise PermissionError("La lecture SSH exige --allow-remote-read")
    campaign_dir = Path(campaign_dir)
    campaign = verify_campaign_reservation(campaign_dir)
    if campaign["partition"] == "final-test":
        raise PermissionError("La collecte final-test reste verrouillée")
    require_clock_ready(campaign_dir)
    if (campaign_dir / "raw").exists():
        raise FileExistsError("Une collecte finalisée existe déjà")

    attempt_id = _attempt_id()
    attempt_dir = campaign_dir / "collection-attempts" / attempt_id
    attempt_dir.mkdir(parents=True, exist_ok=False)
    partial = attempt_dir / "manager-alerts.jsonl.part"
    try:
        result = runner.transfer(
            host=host,
            user=user,
            key=Path(key),
            remote_path=WAZUH_ALERTS_PATH,
            destination=partial,
        )
    except Exception as exc:
        if not partial.exists():
            partial.write_bytes(b"")
        synthetic = TransferResult(None, False, b"", partial.stat().st_size)
        failure = _failure_document(
            campaign, attempt_id, synthetic, partial, f"runner-exception:{type(exc).__name__}"
        )
        partial.replace(attempt_dir / "manager-alerts.jsonl.incomplete")
        write_new_json(attempt_dir / "failure.json", failure)
        raise RuntimeError(f"Échec du runner SSH: {type(exc).__name__}") from exc

    if not partial.exists() or partial.stat().st_size != result.bytes_written:
        if not partial.exists():
            partial.write_bytes(b"")
        failure = _failure_document(
            campaign, attempt_id, result, partial, "transfer-accounting-mismatch"
        )
        partial.replace(attempt_dir / "manager-alerts.jsonl.incomplete")
        write_new_json(attempt_dir / "failure.json", failure)
        raise RuntimeError("Collecte SSH incomplète: transfer-accounting-mismatch")

    if result.interrupted or result.exit_code != 0:
        reason = "interrupted" if result.interrupted else "ssh-nonzero-exit"
        failure = _failure_document(campaign, attempt_id, result, partial, reason)
        incomplete = attempt_dir / "manager-alerts.jsonl.incomplete"
        partial.replace(incomplete)
        write_new_json(attempt_dir / "failure.json", failure)
        raise RuntimeError(f"Collecte SSH incomplète: {reason}")

    snapshot = attempt_dir / "manager-alerts.jsonl.complete"
    partial.replace(snapshot)
    transfer_manifest = {
        "schema_version": "alertgraph-ssh-transfer/2.0",
        "campaign_id": campaign["campaign_id"],
        "run_id": campaign["run_id"],
        "attempt_id": attempt_id,
        "created_at_utc": utc_now(),
        "source_role": "wazuh-manager",
        "remote_resource": "alerts-json",
        "exit_code": result.exit_code,
        "interrupted": False,
        "bytes": snapshot.stat().st_size,
        "sha256": sha256_file(snapshot),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "contains_connection_identifiers": False,
    }
    write_new_json(attempt_dir / "transfer-manifest.json", transfer_manifest)
    try:
        collection = collect_local_export(
            campaign_dir,
            snapshot,
            since=since,
            until=until,
            agents=agents,
            dry_run=True,
            source_label="wazuh-manager:alerts-json:read-only-ssh",
        )
    except Exception as exc:
        write_new_json(
            attempt_dir / "processing-failure.json",
            {
                "schema_version": "alertgraph-ssh-processing-failure/2.0",
                "campaign_id": campaign["campaign_id"],
                "run_id": campaign["run_id"],
                "attempt_id": attempt_id,
                "created_at_utc": utc_now(),
                "reason": f"processing-failed:{type(exc).__name__}",
                "source_sha256": transfer_manifest["sha256"],
            },
        )
        raise
    return {"attempt": transfer_manifest, "collection": collection}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--since", required=True, type=instant)
    parser.add_argument("--until", required=True, type=instant)
    parser.add_argument("--agents", default="")
    parser.add_argument("--allow-remote-read", action="store_true", required=True)
    args = parser.parse_args()
    report = collect_ssh_campaign(
        args.campaign_dir,
        host=args.host,
        user=args.user,
        key=args.key,
        since=args.since,
        until=args.until,
        agents={value.strip() for value in args.agents.split(",") if value.strip()},
        runner=SubprocessSSHRunner(),
        allow_remote_read=args.allow_remote_read,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
