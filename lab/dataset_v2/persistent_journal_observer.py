"""Observateur journald persistant pour une fenêtre expérimentale V2.

Le canal SSH doit être ouvert avant la fenêtre et rester unique. Ce module
construit la commande et conserve les octets journald reçus ; il ne démarre
jamais une VM et n'attribue aucun label.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import BinaryIO

from .io_utils import utc_now, write_new_json
from .boot_id import canonical_boot_id


REQUIRED_JOURNAL_FIELDS = {
    "__CURSOR", "__REALTIME_TIMESTAMP", "_BOOT_ID", "_PID", "MESSAGE"
}


def build_ssh_journal_argv(
    host: str, user: str, *, ssh_executable: str = "ssh",
    identity_file: str | None = None, duration_seconds: int = 40,
) -> list[str]:
    """Retourne une commande SSH non interactive, sans secret dans argv."""

    if not host or not user:
        raise ValueError("host et user sont obligatoires")
    if duration_seconds < 10 or duration_seconds > 300:
        raise ValueError("duration_seconds doit être compris entre 10 et 300")
    argv = [
        ssh_executable,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
    ]
    if identity_file:
        argv.extend(["-i", identity_file])
    journal = "journalctl --since '10 seconds ago' --follow --output=json --no-pager _COMM=sshd"
    remote = (
        "journalctl --no-pager -n 0 _COMM=sshd >/dev/null && "
        "printf 'ALERTGRAPH_JOURNAL_READY\\n' >&2 && "
        f"timeout --signal=TERM {duration_seconds}s {journal}; "
        "rc=$?; [ \"$rc\" -eq 124 ] && exit 0; exit \"$rc\""
    )
    argv.extend([f"{user}@{host}", "sh", "-lc", shlex.quote(remote)])
    return argv


def validate_journal_record(record: object) -> list[str]:
    if not isinstance(record, dict):
        return ["not-an-object"]
    missing = sorted(REQUIRED_JOURNAL_FIELDS - set(record))
    errors = [f"missing:{name}" for name in missing]
    try:
        canonical_boot_id(record.get("_BOOT_ID"))
    except ValueError:
        errors.append("invalid-boot-id-uuid")
    if record.get("_COMM") not in {None, "sshd"}:
        errors.append("unexpected-comm")
    for name in ("__REALTIME_TIMESTAMP", "_PID"):
        value = str(record.get(name, ""))
        if value and not value.isdigit():
            errors.append(f"invalid-integer:{name}")
    return errors


class JournalStreamRecorder:
    """Écrit un flux brut append-only puis le scelle atomiquement."""

    def __init__(self, output_dir: str | Path, observer_id: str):
        self.output_dir = Path(output_dir)
        self.observer_id = observer_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.partial_path = self.output_dir / f"{observer_id}.jsonl.partial"
        self.raw_path = self.output_dir / f"{observer_id}.jsonl"
        self.manifest_path = self.output_dir / f"{observer_id}-manifest.json"
        for path in (self.partial_path, self.raw_path, self.manifest_path):
            if path.exists():
                raise FileExistsError(f"artefact observateur déjà présent: {path}")
        self._stream: BinaryIO = self.partial_path.open("xb")
        self._hash = hashlib.sha256()
        self._line_count = 0
        self._valid_count = 0
        self._invalid: list[dict[str, object]] = []
        self._cursors: set[str] = set()
        self._duplicate_cursors: set[str] = set()
        self._boot_ids: set[str] = set()
        self._pids: set[str] = set()
        self._first_realtime: int | None = None
        self._last_realtime: int | None = None
        self.started_at_utc = utc_now()
        self.closed = False

    def feed(self, raw_line: bytes) -> None:
        if self.closed:
            raise RuntimeError("observateur déjà fermé")
        if not raw_line.endswith(b"\n"):
            raise ValueError("chaque observation doit conserver son délimiteur LF")
        self._stream.write(raw_line); self._stream.flush(); os.fsync(self._stream.fileno())
        self._hash.update(raw_line); self._line_count += 1
        try:
            record = json.loads(raw_line)
            errors = validate_journal_record(record)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            record = None; errors = [f"invalid-json:{type(exc).__name__}"]
        if errors:
            self._invalid.append({"line": self._line_count, "errors": errors})
            return
        assert isinstance(record, dict)
        self._valid_count += 1
        cursor = str(record["__CURSOR"])
        if cursor in self._cursors:
            self._duplicate_cursors.add(cursor)
        self._cursors.add(cursor)
        self._boot_ids.add(str(record["_BOOT_ID"])); self._pids.add(str(record["_PID"]))
        realtime = int(record["__REALTIME_TIMESTAMP"])
        self._first_realtime = realtime if self._first_realtime is None else min(self._first_realtime, realtime)
        self._last_realtime = realtime if self._last_realtime is None else max(self._last_realtime, realtime)

    def close(self, *, process_exit_code: int, interrupted: bool = False) -> dict[str, object]:
        if self.closed:
            raise RuntimeError("observateur déjà fermé")
        self._stream.flush(); os.fsync(self._stream.fileno()); self._stream.close()
        self.partial_path.replace(self.raw_path)
        self.closed = True
        manifest = {
            "schema_version": "alertgraph-persistent-journal-observer/2.0-experimental",
            "observer_id": self.observer_id,
            "started_at_utc": self.started_at_utc,
            "ended_at_utc": utc_now(),
            "mode": "persistent-preopened-journal-stream",
            "raw_file": self.raw_path.name,
            "raw_sha256": self._hash.hexdigest(),
            "raw_bytes": self.raw_path.stat().st_size,
            "line_count": self._line_count,
            "valid_record_count": self._valid_count,
            "invalid_records": self._invalid,
            "duplicate_cursors": sorted(self._duplicate_cursors),
            "boot_ids": sorted(self._boot_ids),
            "sshd_pids": sorted(self._pids),
            "first_realtime_timestamp_us": self._first_realtime,
            "last_realtime_timestamp_us": self._last_realtime,
            "process_exit_code": process_exit_code,
            "interrupted": interrupted,
            "complete": (
                process_exit_code == 0
                and not interrupted
                and not self._invalid
                and not self._duplicate_cursors
            ),
            "labels_emitted": 0,
            "training_ready": False,
        }
        write_new_json(self.manifest_path, manifest)
        return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host"); parser.add_argument("user")
    parser.add_argument("--identity-file")
    parser.add_argument("--duration-seconds", type=int, default=40)
    args = parser.parse_args()
    print(json.dumps(build_ssh_journal_argv(
        args.host, args.user, identity_file=args.identity_file,
        duration_seconds=args.duration_seconds,
    ), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
