"""Produit des réponses d'horloge par commandes locales/SSH en lecture seule.

Ce module est destiné au pré-vol réel. Il n'est jamais appelé par les tests
sans un runner mocké. Le JSON produit ne contient ni utilisateur ni chemin de
clé SSH.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import platform
import subprocess
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .io_utils import write_new_json


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    def run(self, command: list[str]) -> CommandResult: ...


class SubprocessCommandRunner:
    def run(self, command: list[str]) -> CommandResult:
        result = subprocess.run(command, capture_output=True, timeout=20)
        return CommandResult(result.returncode, result.stdout, result.stderr)

    def measure_persistent_clock(
        self, command: list[str], sample_count: int,
    ) -> list[dict[str, object]]:
        """Chronomètre des échanges sur un canal SSH déjà établi."""

        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        ready = process.stdout.readline().strip()
        if ready != b"READY":
            stderr = process.stderr.read() if process.stderr else b""
            process.kill(); process.wait()
            raise RuntimeError(
                "Le canal d'horloge SSH n'est pas prêt: "
                + hashlib.sha256(stderr).hexdigest()
            )
        samples: list[dict[str, object]] = []
        try:
            for index in range(sample_count):
                started = time.time()
                process.stdin.write(b"sample\n"); process.stdin.flush()
                answer = process.stdout.readline().strip()
                ended = time.time()
                try:
                    remote_epoch = int(answer) / 1_000_000_000
                except ValueError as exc:
                    raise ValueError(f"Réponse persistante invalide à l'échantillon {index}") from exc
                midpoint = (started + ended) / 2.0
                samples.append({
                    "sample_index": index,
                    "request_started_at_utc": _iso(started),
                    "request_ended_at_utc": _iso(ended),
                    "remote_time_utc": _iso(remote_epoch),
                    "rtt_ms": (ended - started) * 1000.0,
                    "offset_ms": (remote_epoch - midpoint) * 1000.0,
                    "uncertainty_ms": (ended - started) * 500.0,
                })
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        if process.returncode != 0:
            raise RuntimeError("Le canal d'horloge SSH s'est terminé en erreur")
        return samples


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _windows_console_text(data: bytes) -> str:
    """Décode la sortie OEM localisée de ``w32tm`` et retire les accents."""

    try:
        code_page = ctypes.windll.kernel32.GetOEMCP()
        decoded = data.decode(f"cp{code_page}", errors="replace")
    except (AttributeError, LookupError):
        decoded = data.decode(errors="replace")
    normalized = unicodedata.normalize("NFKD", decoded)
    return normalized.encode("ascii", errors="ignore").decode().casefold()


def measure_controller(runner: CommandRunner) -> dict[str, object]:
    started = time.time()
    remote = time.time()
    if platform.system() == "Windows":
        status = runner.run(["w32tm", "/query", "/status"])
        text = _windows_console_text(status.stdout + status.stderr)
        negative = any(
            marker in text
            for marker in ("unsynchronized", "not synchronized", "non synchronise")
        )
        synchronized = status.returncode == 0 and not negative
        source = "controller:w32tm-status"
    else:
        status = runner.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        synchronized = status.returncode == 0 and status.stdout.strip().lower() == b"yes"
        source = "controller:timedatectl"
    ended = time.time()
    return {
        "request_started_at_utc": _iso(started),
        "request_ended_at_utc": _iso(ended),
        "remote_time_utc": _iso(remote),
        "synchronized": synchronized,
        "sync_source": source,
    }


def measure_unix_ssh(
    *,
    role: str,
    host: str,
    user: str,
    key: Path,
    runner: CommandRunner,
    sample_count: int = 5,
) -> tuple[str, dict[str, object]]:
    if not 3 <= sample_count <= 15:
        raise ValueError("sample_count doit être compris entre 3 et 15")
    base = [
        "ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        f"{user}@{host}",
    ]
    persistent = base + [
        "python3 -u -c 'import sys,time; print(\"READY\",flush=True); "
        "[print(time.time_ns(),flush=True) for _ in iter(sys.stdin.readline,\"\")]'"
    ]
    if hasattr(runner, "measure_persistent_clock"):
        samples = runner.measure_persistent_clock(persistent, sample_count)  # type: ignore[attr-defined]
    else:
        samples = []
        for index in range(sample_count):
            started = time.time()
            clock = runner.run(
                base
                # OpenSSH joins every argument after the destination into one
                # remote command. Keep the expression quoted for its shell.
                + ["python3 -c 'import time; print(time.time_ns())'"]
            )
            ended = time.time()
            if clock.returncode != 0:
                raise RuntimeError(f"Échec de la lecture d'horloge {role} échantillon {index}")
            try:
                remote_epoch = int(clock.stdout.strip()) / 1_000_000_000
            except ValueError as exc:
                raise ValueError(f"Réponse d'horloge invalide pour {role} échantillon {index}") from exc
            midpoint = (started + ended) / 2.0
            samples.append({
                "sample_index": index,
                "request_started_at_utc": _iso(started),
                "request_ended_at_utc": _iso(ended),
                "remote_time_utc": _iso(remote_epoch),
                "rtt_ms": (ended - started) * 1000.0,
                "offset_ms": (remote_epoch - midpoint) * 1000.0,
                "uncertainty_ms": (ended - started) * 500.0,
            })
    sync = runner.run(base + ["timedatectl show -p NTPSynchronized --value"])
    synchronized = sync.returncode == 0 and sync.stdout.strip().lower() == b"yes"
    selected = min(samples, key=lambda item: (float(item["rtt_ms"]), int(item["sample_index"])))
    return role, {
        "request_started_at_utc": selected["request_started_at_utc"],
        "request_ended_at_utc": selected["request_ended_at_utc"],
        "remote_time_utc": selected["remote_time_utc"],
        "synchronized": synchronized,
        "sync_source": "ssh-multiplexed-min-rtt+python-time+timedatectl",
        "selection_policy": "minimum-rtt-then-sample-index-independent-of-offset",
        "selected_sample_index": selected["sample_index"],
        "samples": samples,
    }


def build_readonly_responses(
    *,
    manager_host: str,
    manager_user: str,
    manager_key: Path,
    ubuntu_host: str,
    ubuntu_user: str,
    ubuntu_key: Path,
    windows_response: Path,
    runner: CommandRunner,
) -> dict[str, object]:
    windows = json.loads(windows_response.read_text(encoding="utf-8-sig"))
    if "windows-target" not in windows:
        raise ValueError("La réponse Windows doit contenir windows-target")
    responses = {"controller": measure_controller(runner)}
    for role, value in (
        measure_unix_ssh(
            role="wazuh-manager", host=manager_host, user=manager_user,
            key=manager_key, runner=runner,
        ),
        measure_unix_ssh(
            role="linux-target", host=ubuntu_host, user=ubuntu_user,
            key=ubuntu_key, runner=runner,
        ),
    ):
        responses[role] = value
    responses["windows-target"] = windows["windows-target"]
    return responses


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manager-host", required=True)
    parser.add_argument("--manager-user", required=True)
    parser.add_argument("--manager-key", required=True, type=Path)
    parser.add_argument("--ubuntu-host", required=True)
    parser.add_argument("--ubuntu-user", required=True)
    parser.add_argument("--ubuntu-key", required=True, type=Path)
    parser.add_argument("--windows-response", required=True, type=Path)
    args = parser.parse_args()
    responses = build_readonly_responses(
        manager_host=args.manager_host,
        manager_user=args.manager_user,
        manager_key=args.manager_key,
        ubuntu_host=args.ubuntu_host,
        ubuntu_user=args.ubuntu_user,
        ubuntu_key=args.ubuntu_key,
        windows_response=args.windows_response,
        runner=SubprocessCommandRunner(),
    )
    write_new_json(args.output, responses)
    print(json.dumps({"output": str(args.output), "roles": sorted(responses)}, indent=2))


if __name__ == "__main__":
    main()
