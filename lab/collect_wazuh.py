#!/usr/bin/env python3
"""Exporte un intervalle de alerts.json via une clé SSH, sans secret stocké."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def instant(value: str) -> float:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("Le timestamp doit inclure un fuseau")
    return parsed.timestamp()


def alert_timestamp(raw: dict) -> float:
    return instant(str(raw["timestamp"]))


def collect(
    host: str,
    user: str,
    key: Path,
    destination: Path,
    *,
    since: float,
    until: float,
    agents: set[str],
) -> dict:
    if until < since:
        raise ValueError("until doit être postérieur à since")
    command = [
        "ssh", "-i", str(key), "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10", f"{user}@{host}",
        "cat /var/ossec/logs/alerts/alerts.json",
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    read = written = malformed = 0
    with temporary.open("w", encoding="utf-8", newline="\n") as target:
        assert process.stdout is not None
        for line in process.stdout:
            read += 1
            try:
                raw = json.loads(line)
                timestamp = alert_timestamp(raw)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                malformed += 1
                continue
            agent = str(raw.get("agent", {}).get("name", ""))
            if since <= timestamp <= until and (not agents or agent in agents):
                target.write(json.dumps(raw, ensure_ascii=False, separators=(",", ":")) + "\n")
                written += 1
    stderr = process.stderr.read() if process.stderr else ""
    return_code = process.wait()
    if return_code:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"Échec SSH ({return_code}): {stderr.strip()}")
    temporary.replace(destination)
    return {
        "source": f"{user}@{host}:/var/ossec/logs/alerts/alerts.json",
        "destination": str(destination),
        "since": datetime.fromtimestamp(since, timezone.utc).isoformat(),
        "until": datetime.fromtimestamp(until, timezone.utc).isoformat(),
        "agent_filter": sorted(agents),
        "lines_read": read,
        "alerts_written": written,
        "malformed_lines": malformed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--host", default="192.168.122.129")
    parser.add_argument("--user", default="labuser")
    parser.add_argument(
        "--key", type=Path,
        default=Path.home() / ".ssh" / "wazuh_lab_ed25519",
    )
    parser.add_argument("--since", required=True, type=instant)
    parser.add_argument("--until", required=True, type=instant)
    parser.add_argument("--agents", default="")
    args = parser.parse_args()
    agents = {item.strip() for item in args.agents.split(",") if item.strip()}
    print(json.dumps(collect(args.host, args.user, args.key, args.destination, since=args.since, until=args.until, agents=agents), indent=2))


if __name__ == "__main__":
    main()
