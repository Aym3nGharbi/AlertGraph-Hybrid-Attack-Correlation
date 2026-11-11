#!/usr/bin/env python3
"""Audit reproductible du dataset public SOCBED ACSAC 2021 sans l'extraire."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


EXPECTED_ARCHIVE_BYTES = 77_984_817
EXPECTED_SHA256 = "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"

RUN_DIRECTORIES = (
    "host1_bestpractice",
    "host1_default",
    "host2_bestpractice",
    "host2_default",
)

# Ordre scientifique publié dans l'article ACSAC, pas une caractéristique ML.
ATTACK_STEP = {
    "misc_sqlmap": 1,
    "infect_email_exe": 2,  # l'ouverture de la pièce jointe devient l'étape 3
    "c2_take_screenshot": 4,
    "c2_mimikatz": 5,
    "c2_exfiltration": 6,
    "misc_download_malware": 7,
    "misc_set_autostart": 8,
    "misc_execute_malware": 9,
}

SIGMA_TRUE_POSITIVE_RULES = frozenset(
    {
        "Meterpreter or Cobalt Strike Getsystem Service Start",
        "Windows PowerShell Web Request",
        "Non Interactive PowerShell",
        "Direct Autorun Keys Modification",
        "Autorun Keys Modification",
    }
)

SIGMA_RULE_PHASE = {
    "Meterpreter or Cobalt Strike Getsystem Service Start": 5,
    "Windows PowerShell Web Request": 7,
    "Non Interactive PowerShell": 7,
    "Direct Autorun Keys Modification": 8,
    "Autorun Keys Modification": 8,
}

SURICATA_TRUE_POSITIVE_RULES = frozenset(
    {
        "ET SCAN Sqlmap SQL Injection Scan",
        "ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM",
        "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
        "ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt",
        "ET WEB_SERVER Attempt To Access MSSQL xp_cmdshell Stored Procedure Via URI",
        "ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access",
        "ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt",
        "ET WEB_SERVER SQL Injection Select Sleep Time Delay",
        "ET WEB_SERVER MYSQL Benchmark Command in URI to Consume Server Resources",
        "ET WEB_SERVER Possible Attempt to Get SQL Server Version in URI using SELECT VERSION",
        "ET WEB_SERVER Possible attempt to enumerate MS SQL Server version",
        "ET WEB_SERVER ATTACKER SQLi - SELECT and Schema Columns",
        "ET WEB_SERVER SQL Errors in HTTP 200 Response (error in your SQL syntax)",
        "ET INFO SUSPICIOUS SMTP EXE - EXE SMTP Attachment",
        "ET POLICY PE EXE or DLL Windows file download HTTP",
        "ET INFO Executable Retrieved With Minimal HTTP Headers - Potential Second Stage Download",
        "ET INFO SUSPICIOUS Dotted Quad Host MZ Response",
        "ET INFO EXE IsDebuggerPresent (Used in Malware Anti-Debugging)",
        "ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server)",
        "ET INFO Executable Download from dotted-quad Host",
    }
)

ATTACK_LOG_RE = re.compile(
    r'^(?P<timestamp>\S+) .*\[event="run_attack" attack="(?P<attack>[^"]+)"'
)
SURICATA_ALERT_RE = re.compile(
    r"^\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] "
    r"(?P<signature>.*?) \[Classification: (?P<classification>.*?)\] "
    r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>[^}]+)\} "
    r"(?P<src>\S+) -> (?P<dst>\S+)\s*$"
)


@dataclass(frozen=True)
class AttackStart:
    timestamp: datetime
    attack: str


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_attack_starts(lines) -> list[AttackStart]:
    starts = []
    for raw in lines:
        match = ATTACK_LOG_RE.match(raw)
        if match:
            starts.append(
                AttackStart(
                    datetime.fromisoformat(match.group("timestamp")),
                    match.group("attack"),
                )
            )
    return sorted(starts, key=lambda item: item.timestamp)


def sigma_true_positive(rule: str, event: dict) -> bool:
    """Reproduction exacte du prédicat publié par les auteurs de SOCBED."""

    if rule == "Meterpreter or Cobalt Strike Getsystem Service Start":
        return True
    command = event.get("process", {}).get("command_line", "")
    if rule in {"Windows PowerShell Web Request", "Non Interactive PowerShell"}:
        return "meterpreter_bind_tcp.exe" in command
    if rule == "Direct Autorun Keys Modification":
        return "Meterpreter Bind TCP" in command
    if rule == "Autorun Keys Modification":
        return event.get("registry", {}).get("value") == "Meterpreter Bind TCP"
    return False


def parse_suricata_alert(message: str) -> dict[str, object] | None:
    match = SURICATA_ALERT_RE.match(message)
    if not match:
        return None
    parsed = match.groupdict()
    parsed["priority"] = int(parsed["priority"])
    return parsed


def phase_for_timestamp(
    timestamp: datetime,
    starts: list[AttackStart],
    *,
    signature: str | None = None,
) -> int | None:
    """Attribue une alerte au dernier module lancé, au plus 3 minutes avant."""

    eligible = [item for item in starts if item.timestamp <= timestamp]
    if not eligible:
        return None
    latest = eligible[-1]
    if timestamp - latest.timestamp > timedelta(minutes=3):
        return None
    step = ATTACK_STEP.get(latest.attack)
    if step == 2 and signature != "ET INFO SUSPICIOUS SMTP EXE - EXE SMTP Attachment":
        return 3
    return step


def suricata_phase(
    timestamp: datetime, starts: list[AttackStart], signature: str
) -> int | None:
    """Applique le découpage publié, y compris les détections retardées."""

    if signature.startswith("ET WEB_SERVER ") or signature == "ET SCAN Sqlmap SQL Injection Scan":
        return 1
    if signature == "ET INFO SUSPICIOUS SMTP EXE - EXE SMTP Attachment":
        return 2

    eligible = [item for item in starts if item.timestamp <= timestamp]
    if eligible:
        latest = eligible[-1]
        # Le payload lancé à l'ouverture de la pièce jointe est détecté juste
        # après le lancement du module suivant. L'article l'attribue bien à
        # l'étape 3 (Table 2 et section 6.6), et non à la capture d'écran.
        if latest.attack in {"infect_email_exe", "c2_take_screenshot"}:
            return 3
        if latest.attack == "misc_download_malware":
            return 7

    # Les signatures non ambiguës fournissent un dernier recours auditable.
    if signature in {
        "ET INFO Executable Retrieved With Minimal HTTP Headers - Potential Second Stage Download",
        "ET INFO EXE IsDebuggerPresent (Used in Malware Anti-Debugging)",
        "ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server)",
    }:
        return 3
    if signature == "ET INFO Executable Download from dotted-quad Host":
        return 7
    return None


def _json_lines(archive: zipfile.ZipFile, name: str):
    with archive.open(name) as binary:
        for raw in binary:
            yield json.loads(raw)


def _text_lines(archive: zipfile.ZipFile, name: str):
    with archive.open(name) as binary:
        for raw in binary:
            yield raw.decode("utf-8", errors="replace").rstrip("\r\n")


def audit_run(archive: zipfile.ZipFile, directory: str, run_number: int) -> dict:
    suffix = f"{run_number:02d}"
    starts = parse_attack_starts(
        _text_lines(archive, f"{directory}/attackconsole_{suffix}.log")
    )
    counters = Counter()
    phases = Counter()
    signatures = Counter()
    tp_signatures = Counter()

    for wrapper in _json_lines(archive, f"{directory}/sigma_{suffix}.jsonl"):
        event = wrapper["event"]
        timestamp = datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00"))
        for rule in wrapper.get("rules", ()):
            counters["sigma_alerts"] += 1
            signatures[f"sigma:{rule}"] += 1
            if sigma_true_positive(rule, event):
                counters["sigma_true_positive"] += 1
                tp_signatures[f"sigma:{rule}"] += 1
                phase = SIGMA_RULE_PHASE[rule]
                phases[str(phase) if phase is not None else "unassigned"] += 1
            else:
                counters["sigma_non_attack"] += 1

    for event in _json_lines(archive, f"{directory}/syslog_{suffix}.jsonl"):
        if event.get("program") != "suricata":
            continue
        alert = parse_suricata_alert(event.get("message", ""))
        if alert is None:
            continue
        signature = str(alert["signature"])
        counters["suricata_alerts"] += 1
        signatures[f"suricata:{signature}"] += 1
        if signature in SURICATA_TRUE_POSITIVE_RULES:
            counters["suricata_true_positive"] += 1
            tp_signatures[f"suricata:{signature}"] += 1
            timestamp = datetime.fromisoformat(
                event["@timestamp"].replace("Z", "+00:00")
            )
            phase = suricata_phase(timestamp, starts, signature)
            phases[str(phase) if phase is not None else "unassigned"] += 1
        else:
            counters["suricata_non_attack"] += 1

    counters["all_alerts"] = counters["sigma_alerts"] + counters["suricata_alerts"]
    counters["true_positive"] = (
        counters["sigma_true_positive"] + counters["suricata_true_positive"]
    )
    counters["non_attack"] = (
        counters["sigma_non_attack"] + counters["suricata_non_attack"]
    )
    return {
        "run_id": f"{directory}:{suffix}",
        "directory": directory,
        "run_number": run_number,
        "attack_starts": [
            {"timestamp": item.timestamp.isoformat(), "attack": item.attack}
            for item in starts
        ],
        "counts": dict(counters),
        "true_positive_by_phase": dict(sorted(phases.items())),
        "signature_counts": dict(signatures.most_common()),
        "true_positive_signature_counts": dict(tp_signatures.most_common()),
    }


def audit_archive(path: Path) -> dict:
    archive_hash = sha256(path)
    if path.stat().st_size != EXPECTED_ARCHIVE_BYTES:
        raise ValueError("Taille de l'archive SOCBED inattendue")
    if archive_hash != EXPECTED_SHA256:
        raise ValueError("SHA-256 de l'archive SOCBED inattendu")

    with zipfile.ZipFile(path) as archive:
        bad_member = archive.testzip()
        if bad_member is not None:
            raise ValueError(f"Membre ZIP corrompu: {bad_member}")
        runs = [
            audit_run(archive, directory, run_number)
            for directory in RUN_DIRECTORIES
            for run_number in range(1, 11)
        ]

    totals = Counter()
    phase_totals = Counter()
    for run in runs:
        totals.update(run["counts"])
        phase_totals.update(run["true_positive_by_phase"])
    return {
        "dataset": "SOCBED evaluation dataset (ACSAC 2021)",
        "source": "https://github.com/fkie-cad/socbed-eval-acsac-2021",
        "archive": {
            "path": str(path),
            "bytes": path.stat().st_size,
            "sha256": archive_hash,
        },
        "label_policy": {
            "true_positive": "official count_tps predicates plus attackconsole timing",
            "non_attack": "IDS/Sigma alerts rejected by the official true-positive predicates",
            "phase": "official rule category plus attackconsole timing for duplicated payload rules",
            "email_exception": "SMTP alert is step 2; delayed payload alerts are step 3 as in the paper",
        },
        "run_count": len(runs),
        "totals": dict(totals),
        "true_positive_by_phase": dict(sorted(phase_totals.items())),
        "runs": runs,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = audit_archive(args.archive)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps({k: report[k] for k in ("run_count", "totals", "true_positive_by_phase")}, indent=2))


if __name__ == "__main__":
    main()
