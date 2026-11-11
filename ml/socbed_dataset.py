"""Adaptateur canonique du dataset public SOCBED ACSAC 2021."""

from __future__ import annotations

import json
import re
import zipfile
from datetime import datetime
from pathlib import Path

from ait_dataset import CanonicalAlertRecord
from ait_labels import LabelDecision
from audit_socbed import (
    RUN_DIRECTORIES,
    SIGMA_RULE_PHASE,
    SURICATA_TRUE_POSITIVE_RULES,
    parse_attack_starts,
    parse_suricata_alert,
    sigma_true_positive,
    suricata_phase,
)


SOCBED_RUNS = tuple(
    f"{directory}_{run_number:02d}"
    for directory in RUN_DIRECTORIES
    for run_number in range(1, 11)
)

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def member_names(run_id: str) -> tuple[str, str, str]:
    directory, run_number = run_id.rsplit("_", 1)
    return (
        f"{directory}/attackconsole_{run_number}.log",
        f"{directory}/sigma_{run_number}.jsonl",
        f"{directory}/syslog_{run_number}.jsonl",
    )


def _ground_truth(run_id: str, phase: int | None, is_attack: bool) -> LabelDecision:
    selected = f"step_{phase}" if phase is not None else None
    return LabelDecision(
        scenario_id=run_id,
        time_phase=None,
        event_phase=selected,
        selected_phase=selected,
        attack_family="socbed-espionage" if is_attack else None,
        attack_instance_id=f"socbed:{run_id}" if is_attack else None,
        is_attack=is_attack,
        label_source="official-predicate",
        label_confidence="high",
        label_conflict=False,
        raw_time_label="",
        raw_event_label=selected or "false-positive",
    )


def _entities(*values: str | None) -> tuple[str, ...]:
    return tuple(sorted({value.casefold() for value in values if value}))


def _endpoint(value: str) -> tuple[str, int | None]:
    if value.startswith("[") and "]:" in value:
        address, port = value[1:].rsplit("]:", 1)
    elif value.count(":") == 1:
        address, port = value.rsplit(":", 1)
    else:
        return value, None
    try:
        return address, int(port)
    except ValueError:
        return value, None


def observed_stage(sensor: str, signature: str) -> str | None:
    """Mapping sémantique fixe basé uniquement sur le nom observable de règle."""

    if sensor == "sigma":
        if signature == "Meterpreter or Cobalt Strike Getsystem Service Start":
            return "USER_PRIV_ESC"
        if signature in {"Windows PowerShell Web Request", "Non Interactive PowerShell"}:
            return "COMMAND_AND_CONTROL"
        if signature in {"Direct Autorun Keys Modification", "Autorun Keys Modification"}:
            return "DEFENSE_EVASION"
        return None
    if signature.startswith("ET WEB_SERVER ") or signature == "ET SCAN Sqlmap SQL Injection Scan":
        return "PUBLIC_APP_EXP"
    if signature == "ET INFO SUSPICIOUS SMTP EXE - EXE SMTP Attachment":
        return "SERVICE_SPECIFIC"
    if signature in SURICATA_TRUE_POSITIVE_RULES:
        if "Download" in signature or "download" in signature:
            return "COMMAND_AND_CONTROL"
        return "ARBITRARY_CODE_EXE"
    return None


def _sigma_records(archive: zipfile.ZipFile, run_id: str, member: str, starts):
    sequence = 0
    with archive.open(member) as stream:
        for raw in stream:
            wrapper = json.loads(raw)
            event = wrapper["event"]
            timestamp = datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00"))
            host = event.get("host", {}).get("name")
            agent_host = event.get("agent", {}).get("hostname")
            for rule in wrapper.get("rules", ()):
                sequence += 1
                is_attack = sigma_true_positive(rule, event)
                phase = SIGMA_RULE_PHASE[rule] if is_attack else None
                yield CanonicalAlertRecord(
                    alert_id=f"{run_id}:sigma:{sequence}",
                    source_id=event.get("pre_detection_id"),
                    timestamp=timestamp.timestamp(),
                    sensor="sigma",
                    host=host or agent_host,
                    sensor_ip=None,
                    src_ip=None,
                    src_port=None,
                    dst_ip=None,
                    dst_port=None,
                    protocol=None,
                    service=None,
                    signature_id=rule,
                    signature_text=rule,
                    severity=None,
                    observed_tactics=(),
                    observed_stage=observed_stage("sigma", rule),
                    entities=_entities(
                        f"host:{host}" if host else None,
                        f"host:{agent_host}" if agent_host else None,
                    ),
                    ground_truth=_ground_truth(run_id, phase, is_attack),
                )


def _suricata_records(archive: zipfile.ZipFile, run_id: str, member: str, starts):
    sequence = 0
    with archive.open(member) as stream:
        for raw in stream:
            event = json.loads(raw)
            if event.get("program") != "suricata":
                continue
            alert = parse_suricata_alert(event.get("message", ""))
            if alert is None:
                continue
            sequence += 1
            signature = str(alert["signature"])
            timestamp = datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00"))
            src_ip, src_port = _endpoint(str(alert["src"]))
            dst_ip, dst_port = _endpoint(str(alert["dst"]))
            is_attack = signature in SURICATA_TRUE_POSITIVE_RULES
            phase = suricata_phase(timestamp, starts, signature) if is_attack else None
            host = event.get("logsource") or event.get("host")
            yield CanonicalAlertRecord(
                alert_id=f"{run_id}:suricata:{sequence}",
                source_id=f"{alert['gid']}:{alert['sid']}:{alert['rev']}",
                timestamp=timestamp.timestamp(),
                sensor="suricata",
                host=str(host) if host else None,
                sensor_ip=str(event.get("host")) if event.get("host") else None,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=str(alert["protocol"]).casefold(),
                service=None,
                signature_id=str(alert["sid"]),
                signature_text=signature,
                severity=int(alert["priority"]),
                observed_tactics=(),
                observed_stage=observed_stage("suricata", signature),
                entities=_entities(
                    f"host:{host}" if host else None,
                    f"ip:{event.get('host')}" if event.get("host") else None,
                    f"ip:{src_ip}",
                    f"ip:{dst_ip}",
                ),
                ground_truth=_ground_truth(run_id, phase, is_attack),
            )


def iter_socbed_run(archive_path: str | Path, run_id: str):
    if run_id not in SOCBED_RUNS:
        raise ValueError(f"Run SOCBED inconnu: {run_id}")
    attack_member, sigma_member, syslog_member = member_names(run_id)
    with zipfile.ZipFile(archive_path) as archive:
        with archive.open(attack_member) as stream:
            starts = parse_attack_starts(
                raw.decode("utf-8", errors="replace").rstrip("\r\n")
                for raw in stream
            )
        records = [
            *_sigma_records(archive, run_id, sigma_member, starts),
            *_suricata_records(archive, run_id, syslog_member, starts),
        ]
    yield from sorted(records, key=lambda item: (item.timestamp, item.alert_id))
