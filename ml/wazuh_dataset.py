"""Adaptateur Wazuh vers le schéma observable utilisé par le modèle hybride."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from ait_dataset import CanonicalAlertRecord
from ait_labels import LabelDecision


@dataclass(frozen=True)
class StageMapping:
    rule_to_stage: Mapping[str, str]
    technique_to_stage: Mapping[str, str]
    group_to_stage: Mapping[str, str]
    precedence: tuple[str, ...]


def load_stage_mapping(path: str | Path) -> StageMapping:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if raw.get("policy") != "unknown-is-neutral":
        raise ValueError("Le mapping Wazuh doit déclarer unknown-is-neutral")
    precedence = tuple(raw.get("precedence", ("rule", "technique", "group")))
    if set(precedence) != {"rule", "technique", "group"}:
        raise ValueError("La précédence doit contenir rule, technique et group")
    return StageMapping(
        rule_to_stage={str(k): str(v) for k, v in raw.get("rule_to_stage", {}).items()},
        technique_to_stage={
            str(k).upper(): str(v)
            for k, v in raw.get("technique_to_stage", {}).items()
        },
        group_to_stage={
            str(k).casefold(): str(v)
            for k, v in raw.get("group_to_stage", {}).items()
        },
        precedence=precedence,
    )


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _texts(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        values = ()
    return tuple(
        sorted(
            {
                str(item).strip()
                for item in values
                if item is not None and str(item).strip()
            }
        )
    )


def _text(value: object) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _integer(value: object) -> int | None:
    try:
        return int(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


def parse_wazuh_timestamp(value: object) -> float:
    text = str(value or "").strip()
    if not text:
        raise ValueError("Alerte Wazuh sans timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("Le timestamp Wazuh doit inclure un fuseau")
    return parsed.timestamp()


def observed_stage(raw: Mapping[str, object], mapping: StageMapping) -> str | None:
    """Retourne une étape observable; l'absence de mapping reste ``None``."""

    rule = _mapping(raw.get("rule"))
    mitre = _mapping(rule.get("mitre"))
    techniques = []
    for item in _texts(mitre.get("id")):
        technique = item.upper()
        techniques.append(technique)
        if "." in technique:
            techniques.append(technique.split(".", 1)[0])
    candidates = {
        "rule": tuple(filter(None, (_text(rule.get("id")),))),
        "technique": tuple(dict.fromkeys(techniques)),
        "group": tuple(item.casefold() for item in _texts(rule.get("groups"))),
    }
    tables = {
        "rule": mapping.rule_to_stage,
        "technique": mapping.technique_to_stage,
        "group": mapping.group_to_stage,
    }
    for kind in mapping.precedence:
        for key in candidates[kind]:
            stage = tables[kind].get(key)
            if stage:
                return stage
    return None


def _first(*values: object) -> str | None:
    for value in values:
        result = _text(value)
        if result:
            return result
    return None


def _unknown_truth(run_id: str) -> LabelDecision:
    return LabelDecision(
        scenario_id=run_id,
        time_phase=None,
        event_phase=None,
        selected_phase=None,
        attack_family=None,
        attack_instance_id=None,
        is_attack=None,
        label_source="unknown",
        label_confidence="unknown",
        label_conflict=False,
        raw_time_label="",
        raw_event_label="",
    )


def normalize_wazuh_alert(
    raw: Mapping[str, object],
    mapping: StageMapping,
    *,
    run_id: str = "unassigned",
) -> CanonicalAlertRecord:
    rule = _mapping(raw.get("rule"))
    agent = _mapping(raw.get("agent"))
    decoder = _mapping(raw.get("decoder"))
    data = _mapping(raw.get("data"))
    win = _mapping(data.get("win"))
    eventdata = _mapping(win.get("eventdata"))
    system = _mapping(win.get("system"))
    syscheck = _mapping(raw.get("syscheck"))
    mitre = _mapping(rule.get("mitre"))

    host = _first(agent.get("name"), system.get("computer"))
    sensor_ip = _text(agent.get("ip"))
    src_ip = _first(
        data.get("srcip"), data.get("src_ip"), eventdata.get("sourceIp"),
        eventdata.get("sourceAddress"),
    )
    dst_ip = _first(
        data.get("dstip"), data.get("dst_ip"), eventdata.get("destinationIp"),
        eventdata.get("destinationAddress"),
    )
    user = _first(
        data.get("srcuser"), data.get("dstuser"), eventdata.get("user"),
        eventdata.get("targetUserName"), eventdata.get("sourceUser"),
    )
    entities = set()
    if host:
        entities.add(f"host:{host.casefold()}")
    agent_id = _text(agent.get("id"))
    if agent_id:
        entities.add(f"agent:{agent_id}")
    for address in (sensor_ip, src_ip, dst_ip):
        if address and address not in {"-", "0.0.0.0", "::"}:
            entities.add(f"ip:{address.casefold()}")
    if user and user != "-":
        entities.add(f"user:{user.casefold()}")
    artifact = _text(syscheck.get("path"))
    if artifact:
        entities.add(f"artifact:{artifact.casefold()}")
    for process in (
        eventdata.get("image"), eventdata.get("sourceImage"),
        eventdata.get("targetImage"), eventdata.get("parentImage"),
    ):
        process_text = _text(process)
        if process_text:
            entities.add(f"process:{process_text.casefold()}")

    rule_id = _text(rule.get("id")) or "unknown"
    description = _text(rule.get("description")) or "Wazuh alert"
    protocol = _first(data.get("protocol"), data.get("proto"))
    service = _first(data.get("service"), data.get("app_proto"))
    return CanonicalAlertRecord(
        alert_id=_text(raw.get("id")) or f"wazuh:{rule_id}:{raw.get('timestamp')}",
        source_id=agent_id,
        timestamp=parse_wazuh_timestamp(raw.get("timestamp")),
        sensor=f"wazuh:{_text(decoder.get('name')) or 'unknown'}",
        host=host,
        sensor_ip=sensor_ip,
        src_ip=src_ip,
        src_port=_integer(_first(data.get("srcport"), eventdata.get("sourcePort"))),
        dst_ip=dst_ip,
        dst_port=_integer(_first(data.get("dstport"), eventdata.get("destinationPort"))),
        protocol=protocol.casefold() if protocol else None,
        service=service.casefold() if service else None,
        signature_id=f"wazuh:{rule_id}",
        signature_text=description,
        severity=_integer(rule.get("level")),
        observed_tactics=tuple(item.casefold() for item in _texts(mitre.get("tactic"))),
        observed_stage=observed_stage(raw, mapping),
        entities=tuple(sorted(entities)),
        ground_truth=_unknown_truth(run_id),
    )


def iter_wazuh_jsonl(
    path: str | Path,
    mapping: StageMapping,
    *,
    run_id: str = "unassigned",
    since: float | None = None,
    until: float | None = None,
) -> Iterator[CanonicalAlertRecord]:
    with Path(path).open("r", encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                record = normalize_wazuh_alert(raw, mapping, run_id=run_id)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
            if since is not None and record.timestamp < since:
                continue
            if until is not None and record.timestamp > until:
                continue
            yield record


def mapping_audit(records: Iterable[CanonicalAlertRecord]) -> dict[str, object]:
    records = list(records)
    mapped = [item for item in records if item.observed_stage]
    counts: dict[str, int] = {}
    for item in mapped:
        counts[item.observed_stage] = counts.get(item.observed_stage, 0) + 1
    return {
        "alerts": len(records),
        "mapped_alerts": len(mapped),
        "unknown_alerts": len(records) - len(mapped),
        "coverage": len(mapped) / len(records) if records else 0.0,
        "stage_counts": dict(sorted(counts.items())),
        "unknown_policy": "neutral",
    }
