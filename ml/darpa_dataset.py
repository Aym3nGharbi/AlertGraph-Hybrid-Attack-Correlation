"""Adaptateur des alertes Suricata générées depuis DARPA 2000 LLDOS."""

from __future__ import annotations

import ipaddress
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from ait_dataset import CanonicalAlertRecord
from ait_labels import LabelDecision


DARPA_SCENARIOS = ("lldos1", "lldos2")
SCENARIO_DIRECTORIES = {
    "lldos1": "LLS_DDOS_1.0",
    "lldos2": "LLS_DDOS_2.0.2",
}
SENSOR_DIRECTORIES = {
    "inside": "tcpdump_inside",
    "dmz": "tcpdump_dmz",
}
EASTERN = ZoneInfo("America/New_York")


@dataclass(frozen=True)
class OfficialSession:
    phase: int
    start: float
    end: float
    src_ip: str
    dst_ip: str


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        try:
            return ".".join(str(int(part)) for part in raw.split("."))
        except (TypeError, ValueError):
            return raw.casefold()


def _duration(value: str | None) -> float:
    try:
        hours, minutes, seconds = (int(part) for part in (value or "0:0:0").split(":"))
    except (TypeError, ValueError):
        return 0.0
    return float(hours * 3600 + minutes * 60 + seconds)


def parse_official_sessions(xml_path: Path, phase: int) -> list[OfficialSession]:
    root = ET.parse(xml_path).getroot()
    result = []
    for alert in root.iter("Alert"):
        date = alert.findtext("./Time/date")
        clock = alert.findtext("./Time/time")
        src_ip = _ip(alert.findtext("./Source/Node/Address/address"))
        dst_ip = _ip(alert.findtext("./Target/Node/Address/address"))
        if not date or not clock or not src_ip or not dst_ip:
            continue
        start_dt = datetime.strptime(f"{date} {clock}", "%m/%d/%Y %H:%M:%S").replace(
            tzinfo=EASTERN
        )
        start = start_dt.timestamp()
        duration = _duration(alert.findtext("./Time/sessionduration"))
        result.append(
            OfficialSession(
                phase=phase,
                start=start,
                end=start + max(duration, 1.0),
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        )
    return result


def load_official_sessions(dataset_root: Path, scenario: str) -> dict[str, dict[tuple[str, str], list[OfficialSession]]]:
    scenario_root = dataset_root / SCENARIO_DIRECTORIES[scenario] / "data_and_labeling"
    result = {}
    for sensor, directory in SENSOR_DIRECTORIES.items():
        by_endpoints: dict[tuple[str, str], list[OfficialSession]] = {}
        for phase in range(1, 6):
            path = scenario_root / directory / f"mid-level-phase-{phase}.xml"
            for session in parse_official_sessions(path, phase):
                key = tuple(sorted((session.src_ip, session.dst_ip)))
                by_endpoints.setdefault(key, []).append(session)
        for sessions in by_endpoints.values():
            sessions.sort(key=lambda item: (item.start, item.end, item.phase))
        result[sensor] = by_endpoints
    return result


def _phase_for_alert(
    timestamp: float,
    src_ip: str | None,
    dst_ip: str | None,
    sessions: dict[tuple[str, str], list[OfficialSession]],
    tolerance: float = 1.0,
) -> int | None:
    if not src_ip or not dst_ip:
        return None
    key = tuple(sorted((src_ip, dst_ip)))
    matches = [
        item
        for item in sessions.get(key, ())
        if item.start - tolerance <= timestamp <= item.end + tolerance
    ]
    if not matches:
        return None
    return min(matches, key=lambda item: (abs(timestamp - item.start), item.phase)).phase


def observed_stage(signature: str) -> str | None:
    """Taxonomie sémantique générique fondée uniquement sur la règle IDS."""

    value = signature.casefold()
    if "mstream" in value or "ddos" in value or "loopback traffic" in value:
        return "NETWORK_DOS"
    if "sadmind" in value and ("root" in value or "exploit" in value):
        return "PUBLIC_APP_EXP"
    if "portmap" in value or ("sadmind" in value and "ping" in value):
        return "VULN_DISC"
    if "bad login" in value or "brute force" in value:
        return "BRUTE_FORCE_CREDS"
    if "telnet" in value or "remote login" in value:
        return "REMOTE_SERVICE_EXP"
    if "scan" in value or "port sweep" in value:
        return "SERVICE_DISC"
    if "icmp" in value and ("ping" in value or "echo" in value):
        return "HOST_DISC"
    if "ftp" in value and ("upload" in value or "download" in value):
        return "COMMAND_AND_CONTROL"
    return None


def _ground_truth(scenario: str, phase: int | None) -> LabelDecision:
    selected = f"phase_{phase}" if phase is not None else None
    is_attack = phase is not None
    return LabelDecision(
        scenario_id=scenario,
        time_phase=selected,
        event_phase=selected,
        selected_phase=selected,
        attack_family="lldos" if is_attack else None,
        attack_instance_id=f"darpa2000:{scenario}" if is_attack else None,
        is_attack=is_attack,
        label_source="official-network-session" if is_attack else "official-session-complement",
        label_confidence="high",
        label_conflict=False,
        raw_time_label=selected or "benign",
        raw_event_label=selected or "benign",
    )


def _tactics(metadata: object) -> tuple[str, ...]:
    if not isinstance(metadata, dict):
        return ()
    values = metadata.get("mitre_tactic_id", ())
    if isinstance(values, str):
        values = (values,)
    return tuple(sorted({str(item) for item in values}))


def iter_darpa_scenario(dataset_root: Path, eve_root: Path, scenario: str):
    if scenario not in DARPA_SCENARIOS:
        raise ValueError(f"Scénario DARPA inconnu: {scenario}")
    official = load_official_sessions(dataset_root, scenario)
    records = []
    sequence = 0
    for sensor in ("inside", "dmz"):
        path = eve_root / f"{scenario}-{sensor}" / "eve.json"
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                event = json.loads(line)
                if event.get("event_type") != "alert":
                    continue
                sequence += 1
                alert = event.get("alert", {})
                timestamp = datetime.fromisoformat(event["timestamp"]).timestamp()
                src_ip = _ip(event.get("src_ip"))
                dst_ip = _ip(event.get("dest_ip"))
                phase = _phase_for_alert(timestamp, src_ip, dst_ip, official[sensor])
                signature = str(alert.get("signature", "unknown"))
                src_port = event.get("src_port")
                dst_port = event.get("dest_port")
                entities = tuple(
                    sorted(
                        {f"ip:{value}" for value in (src_ip, dst_ip) if value}
                    )
                )
                records.append(
                    CanonicalAlertRecord(
                        alert_id=f"{scenario}:{sensor}:{sequence}",
                        source_id=f"{alert.get('gid', 1)}:{alert.get('signature_id', 0)}:{alert.get('rev', 0)}",
                        timestamp=timestamp,
                        sensor="suricata",
                        host=None,
                        sensor_ip=None,
                        src_ip=src_ip,
                        src_port=int(src_port) if src_port is not None else None,
                        dst_ip=dst_ip,
                        dst_port=int(dst_port) if dst_port is not None else None,
                        protocol=str(event.get("proto", "")).casefold() or None,
                        service=str(event.get("app_proto", "")) or None,
                        signature_id=str(alert.get("signature_id", "unknown")),
                        signature_text=signature,
                        severity=int(alert["severity"]) if alert.get("severity") is not None else None,
                        observed_tactics=_tactics(alert.get("metadata")),
                        observed_stage=observed_stage(signature),
                        entities=entities,
                        ground_truth=_ground_truth(scenario, phase),
                    )
                )
    yield from sorted(records, key=lambda item: (item.timestamp, item.alert_id))

