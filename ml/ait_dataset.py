"""Lecture streaming d'AIT-ADS avec séparation observable/vérité terrain.

Les JSON officiels contiennent les attributs réellement disponibles au moment
de l'alerte. L'archive CSV officielle fournit les timestamps normalisés et les
annotations. Leur ordre a été vérifié et ce lecteur refuse silencieusement tout
décalage : une incohérence lève ``DatasetAlignmentError``.
"""

from __future__ import annotations

import csv
import heapq
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping

from ait_labels import LabelDecision, adapt_label
from ait_observable_stages import observable_stage
from candidates import ObservableAlert


class DatasetAlignmentError(ValueError):
    """Les flux brut et compact ne décrivent pas la même suite d'alertes."""


@dataclass(frozen=True)
class CanonicalAlertRecord:
    """Une alerte normalisée, sans mélanger observations et annotation."""

    alert_id: str
    source_id: str | None
    timestamp: float
    sensor: str
    host: str | None
    sensor_ip: str | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    service: str | None
    signature_id: str
    signature_text: str
    severity: int | None
    observed_tactics: tuple[str, ...]
    observed_stage: str | None
    entities: tuple[str, ...]
    ground_truth: LabelDecision

    def to_observable_alert(self) -> ObservableAlert:
        """Projection autorisée pour la génération de candidats.

        ``ground_truth`` est volontairement absent de l'objet retourné.
        """

        return ObservableAlert(
            alert_id=self.alert_id,
            timestamp=self.timestamp,
            sensor=self.sensor,
            signature=self.signature_id,
            entities=self.entities,
            observed_stage=self.observed_stage,
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


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _tuple_of_text(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        values = ()
    return tuple(sorted({_text(item) for item in values} - {None}))


def _entities(*, host: str | None, sensor_ip: str | None,
              src_ip: str | None, dst_ip: str | None) -> tuple[str, ...]:
    values = set()
    if host:
        values.add(f"host:{host.casefold()}")
    for address in (sensor_ip, src_ip, dst_ip):
        if address:
            values.add(f"ip:{address.casefold()}")
    return tuple(sorted(values))


def _expected_name(raw: Mapping[str, object], source: str) -> str:
    if source == "wazuh":
        rule = _mapping(raw.get("rule"))
        description = _text(rule.get("description")) or ""
        return (
            description
            if description.startswith("Suricata: ")
            else f"Wazuh: {description}"
        )
    component = _mapping(raw.get("AnalysisComponent"))
    return _text(component.get("AnalysisComponentName")) or ""


def _wazuh_record(
    scenario: str,
    sequence: int,
    raw: Mapping[str, object],
    compact: Mapping[str, str],
) -> CanonicalAlertRecord:
    rule = _mapping(raw.get("rule"))
    data = _mapping(raw.get("data"))
    suricata_alert = _mapping(data.get("alert"))
    mitre = _mapping(rule.get("mitre"))
    description = _text(rule.get("description")) or ""
    sensor = "suricata" if description.startswith("Suricata: ") else "wazuh"

    if sensor == "suricata":
        src_ip = _text(data.get("src_ip"))
        dst_ip = _text(data.get("dest_ip"))
        src_port = _integer(data.get("src_port"))
        dst_port = _integer(data.get("dest_port"))
        protocol = _text(data.get("proto"))
        service = _text(data.get("app_proto"))
        signature_id = _text(suricata_alert.get("signature_id"))
        severity = _integer(suricata_alert.get("severity"))
    else:
        src_ip = _text(data.get("srcip"))
        dst_ip = _text(data.get("dstip"))
        src_port = _integer(data.get("srcport"))
        dst_port = _integer(data.get("dstport"))
        protocol = _text(data.get("protocol"))
        service = _text(data.get("service"))
        signature_id = None
        severity = _integer(rule.get("level"))

    host = _text(compact.get("host"))
    sensor_ip = _text(compact.get("ip"))
    signature_text = compact["name"]
    return CanonicalAlertRecord(
        alert_id=f"{scenario}:{sensor}:{sequence}",
        source_id=_text(raw.get("id")),
        timestamp=float(compact["time"]),
        sensor=sensor,
        host=host,
        sensor_ip=sensor_ip,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol.casefold() if protocol else None,
        service=service.casefold() if service else None,
        signature_id=signature_id or compact["short"],
        signature_text=signature_text,
        severity=severity,
        observed_tactics=_tuple_of_text(mitre.get("tactic")),
        observed_stage=observable_stage(signature_text),
        entities=_entities(
            host=host, sensor_ip=sensor_ip, src_ip=src_ip, dst_ip=dst_ip
        ),
        ground_truth=adapt_label(
            scenario, compact["time_label"], compact["event_label"]
        ),
    )


def _aminer_record(
    scenario: str,
    sequence: int,
    raw: Mapping[str, object],
    compact: Mapping[str, str],
) -> CanonicalAlertRecord:
    aminer = _mapping(raw.get("AMiner"))
    component = _mapping(raw.get("AnalysisComponent"))
    host = _text(compact.get("host"))
    sensor_ip = _text(compact.get("ip")) or _text(aminer.get("ID"))
    signature_text = compact["name"]
    source_id = _text(component.get("AnalysisComponentIdentifier"))
    return CanonicalAlertRecord(
        alert_id=f"{scenario}:aminer:{sequence}",
        source_id=source_id,
        timestamp=float(compact["time"]),
        sensor="aminer",
        host=host,
        sensor_ip=sensor_ip,
        src_ip=None,
        src_port=None,
        dst_ip=None,
        dst_port=None,
        protocol=None,
        service=None,
        signature_id=compact["short"],
        signature_text=signature_text,
        severity=None,
        observed_tactics=(),
        observed_stage=observable_stage(signature_text),
        entities=_entities(
            host=host, sensor_ip=sensor_ip, src_ip=None, dst_ip=None
        ),
        ground_truth=adapt_label(
            scenario, compact["time_label"], compact["event_label"]
        ),
    )


def iter_ait_scenario(
    raw_archive: str | Path,
    compact_archive: str | Path,
    scenario: str,
) -> Iterator[CanonicalAlertRecord]:
    """Lit un scénario dans l'ordre officiel sans extraire les archives."""

    compact_member = f"alerts_csv/{scenario}_alerts.txt"
    with zipfile.ZipFile(compact_archive) as compact_zip, zipfile.ZipFile(
        raw_archive
    ) as raw_zip:
        compact_stream = io.TextIOWrapper(
            compact_zip.open(compact_member), encoding="utf-8", newline=""
        )
        rows = csv.DictReader(compact_stream)
        for source in ("wazuh", "aminer"):
            source_sequence = 0
            with raw_zip.open(f"{scenario}_{source}.json") as raw_stream:
                for line_number, binary_line in enumerate(raw_stream, 1):
                    line = binary_line.decode("utf-8-sig").strip()
                    if not line or "The average number" in line:
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise DatasetAlignmentError(
                            f"JSON invalide dans {source}, ligne {line_number}"
                        ) from error

                    compact = next(rows, None)
                    if compact is None:
                        raise DatasetAlignmentError(
                            f"CSV épuisé avant {source}, ligne {line_number}"
                        )
                    expected = _expected_name(raw, source)
                    if compact.get("name") != expected:
                        raise DatasetAlignmentError(
                            f"Décalage {source}, ligne {line_number}: "
                            f"{expected!r} != {compact.get('name')!r}"
                        )

                    source_sequence += 1
                    if source == "wazuh":
                        yield _wazuh_record(
                            scenario, source_sequence, raw, compact
                        )
                    else:
                        yield _aminer_record(
                            scenario, source_sequence, raw, compact
                        )

        if next(rows, None) is not None:
            raise DatasetAlignmentError("Le CSV contient des alertes restantes")


def _compact_row_matches_source(row: Mapping[str, str], source: str) -> bool:
    is_aminer = (row.get("name") or "").startswith("AMiner: ")
    return is_aminer if source == "aminer" else not is_aminer


def _iter_ait_source(
    raw_archive: str | Path,
    compact_archive: str | Path,
    scenario: str,
    source: str,
) -> Iterator[CanonicalAlertRecord]:
    """Lit un des deux flux déjà chronologiques d'un scénario."""

    if source not in {"wazuh", "aminer"}:
        raise ValueError("source attendue: 'wazuh' ou 'aminer'")

    compact_member = f"alerts_csv/{scenario}_alerts.txt"
    with zipfile.ZipFile(compact_archive) as compact_zip, zipfile.ZipFile(
        raw_archive
    ) as raw_zip:
        compact_stream = io.TextIOWrapper(
            compact_zip.open(compact_member), encoding="utf-8", newline=""
        )
        matching_rows = (
            row
            for row in csv.DictReader(compact_stream)
            if _compact_row_matches_source(row, source)
        )
        sequence = 0
        previous_timestamp: float | None = None
        with raw_zip.open(f"{scenario}_{source}.json") as raw_stream:
            for line_number, binary_line in enumerate(raw_stream, 1):
                line = binary_line.decode("utf-8-sig").strip()
                if not line or "The average number" in line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as error:
                    raise DatasetAlignmentError(
                        f"JSON invalide dans {source}, ligne {line_number}"
                    ) from error

                compact = next(matching_rows, None)
                if compact is None:
                    raise DatasetAlignmentError(
                        f"CSV {source} épuisé à la ligne {line_number}"
                    )
                expected = _expected_name(raw, source)
                if compact.get("name") != expected:
                    raise DatasetAlignmentError(
                        f"Décalage {source}, ligne {line_number}: "
                        f"{expected!r} != {compact.get('name')!r}"
                    )

                sequence += 1
                record = (
                    _wazuh_record(scenario, sequence, raw, compact)
                    if source == "wazuh"
                    else _aminer_record(scenario, sequence, raw, compact)
                )
                if (
                    previous_timestamp is not None
                    and record.timestamp < previous_timestamp
                ):
                    raise DatasetAlignmentError(
                        f"Le flux {source} n'est pas chronologique"
                    )
                previous_timestamp = record.timestamp
                yield record

        if next(matching_rows, None) is not None:
            raise DatasetAlignmentError(
                f"Le CSV contient des alertes {source} restantes"
            )


def iter_ait_scenario_chronological(
    raw_archive: str | Path,
    compact_archive: str | Path,
    scenario: str,
) -> Iterator[CanonicalAlertRecord]:
    """Fusionne chronologiquement Wazuh/Suricata et AMiner en streaming."""

    streams = (
        _iter_ait_source(raw_archive, compact_archive, scenario, "wazuh"),
        _iter_ait_source(raw_archive, compact_archive, scenario, "aminer"),
    )
    return heapq.merge(
        *streams,
        key=lambda record: (record.timestamp, record.alert_id),
    )

