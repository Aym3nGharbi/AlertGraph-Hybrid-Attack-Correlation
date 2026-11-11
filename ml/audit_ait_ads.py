#!/usr/bin/env python3
"""Audit progressif des CSV d'analyse d'AIT-ADS.

Le programme accepte l'archive ``alerts_csv.zip`` officielle, localement ou par
URL. Chaque entrée CSV est lue ligne par ligne ; les fichiers décompressés ne
sont jamais chargés entièrement en mémoire.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from collections import Counter
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlparse
from urllib.request import urlopen
from zipfile import ZipFile

from ait_labels import adapt_label


DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/ait-aecid/alert-data-set/"
    "main/alerts_csv/alerts_csv.zip"
)


def _read_source(source: str) -> bytes:
    scheme = urlparse(source).scheme.lower()
    if scheme in {"http", "https"}:
        with urlopen(source) as response:  # nosec B310: URL choisie par l'utilisateur
            return response.read()
    return Path(source).read_bytes()


def _scenario_name(entry_name: str) -> str:
    filename = Path(entry_name).name
    suffix = "_alerts.txt"
    return filename[: -len(suffix)] if filename.endswith(suffix) else filename


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(counter.most_common())


def audit_zip(stream: BinaryIO) -> dict[str, object]:
    by_scenario: dict[str, dict[str, object]] = {}
    overall_time: Counter[str] = Counter()
    overall_event: Counter[str] = Counter()
    overall_sources: Counter[str] = Counter()
    overall_confidences: Counter[str] = Counter()
    overall_families: Counter[str] = Counter()
    overall_attack_status: Counter[str] = Counter()
    total = 0
    event_labeled = 0
    raw_label_mismatches = 0
    canonical_conflicts = 0

    with ZipFile(stream) as archive:
        entries = sorted(
            (entry for entry in archive.infolist() if entry.filename.endswith(".txt")),
            key=lambda entry: entry.filename,
        )
        if not entries:
            raise ValueError("L'archive ne contient aucun fichier *_alerts.txt")

        for entry in entries:
            scenario = _scenario_name(entry.filename)
            time_counts: Counter[str] = Counter()
            event_counts: Counter[str] = Counter()
            scenario_total = 0
            scenario_event_labeled = 0
            scenario_mismatches = 0
            scenario_sources: Counter[str] = Counter()
            scenario_confidences: Counter[str] = Counter()
            scenario_families: Counter[str] = Counter()
            scenario_attack_status: Counter[str] = Counter()
            scenario_conflicts = 0

            with archive.open(entry) as raw:
                text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
                reader = csv.DictReader(text)
                required = {"time_label", "event_label"}
                if not required.issubset(reader.fieldnames or []):
                    raise ValueError(
                        f"Colonnes absentes dans {entry.filename}: {sorted(required)}"
                    )

                for row in reader:
                    time_label = (row.get("time_label") or "").strip()
                    event_label = (row.get("event_label") or "").strip()
                    scenario_total += 1
                    time_counts[time_label] += 1
                    event_counts[event_label] += 1

                    if event_label != "-":
                        scenario_event_labeled += 1
                        if event_label != time_label:
                            scenario_mismatches += 1

                    decision = adapt_label(scenario, time_label, event_label)
                    scenario_sources[decision.label_source] += 1
                    scenario_confidences[decision.label_confidence] += 1
                    scenario_families[decision.attack_family or "none"] += 1
                    status = (
                        "attack"
                        if decision.is_attack is True
                        else "benign"
                        if decision.is_attack is False
                        else "unknown"
                    )
                    scenario_attack_status[status] += 1
                    if decision.label_conflict:
                        scenario_conflicts += 1

            total += scenario_total
            event_labeled += scenario_event_labeled
            raw_label_mismatches += scenario_mismatches
            canonical_conflicts += scenario_conflicts
            overall_time.update(time_counts)
            overall_event.update(event_counts)
            overall_sources.update(scenario_sources)
            overall_confidences.update(scenario_confidences)
            overall_families.update(scenario_families)
            overall_attack_status.update(scenario_attack_status)
            by_scenario[scenario] = {
                "total": scenario_total,
                "event_labeled": scenario_event_labeled,
                "event_coverage_pct": round(
                    100 * scenario_event_labeled / max(scenario_total, 1), 3
                ),
                "raw_label_mismatches": scenario_mismatches,
                "canonical_phase_conflicts": scenario_conflicts,
                "time_labels": _counter_dict(time_counts),
                "event_labels": _counter_dict(event_counts),
                "label_sources": _counter_dict(scenario_sources),
                "label_confidences": _counter_dict(scenario_confidences),
                "attack_families": _counter_dict(scenario_families),
                "attack_status": _counter_dict(scenario_attack_status),
            }

    return {
        "summary": {
            "total": total,
            "event_labeled": event_labeled,
            "event_coverage_pct": round(100 * event_labeled / max(total, 1), 3),
            "raw_label_mismatches": raw_label_mismatches,
            "canonical_phase_conflicts": canonical_conflicts,
            "time_labels": _counter_dict(overall_time),
            "event_labels": _counter_dict(overall_event),
            "label_sources": _counter_dict(overall_sources),
            "label_confidences": _counter_dict(overall_confidences),
            "attack_families": _counter_dict(overall_families),
            "attack_status": _counter_dict(overall_attack_status),
        },
        "scenarios": by_scenario,
    }


def audit_source(source: str) -> dict[str, object]:
    return audit_zip(io.BytesIO(_read_source(source)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source",
        nargs="?",
        default=DEFAULT_SOURCE,
        help="Chemin local ou URL de alerts_csv.zip",
    )
    parser.add_argument("--output", help="Fichier JSON optionnel pour le rapport")
    args = parser.parse_args()

    report = audit_source(args.source)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()

