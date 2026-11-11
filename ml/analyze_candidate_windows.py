#!/usr/bin/env python3
"""Analyse les fenêtres candidates d'AIT-ADS sans matérialiser les paires."""

from __future__ import annotations

import argparse
import csv
import io
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import BinaryIO, Iterable
from zipfile import ZipFile

from ait_labels import adapt_label
from ait_observable_stages import observable_stage
from audit_ait_ads import DEFAULT_SOURCE, _read_source


DEFAULT_WINDOWS = (2, 10, 60, 150, 600, 2700)
DEFAULT_CAPS = (20, 50, 100, 1000)


def _scenario_name(entry_name: str) -> str:
    filename = Path(entry_name).name
    suffix = "_alerts.txt"
    return filename[: -len(suffix)] if filename.endswith(suffix) else filename


def _empty_window_stats(caps: Iterable[int]) -> dict[str, object]:
    return {
        "candidate_sum": 0,
        "candidate_max": 0,
        "alerts_over_cap": {str(cap): 0 for cap in caps},
        "positive_predecessors_covered": 0,
        "positive_predecessors_covered_under_cap": {
            str(cap): 0 for cap in caps
        },
    }


def analyze_zip(
    stream: BinaryIO,
    windows: tuple[int, ...] = DEFAULT_WINDOWS,
    caps: tuple[int, ...] = DEFAULT_CAPS,
    collapse_repeats_seconds: int = 0,
) -> dict[str, object]:
    if not windows or any(window <= 0 for window in windows):
        raise ValueError("Les fenêtres doivent être des secondes strictement positives")

    windows = tuple(sorted(set(windows)))
    caps = tuple(sorted(set(caps)))
    global_stats = {window: _empty_window_stats(caps) for window in windows}
    per_scenario: dict[str, dict[str, object]] = {}
    total_alerts = 0
    total_units = 0
    total_collapsed_repeats = 0
    total_attack_alerts = 0
    total_attack_with_prior = 0
    total_non_monotonic = 0
    duplicate_counts = {1: 0, 2: 0}
    raw_stage_counts: dict[str, int] = defaultdict(int)
    unit_stage_counts: dict[str, int] = defaultdict(int)

    with ZipFile(stream) as archive:
        entries = sorted(
            (entry for entry in archive.infolist() if entry.filename.endswith(".txt")),
            key=lambda entry: entry.filename,
        )

        for entry in entries:
            scenario = _scenario_name(entry.filename)
            queues = {
                window: defaultdict(deque) for window in windows
            }
            window_stats = {
                window: _empty_window_stats(caps) for window in windows
            }
            last_attack_state: dict[tuple[str, str], tuple[int, int]] = {}
            last_signature_time: dict[tuple[str, str], int] = {}
            entity_positions: dict[str, int] = defaultdict(int)
            alerts = 0
            units = 0
            collapsed_repeats = 0
            attack_alerts = 0
            attack_with_prior = 0
            non_monotonic = 0
            scenario_duplicates = {1: 0, 2: 0}

            with archive.open(entry) as raw:
                text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
                prepared_rows: list[tuple[int, int, dict[str, str]]] = []
                previous_input_timestamp: int | None = None
                for input_position, row in enumerate(csv.DictReader(text)):
                    timestamp = int(float(row["time"]))
                    if (
                        previous_input_timestamp is not None
                        and timestamp < previous_input_timestamp
                    ):
                        non_monotonic += 1
                        total_non_monotonic += 1
                    previous_input_timestamp = timestamp
                    prepared_rows.append((timestamp, input_position, row))

                # L'archive officielle concatène Wazuh/Suricata puis AMiner,
                # alors que leurs plages temporelles se chevauchent. Le tri
                # repose uniquement sur le timestamp observable ; la position
                # d'entrée rend déterministe l'ordre des ex aequo.
                prepared_rows.sort(key=lambda item: (item[0], item[1]))

                for timestamp, _, row in prepared_rows:
                    entity = (row.get("host") or row.get("ip") or "unknown").strip()
                    signature = (row.get("short") or row.get("name") or "unknown").strip()
                    decision = adapt_label(
                        scenario, row.get("time_label", ""), row.get("event_label", "")
                    )
                    stage = observable_stage(row.get("name", "")) or "UNMAPPED"
                    raw_stage_counts[stage] += 1

                    alerts += 1
                    total_alerts += 1
                    effective_timestamp = timestamp

                    signature_key = (entity, signature)
                    delta_signature: int | None = None
                    if signature_key in last_signature_time:
                        delta_signature = timestamp - last_signature_time[signature_key]
                        for duplicate_window in (1, 2):
                            if 0 <= delta_signature <= duplicate_window:
                                scenario_duplicates[duplicate_window] += 1
                                duplicate_counts[duplicate_window] += 1
                    last_signature_time[signature_key] = timestamp

                    if (
                        collapse_repeats_seconds > 0
                        and delta_signature is not None
                        and 0 <= delta_signature <= collapse_repeats_seconds
                    ):
                        collapsed_repeats += 1
                        total_collapsed_repeats += 1
                        continue

                    units += 1
                    total_units += 1
                    unit_stage_counts[stage] += 1
                    entity_position = entity_positions[entity]
                    entity_positions[entity] += 1

                    predecessor_delta: int | None = None
                    predecessor_rank: int | None = None
                    if decision.is_attack and decision.attack_instance_id:
                        attack_alerts += 1
                        total_attack_alerts += 1
                        attack_key = (decision.attack_instance_id, entity)
                        if attack_key in last_attack_state:
                            predecessor_time, predecessor_position = last_attack_state[
                                attack_key
                            ]
                            predecessor_delta = effective_timestamp - predecessor_time
                            predecessor_rank = entity_position - predecessor_position
                            if predecessor_delta >= 0:
                                attack_with_prior += 1
                                total_attack_with_prior += 1
                        last_attack_state[attack_key] = (
                            effective_timestamp,
                            entity_position,
                        )

                    for window in windows:
                        queue = queues[window][entity]
                        cutoff = effective_timestamp - window
                        while queue and queue[0] < cutoff:
                            queue.popleft()
                        candidates = len(queue)
                        stats = window_stats[window]
                        stats["candidate_sum"] += candidates
                        stats["candidate_max"] = max(stats["candidate_max"], candidates)
                        for cap in caps:
                            if candidates > cap:
                                stats["alerts_over_cap"][str(cap)] += 1
                        if (
                            predecessor_delta is not None
                            and 0 <= predecessor_delta <= window
                        ):
                            stats["positive_predecessors_covered"] += 1
                            for cap in caps:
                                if predecessor_rank is not None and predecessor_rank <= cap:
                                    stats["positive_predecessors_covered_under_cap"][
                                        str(cap)
                                    ] += 1
                        queue.append(effective_timestamp)

            rendered_windows: dict[str, object] = {}
            for window, stats in window_stats.items():
                global_window = global_stats[window]
                global_window["candidate_sum"] += stats["candidate_sum"]
                global_window["candidate_max"] = max(
                    global_window["candidate_max"], stats["candidate_max"]
                )
                global_window["positive_predecessors_covered"] += stats[
                    "positive_predecessors_covered"
                ]
                for cap in caps:
                    global_window["alerts_over_cap"][str(cap)] += stats[
                        "alerts_over_cap"
                    ][str(cap)]
                    global_window["positive_predecessors_covered_under_cap"][
                        str(cap)
                    ] += stats["positive_predecessors_covered_under_cap"][str(cap)]
                rendered_windows[str(window)] = _render_window(
                    stats, units, attack_with_prior, caps
                )

            per_scenario[scenario] = {
                "alerts": alerts,
                "analyzed_units": units,
                "collapsed_repeats": collapsed_repeats,
                "attack_alerts": attack_alerts,
                "attack_alerts_with_prior_same_entity": attack_with_prior,
                "non_monotonic_timestamps": non_monotonic,
                "repeated_signature_within_seconds": scenario_duplicates,
                "windows": rendered_windows,
            }

    return {
        "summary": {
            "alerts": total_alerts,
            "analyzed_units": total_units,
            "collapsed_repeats": total_collapsed_repeats,
            "collapse_repeats_seconds": collapse_repeats_seconds,
            "attack_alerts": total_attack_alerts,
            "attack_alerts_with_prior_same_entity": total_attack_with_prior,
            "non_monotonic_timestamps": total_non_monotonic,
            "repeated_signature_within_seconds": duplicate_counts,
            "observable_stage_mapping": {
                "raw_mapped": total_alerts - raw_stage_counts["UNMAPPED"],
                "raw_coverage_pct": round(
                    100
                    * (total_alerts - raw_stage_counts["UNMAPPED"])
                    / max(total_alerts, 1),
                    3,
                ),
                "meta_mapped": total_units - unit_stage_counts["UNMAPPED"],
                "meta_coverage_pct": round(
                    100
                    * (total_units - unit_stage_counts["UNMAPPED"])
                    / max(total_units, 1),
                    3,
                ),
                "meta_stage_counts": dict(
                    sorted(
                        unit_stage_counts.items(),
                        key=lambda item: (-item[1], item[0]),
                    )
                ),
            },
            "windows": {
                str(window): _render_window(
                    stats, total_units, total_attack_with_prior, caps
                )
                for window, stats in global_stats.items()
            },
        },
        "scenarios": per_scenario,
    }


def _render_window(
    stats: dict[str, object], alerts: int, attack_with_prior: int, caps: tuple[int, ...]
) -> dict[str, object]:
    return {
        "mean_prior_candidates_same_entity": round(
            stats["candidate_sum"] / max(alerts, 1), 3
        ),
        "max_prior_candidates_same_entity": stats["candidate_max"],
        "positive_predecessor_coverage_pct": round(
            100 * stats["positive_predecessors_covered"] / max(attack_with_prior, 1),
            3,
        ),
        "positive_predecessor_coverage_under_cap_pct": {
            str(cap): round(
                100
                * stats["positive_predecessors_covered_under_cap"][str(cap)]
                / max(attack_with_prior, 1),
                3,
            )
            for cap in caps
        },
        "alerts_over_cap_pct": {
            str(cap): round(
                100 * stats["alerts_over_cap"][str(cap)] / max(alerts, 1), 3
            )
            for cap in caps
        },
    }


def analyze_source(
    source: str,
    windows: tuple[int, ...] = DEFAULT_WINDOWS,
    caps: tuple[int, ...] = DEFAULT_CAPS,
    collapse_repeats_seconds: int = 0,
) -> dict[str, object]:
    return analyze_zip(
        io.BytesIO(_read_source(source)), windows, caps, collapse_repeats_seconds
    )


def _positive_int_csv(value: str) -> tuple[int, ...]:
    parsed = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    if not parsed or any(item <= 0 for item in parsed):
        raise argparse.ArgumentTypeError("valeurs attendues: entiers positifs séparés par des virgules")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", default=DEFAULT_SOURCE)
    parser.add_argument("--windows", type=_positive_int_csv, default=DEFAULT_WINDOWS)
    parser.add_argument("--caps", type=_positive_int_csv, default=DEFAULT_CAPS)
    parser.add_argument(
        "--collapse-repeats-seconds",
        type=int,
        default=0,
        help="Regroupe pour l'analyse les répétitions même hôte/signature",
    )
    parser.add_argument("--output")
    args = parser.parse_args()

    if args.collapse_repeats_seconds < 0:
        parser.error("--collapse-repeats-seconds doit être positif ou nul")
    report = analyze_source(
        args.source, args.windows, args.caps, args.collapse_repeats_seconds
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()

