#!/usr/bin/env python3
"""Audite les labels des paires candidates réelles d'AIT-ADS.

La génération des candidats n'accède jamais à la vérité terrain. Les labels
servent uniquement après génération pour mesurer le déséquilibre et la
couverture. Les répétitions sont regroupées de façon réversible.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from ait_dataset import CanonicalAlertRecord, iter_ait_scenario_chronological
from candidates import MetaAlert


DEFAULT_SCENARIOS = (
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
)


@dataclass
class _MetaBuilder:
    meta_id: str
    first_timestamp: float
    last_timestamp: float
    sensor: str
    signature: str
    entities: tuple[str, ...]
    observed_stage: str | None
    signature_text: str
    member_alert_ids: list[str] = field(default_factory=list)
    truth_keys: set[tuple[bool | None, str | None]] = field(default_factory=set)
    truth_phases: set[str] = field(default_factory=set)
    all_event_confidence: bool = True
    protocols: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    observed_tactics: set[str] = field(default_factory=set)
    severities: list[int] = field(default_factory=list)
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class AuditedMetaAlert:
    meta_id: str
    first_timestamp: float
    last_timestamp: float
    sensor: str
    signature: str
    signature_text: str
    entities: tuple[str, ...]
    member_alert_ids: tuple[str, ...]
    observed_stage: str | None
    protocols: tuple[str, ...]
    services: tuple[str, ...]
    observed_tactics: tuple[str, ...]
    src_ips: tuple[str, ...]
    dst_ips: tuple[str, ...]
    min_severity: int | None
    max_severity: int | None
    is_attack: bool | None
    attack_instance_id: str | None
    ground_truth_phases: tuple[str, ...]
    truth_confidence: str
    prior_entity_density_2s: int = 0
    prior_entity_density_10s: int = 0
    prior_entity_density_60s: int = 0
    prior_entity_density_150s: int = 0
    seconds_since_same_signature_entity: float | None = None

    @property
    def truth_is_mixed(self) -> bool:
        return self.truth_confidence == "mixed"

    def to_meta_alert(self) -> MetaAlert:
        """Projection observable compatible avec les générateurs existants."""

        return MetaAlert(
            meta_id=self.meta_id,
            first_timestamp=self.first_timestamp,
            last_timestamp=self.last_timestamp,
            sensor=self.sensor,
            signature=self.signature,
            entities=self.entities,
            member_alert_ids=self.member_alert_ids,
            observed_stage=self.observed_stage,
        )


def _add_member(builder: _MetaBuilder, alert: CanonicalAlertRecord) -> None:
    builder.last_timestamp = alert.timestamp
    builder.member_alert_ids.append(alert.alert_id)
    truth = alert.ground_truth
    builder.truth_keys.add((truth.is_attack, truth.attack_instance_id))
    if truth.selected_phase:
        builder.truth_phases.add(truth.selected_phase)
    builder.all_event_confidence &= truth.label_confidence == "high"
    if alert.protocol:
        builder.protocols.add(alert.protocol)
    if alert.service:
        builder.services.add(alert.service)
    builder.observed_tactics.update(alert.observed_tactics)
    if alert.severity is not None:
        builder.severities.append(alert.severity)
    if alert.src_ip:
        builder.src_ips.add(alert.src_ip.casefold())
    if alert.dst_ip:
        builder.dst_ips.add(alert.dst_ip.casefold())


def collapse_labeled_records(
    records: Iterable[CanonicalAlertRecord], max_gap_seconds: float = 2.0
) -> list[AuditedMetaAlert]:
    """Compresse avec les seuls attributs observables, puis agrège les labels."""

    if max_gap_seconds < 0:
        raise ValueError("max_gap_seconds doit être positif ou nul")

    builders: list[_MetaBuilder] = []
    active: dict[tuple[str, str, tuple[str, ...], str | None], int] = {}
    previous_timestamp: float | None = None

    for alert in records:
        if previous_timestamp is not None and alert.timestamp < previous_timestamp:
            raise ValueError("Les alertes doivent être chronologiques")
        previous_timestamp = alert.timestamp
        key = (alert.sensor, alert.signature_id, alert.entities, alert.observed_stage)
        index = active.get(key)
        if index is not None:
            current = builders[index]
            if 0 <= alert.timestamp - current.last_timestamp <= max_gap_seconds:
                _add_member(current, alert)
                continue

        builder = _MetaBuilder(
            meta_id=f"meta-{len(builders) + 1}",
            first_timestamp=alert.timestamp,
            last_timestamp=alert.timestamp,
            sensor=alert.sensor,
            signature=alert.signature_id,
            entities=alert.entities,
            observed_stage=alert.observed_stage,
            signature_text=alert.signature_text,
        )
        _add_member(builder, alert)
        active[key] = len(builders)
        builders.append(builder)

    result = []
    for builder in builders:
        if len(builder.truth_keys) == 1:
            is_attack, attack_instance_id = next(iter(builder.truth_keys))
            confidence = "high" if builder.all_event_confidence else "weak"
        else:
            is_attack = None
            attack_instance_id = None
            confidence = "mixed"
        result.append(
            AuditedMetaAlert(
                meta_id=builder.meta_id,
                first_timestamp=builder.first_timestamp,
                last_timestamp=builder.last_timestamp,
                sensor=builder.sensor,
                signature=builder.signature,
                signature_text=builder.signature_text,
                entities=builder.entities,
                member_alert_ids=tuple(builder.member_alert_ids),
                observed_stage=builder.observed_stage,
                protocols=tuple(sorted(builder.protocols)),
                services=tuple(sorted(builder.services)),
                observed_tactics=tuple(sorted(builder.observed_tactics)),
                src_ips=tuple(sorted(builder.src_ips)),
                dst_ips=tuple(sorted(builder.dst_ips)),
                min_severity=min(builder.severities) if builder.severities else None,
                max_severity=max(builder.severities) if builder.severities else None,
                is_attack=is_attack,
                attack_instance_id=attack_instance_id,
                ground_truth_phases=tuple(sorted(builder.truth_phases)),
                truth_confidence=confidence,
            )
        )
    return result


def add_observable_context(
    meta_alerts: Iterable[AuditedMetaAlert],
) -> list[AuditedMetaAlert]:
    """Ajoute une histoire locale calculée sans aucune vérité terrain."""

    windows = (2, 10, 60, 150)
    queues = {
        window: defaultdict(deque) for window in windows
    }
    latest_signature_entity: dict[tuple[str, str, str], float] = {}
    result = []

    for current in sorted(
        meta_alerts, key=lambda item: (item.first_timestamp, item.meta_id)
    ):
        densities = {}
        for window in windows:
            largest_queue = 0
            cutoff = current.first_timestamp - window
            for entity in current.entities:
                queue = queues[window][entity]
                while queue and queue[0] < cutoff:
                    queue.popleft()
                largest_queue = max(largest_queue, len(queue))
            densities[window] = largest_queue

        previous_times = [
            latest_signature_entity[(current.sensor, current.signature, entity)]
            for entity in current.entities
            if (current.sensor, current.signature, entity)
            in latest_signature_entity
        ]
        signature_gap = (
            max(0.0, current.first_timestamp - max(previous_times))
            if previous_times
            else None
        )
        enriched = replace(
            current,
            prior_entity_density_2s=densities[2],
            prior_entity_density_10s=densities[10],
            prior_entity_density_60s=densities[60],
            prior_entity_density_150s=densities[150],
            seconds_since_same_signature_entity=signature_gap,
        )
        result.append(enriched)

        for window in windows:
            for entity in current.entities:
                queues[window][entity].append(current.first_timestamp)
        for entity in current.entities:
            latest_signature_entity[
                (current.sensor, current.signature, entity)
            ] = current.last_timestamp

    return result


def _pair_category(left: AuditedMetaAlert, right: AuditedMetaAlert) -> str:
    if left.truth_is_mixed or right.truth_is_mixed:
        return "unknown_mixed_meta"
    if left.is_attack is None or right.is_attack is None:
        return "unknown_label"
    if left.is_attack and right.is_attack:
        if left.attack_instance_id == right.attack_instance_id:
            return "positive_same_attack"
        return "negative_different_attacks"
    if left.is_attack != right.is_attack:
        return "negative_attack_benign"
    return "negative_benign_benign"


def audit_meta_candidates(
    meta_alerts: Iterable[AuditedMetaAlert],
    window_seconds: float = 60.0,
    max_candidates_per_alert: int = 50,
) -> dict[str, object]:
    if window_seconds <= 0 or max_candidates_per_alert <= 0:
        raise ValueError("La fenêtre et le plafond doivent être positifs")

    ordered = sorted(
        meta_alerts, key=lambda item: (item.first_timestamp, item.meta_id)
    )
    by_entity: dict[str, deque[AuditedMetaAlert]] = defaultdict(deque)
    last_positive_by_entity: dict[tuple[str, str], AuditedMetaAlert] = {}
    pair_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    candidate_counts: Counter[str] = Counter()
    attack_with_observable_prior = 0
    attack_prior_covered = 0

    for current in ordered:
        candidates: dict[str, AuditedMetaAlert] = {}
        cutoff = current.first_timestamp - window_seconds
        for entity in current.entities:
            queue = by_entity[entity]
            while queue and queue[0].last_timestamp < cutoff:
                queue.popleft()
            for previous in queue:
                candidates[previous.meta_id] = previous

        recent = sorted(
            candidates.values(),
            key=lambda item: (item.last_timestamp, item.meta_id),
            reverse=True,
        )[:max_candidates_per_alert]
        recent_ids = {item.meta_id for item in recent}
        candidate_counts["total"] += len(recent)
        candidate_counts["alerts_with_candidates"] += bool(recent)
        candidate_counts["max_before_cap"] = max(
            candidate_counts["max_before_cap"], len(candidates)
        )
        candidate_counts["over_cap"] += len(candidates) > max_candidates_per_alert

        for previous in recent:
            category = _pair_category(previous, current)
            pair_counts[category] += 1
            if category not in {"unknown_mixed_meta", "unknown_label"}:
                confidence = (
                    "high"
                    if previous.truth_confidence == current.truth_confidence == "high"
                    else "weak"
                )
                confidence_counts[confidence] += 1

        if current.is_attack and current.attack_instance_id:
            prior_ids = {
                last_positive_by_entity[(current.attack_instance_id, entity)].meta_id
                for entity in current.entities
                if (current.attack_instance_id, entity) in last_positive_by_entity
            }
            if prior_ids:
                attack_with_observable_prior += 1
                attack_prior_covered += bool(prior_ids & recent_ids)

        for entity in current.entities:
            by_entity[entity].append(current)
            if current.is_attack and current.attack_instance_id:
                last_positive_by_entity[
                    (current.attack_instance_id, entity)
                ] = current

    positives = pair_counts["positive_same_attack"]
    negatives = sum(
        value for key, value in pair_counts.items() if key.startswith("negative_")
    )
    return {
        "meta_alerts": len(ordered),
        "mixed_truth_meta_alerts": sum(item.truth_is_mixed for item in ordered),
        "member_alerts": sum(len(item.member_alert_ids) for item in ordered),
        "candidate_pairs": candidate_counts["total"],
        "mean_candidates_per_meta_alert": round(
            candidate_counts["total"] / max(len(ordered), 1), 3
        ),
        "max_candidates_before_cap": candidate_counts["max_before_cap"],
        "meta_alerts_over_cap": candidate_counts["over_cap"],
        "pair_categories": dict(sorted(pair_counts.items())),
        "labeled_positive_pairs": positives,
        "labeled_negative_pairs": negatives,
        "positive_fraction_pct": round(
            100 * positives / max(positives + negatives, 1), 3
        ),
        "pair_confidence": dict(sorted(confidence_counts.items())),
        "attack_meta_alerts_with_prior_same_instance_entity": attack_with_observable_prior,
        "prior_positive_covered": attack_prior_covered,
        "prior_positive_coverage_pct": round(
            100 * attack_prior_covered / max(attack_with_observable_prior, 1), 3
        ),
    }


def audit_scenario(
    raw_archive: str | Path,
    compact_archive: str | Path,
    scenario: str,
    collapse_seconds: float = 2.0,
    window_seconds: float = 60.0,
    cap: int = 50,
) -> dict[str, object]:
    records = iter_ait_scenario_chronological(
        raw_archive, compact_archive, scenario
    )
    meta_alerts = collapse_labeled_records(records, collapse_seconds)
    return audit_meta_candidates(meta_alerts, window_seconds, cap)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_archive")
    parser.add_argument("compact_archive")
    parser.add_argument("--scenarios", default=",".join(DEFAULT_SCENARIOS))
    parser.add_argument("--collapse-seconds", type=float, default=2.0)
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--cap", type=int, default=50)
    parser.add_argument("--output")
    args = parser.parse_args()

    scenarios = tuple(item.strip() for item in args.scenarios.split(",") if item.strip())
    report = {
        "parameters": {
            "collapse_seconds": args.collapse_seconds,
            "window_seconds": args.window_seconds,
            "cap": args.cap,
        },
        "scenarios": {},
    }
    for scenario in scenarios:
        report["scenarios"][scenario] = audit_scenario(
            args.raw_archive,
            args.compact_archive,
            scenario,
            args.collapse_seconds,
            args.window_seconds,
            args.cap,
        )

    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
