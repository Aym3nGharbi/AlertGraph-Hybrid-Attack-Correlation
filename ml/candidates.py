"""Compression réversible et génération de candidats sans fuite de labels."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, replace
from typing import Iterable, Iterator


@dataclass(frozen=True)
class ObservableAlert:
    alert_id: str
    timestamp: float
    sensor: str
    signature: str
    entities: tuple[str, ...]
    observed_stage: str | None = None


@dataclass(frozen=True)
class MetaAlert:
    meta_id: str
    first_timestamp: float
    last_timestamp: float
    sensor: str
    signature: str
    entities: tuple[str, ...]
    member_alert_ids: tuple[str, ...]
    observed_stage: str | None = None

    @property
    def count(self) -> int:
        return len(self.member_alert_ids)


@dataclass(frozen=True)
class PairCandidate:
    earlier_meta_id: str
    later_meta_id: str
    delta_seconds: float
    shared_entities: tuple[str, ...]
    source: str = "local-window"


def _normalized_entities(entities: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({entity.strip() for entity in entities if entity.strip()}))


def collapse_repeated_alerts(
    alerts: Iterable[ObservableAlert], max_gap_seconds: float = 2.0
) -> list[MetaAlert]:
    """Regroupe les répétitions tout en conservant chaque identifiant original."""

    if max_gap_seconds < 0:
        raise ValueError("max_gap_seconds doit être positif ou nul")

    active: dict[tuple[str, str, tuple[str, ...], str | None], int] = {}
    meta_alerts: list[MetaAlert] = []

    for alert in sorted(alerts, key=lambda item: (item.timestamp, item.alert_id)):
        entities = _normalized_entities(alert.entities)
        key = (alert.sensor, alert.signature, entities, alert.observed_stage)
        active_index = active.get(key)

        if active_index is not None:
            current = meta_alerts[active_index]
            gap = alert.timestamp - current.last_timestamp
            if 0 <= gap <= max_gap_seconds:
                meta_alerts[active_index] = replace(
                    current,
                    last_timestamp=alert.timestamp,
                    member_alert_ids=current.member_alert_ids + (alert.alert_id,),
                )
                continue

        active[key] = len(meta_alerts)
        meta_alerts.append(
            MetaAlert(
                meta_id=f"meta-{len(meta_alerts) + 1}",
                first_timestamp=alert.timestamp,
                last_timestamp=alert.timestamp,
                sensor=alert.sensor,
                signature=alert.signature,
                entities=entities,
                member_alert_ids=(alert.alert_id,),
                observed_stage=alert.observed_stage,
            )
        )

    return sorted(
        meta_alerts, key=lambda item: (item.first_timestamp, item.meta_id)
    )


def iter_local_candidates(
    meta_alerts: Iterable[MetaAlert],
    window_seconds: float = 60.0,
    max_candidates_per_alert: int = 50,
) -> Iterator[PairCandidate]:
    """Génère des paires partageant une entité dans une fenêtre bornée.

    Le tri et le blocage utilisent uniquement des attributs observables. Les
    candidats les plus récents sont retenus lorsque le plafond est atteint.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds doit être strictement positif")
    if max_candidates_per_alert <= 0:
        raise ValueError("max_candidates_per_alert doit être strictement positif")

    ordered = sorted(
        meta_alerts, key=lambda item: (item.first_timestamp, item.meta_id)
    )
    by_entity: dict[str, deque[MetaAlert]] = defaultdict(deque)
    for current in ordered:
        candidates: dict[str, MetaAlert] = {}
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

        for previous in reversed(recent):
            shared = tuple(sorted(set(previous.entities) & set(current.entities)))
            yield PairCandidate(
                earlier_meta_id=previous.meta_id,
                later_meta_id=current.meta_id,
                delta_seconds=max(
                    0.0, current.first_timestamp - previous.last_timestamp
                ),
                shared_entities=shared,
            )

        for entity in current.entities:
            by_entity[entity].append(current)



def generate_local_candidates(
    meta_alerts: Iterable[MetaAlert],
    window_seconds: float = 60.0,
    max_candidates_per_alert: int = 50,
) -> list[PairCandidate]:
    """Compatibilité : matérialise l'itérateur lorsque la taille est petite."""

    return list(
        iter_local_candidates(
            meta_alerts, window_seconds, max_candidates_per_alert
        )
    )

