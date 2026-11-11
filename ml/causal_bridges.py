"""Ponts de progression compatibles basés uniquement sur des observations."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from candidates import MetaAlert, PairCandidate


DISCOVERY = frozenset({"HOST_DISC", "SERVICE_DISC", "VULN_DISC", "INFO_DISC"})
ACCESS = frozenset(
    {
        "BRUTE_FORCE_CREDS", "PUBLIC_APP_EXP", "REMOTE_SERVICE_EXP",
        "SERVICE_SPECIFIC", "VALID_ACCOUNT_ACCESS",
    }
)
POST_ACCESS = frozenset(
    {
        "USER_PRIV_ESC", "ROOT_PRIV_ESC", "PRIV_ESC",
        "ARBITRARY_CODE_EXE", "PERSISTENCE",
    }
)
CONTROL = frozenset({"DEFENSE_EVASION", "COMMAND_AND_CONTROL", "LATERAL_MOVEMENT"})
OUTCOME = frozenset({"DATA_EXFILTRATION", "SERVICE_STOP", "NETWORK_DOS", "END_POINT_DOS"})


def _transition_table() -> dict[str, frozenset[str]]:
    transitions: dict[str, frozenset[str]] = {}
    for stage in DISCOVERY:
        transitions[stage] = ACCESS
    for stage in ACCESS:
        transitions[stage] = POST_ACCESS | CONTROL | OUTCOME
    for stage in POST_ACCESS:
        transitions[stage] = CONTROL | OUTCOME
    for stage in CONTROL:
        transitions[stage] = CONTROL | OUTCOME
    return transitions


COMPATIBLE_SUCCESSORS = _transition_table()


def progression_compatible(earlier_stage: str | None, later_stage: str | None) -> bool:
    if not earlier_stage or not later_stage:
        return False
    if "NON_MALICIOUS" in {earlier_stage, later_stage}:
        return False
    return later_stage in COMPATIBLE_SUCCESSORS.get(earlier_stage, frozenset())


def generate_causal_bridges(
    meta_alerts: Iterable[MetaAlert],
    max_bridges_per_alert: int = 5,
    max_age_seconds: float | None = None,
) -> list[PairCandidate]:
    """Relie les derniers types compatibles sur une entité commune.

    L'index garde au plus une méta-alerte par couple entité/étape. ATT&CK n'est
    pas traité comme une séquence ordonnée ; seules les transitions explicites
    ci-dessus sont considérées comme des indices de progression possibles.
    """

    if max_bridges_per_alert <= 0:
        raise ValueError("max_bridges_per_alert doit être strictement positif")
    if max_age_seconds is not None and max_age_seconds <= 0:
        raise ValueError("max_age_seconds doit être positif ou None")

    ordered = sorted(
        meta_alerts, key=lambda item: (item.first_timestamp, item.meta_id)
    )
    latest: dict[str, dict[str, MetaAlert]] = defaultdict(dict)
    bridges: list[PairCandidate] = []

    for current in ordered:
        if not current.observed_stage or current.observed_stage == "NON_MALICIOUS":
            continue

        possible: dict[str, MetaAlert] = {}
        for entity in current.entities:
            for stage, previous in latest[entity].items():
                if progression_compatible(stage, current.observed_stage):
                    possible[previous.meta_id] = previous

        ranked = sorted(
            possible.values(),
            key=lambda item: (item.last_timestamp, item.meta_id),
            reverse=True,
        )
        selected = []
        for previous in ranked:
            delta = max(0.0, current.first_timestamp - previous.last_timestamp)
            if max_age_seconds is not None and delta > max_age_seconds:
                continue
            selected.append(previous)
            if len(selected) >= max_bridges_per_alert:
                break

        for previous in reversed(selected):
            bridges.append(
                PairCandidate(
                    earlier_meta_id=previous.meta_id,
                    later_meta_id=current.meta_id,
                    delta_seconds=max(
                        0.0, current.first_timestamp - previous.last_timestamp
                    ),
                    shared_entities=tuple(
                        sorted(set(previous.entities) & set(current.entities))
                    ),
                    source="causal-bridge",
                )
            )

        for entity in current.entities:
            latest[entity][current.observed_stage] = current

    return bridges


def merge_candidate_sources(
    *candidate_sets: Iterable[PairCandidate],
) -> list[PairCandidate]:
    merged: dict[tuple[str, str], PairCandidate] = {}
    sources: dict[tuple[str, str], set[str]] = defaultdict(set)

    for candidate_set in candidate_sets:
        for candidate in candidate_set:
            key = (candidate.earlier_meta_id, candidate.later_meta_id)
            sources[key].add(candidate.source)
            if key not in merged:
                merged[key] = candidate
            else:
                previous = merged[key]
                merged[key] = PairCandidate(
                    earlier_meta_id=key[0],
                    later_meta_id=key[1],
                    delta_seconds=min(previous.delta_seconds, candidate.delta_seconds),
                    shared_entities=tuple(
                        sorted(
                            set(previous.shared_entities)
                            | set(candidate.shared_entities)
                        )
                    ),
                    source=previous.source,
                )

    return [
        PairCandidate(
            earlier_meta_id=pair.earlier_meta_id,
            later_meta_id=pair.later_meta_id,
            delta_seconds=pair.delta_seconds,
            shared_entities=pair.shared_entities,
            source="+".join(sorted(sources[key])),
        )
        for key, pair in sorted(merged.items())
    ]

