"""Accélération observable et historique causal strictement antérieur."""

from __future__ import annotations

import math
from collections import defaultdict

import pandas as pd

from causal_bridges import progression_compatible


ACCELERATION_FEATURE_NAMES = (
    "earlier_activity_acceleration_2s_10s",
    "earlier_activity_acceleration_10s_60s",
    "earlier_activity_acceleration_60s_150s",
    "later_activity_acceleration_2s_10s",
    "later_activity_acceleration_10s_60s",
    "later_activity_acceleration_60s_150s",
)

HISTORY_FEATURE_NAMES = (
    "earlier_compatible_history_known",
    "earlier_log1p_compatible_history_count",
    "earlier_compatible_history_distinct_stages",
    "later_compatible_history_known",
    "later_log1p_compatible_history_count",
    "later_compatible_history_distinct_stages",
)

ADVANCED_CONTEXT_FEATURE_NAMES = (
    *ACCELERATION_FEATURE_NAMES,
    *HISTORY_FEATURE_NAMES,
)


def activity_accelerations(d2: int, d10: int, d60: int, d150: int) -> tuple[float, float, float]:
    """Différences signées entre taux antérieurs courts et longs."""

    rates = (
        math.log1p(d2 / 2.0),
        math.log1p(d10 / 10.0),
        math.log1p(d60 / 60.0),
        math.log1p(d150 / 150.0),
    )
    return rates[0] - rates[1], rates[1] - rates[2], rates[2] - rates[3]


def meta_advanced_context(meta: pd.DataFrame) -> dict[str, dict[str, float | int]]:
    """Calcule le contexte de chaque nœud avant de mettre à jour son état."""

    state: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    result: dict[str, dict[str, float | int]] = {}
    ordered = meta.sort_values(["first_timestamp", "meta_id"])
    for row in ordered.itertuples(index=False):
        acceleration = activity_accelerations(
            row.prior_entity_density_2s,
            row.prior_entity_density_10s,
            row.prior_entity_density_60s,
            row.prior_entity_density_150s,
        )
        stage_known = bool(row.observed_stage) and row.observed_stage != "NON_MALICIOUS"
        strongest_count = 0
        strongest_distinct = 0
        if stage_known:
            for entity in row.entities:
                compatible = {
                    stage: count
                    for stage, count in state[entity].items()
                    if progression_compatible(stage, row.observed_stage)
                }
                strongest_count = max(strongest_count, sum(compatible.values()))
                strongest_distinct = max(strongest_distinct, len(compatible))
        result[row.meta_id] = {
            "activity_acceleration_2s_10s": acceleration[0],
            "activity_acceleration_10s_60s": acceleration[1],
            "activity_acceleration_60s_150s": acceleration[2],
            "compatible_history_known": int(stage_known),
            "log1p_compatible_history_count": math.log1p(strongest_count),
            "compatible_history_distinct_stages": strongest_distinct,
        }

        if stage_known:
            raw_members = len(row.member_alert_ids)
            for entity in row.entities:
                state[entity][row.observed_stage] += raw_members
    return result
