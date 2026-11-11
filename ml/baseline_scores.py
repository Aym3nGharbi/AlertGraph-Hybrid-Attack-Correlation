"""Scores déterministes de similarité, causalité et hybride manuel."""

from __future__ import annotations

import math
from collections.abc import Mapping


def similarity_score(features: Mapping[str, float], window_seconds: float = 60.0) -> float:
    if window_seconds <= 0:
        raise ValueError("window_seconds doit être strictement positif")
    delta = float(features["delta_seconds"])
    temporal = (
        math.exp(-delta / max(window_seconds / 3.0, 1.0))
        if delta <= window_seconds
        else 0.0
    )
    network = float(features["shared_ip_count"] > 0)
    host = float(features["shared_host_count"] > 0)
    service = float(features["service_overlap"])
    semantic = float(features["signature_text_jaccard"])
    return min(
        1.0,
        0.35 * network
        + 0.15 * host
        + 0.10 * service
        + 0.15 * semantic
        + 0.25 * temporal,
    )


def causal_score(features: Mapping[str, float]) -> float:
    """Compatibilité observable ; ce score n'affirme pas une causalité réelle."""

    if features["non_malicious_stage_present"]:
        return 0.05
    if not features["stage_known_both"]:
        return 0.15
    if features["forward_progression_compatible"]:
        return 1.0
    if features["same_stage"]:
        return 0.55
    return 0.05


def manual_hybrid_score(
    features: Mapping[str, float],
    alpha: float = 0.65,
    window_seconds: float = 60.0,
) -> float:
    if not 0 <= alpha <= 1:
        raise ValueError("alpha doit être compris entre 0 et 1")
    similarity = similarity_score(features, window_seconds)
    causal = causal_score(features)
    return alpha * similarity + (1.0 - alpha) * causal

