"""Contexte topologique strictement antérieur dans le graphe des candidats."""

from __future__ import annotations

import math
from collections.abc import Iterable


GRAPH_CONTEXT_FEATURE_NAMES = (
    "earlier_log1p_prior_candidate_degree",
    "later_log1p_prior_candidate_degree",
    "log1p_common_prior_candidate_count",
    "prior_candidate_jaccard",
)


def predecessor_index(
    edges: Iterable[tuple[str, str]],
) -> dict[str, set[str]]:
    """Indexe les prédécesseurs candidats sans utiliser labels ou scores ML."""

    predecessors: dict[str, set[str]] = {}
    for earlier, later in edges:
        predecessors.setdefault(earlier, set())
        predecessors.setdefault(later, set()).add(earlier)
    return predecessors


def pair_graph_context(
    earlier: str,
    later: str,
    predecessors: dict[str, set[str]],
) -> tuple[float, float, float, float]:
    """Décrit la paire avec son voisinage disponible à l'arrivée de `later`."""

    earlier_neighbors = predecessors.get(earlier, set())
    later_neighbors = predecessors.get(later, set())
    common_count = len(earlier_neighbors & later_neighbors)
    union_count = len(earlier_neighbors | later_neighbors)
    return (
        math.log1p(len(earlier_neighbors)),
        math.log1p(len(later_neighbors)),
        math.log1p(common_count),
        common_count / union_count if union_count else 0.0,
    )
