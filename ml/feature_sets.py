"""Profils explicites de caractéristiques pour les expériences reproductibles."""

from __future__ import annotations

from advanced_context import ACCELERATION_FEATURE_NAMES, HISTORY_FEATURE_NAMES


DIRECTION_FEATURES = frozenset(
    {
        "network_direction_known_both",
        "shared_source_ip_count",
        "shared_destination_ip_count",
        "forward_network_handoff_count",
        "reverse_network_handoff_count",
    }
)

CONTEXT_FEATURES = frozenset(
    {
        "earlier_log1p_entity_density_2s",
        "earlier_log1p_entity_density_10s",
        "earlier_log1p_entity_density_60s",
        "earlier_log1p_entity_density_150s",
        "later_log1p_entity_density_2s",
        "later_log1p_entity_density_10s",
        "later_log1p_entity_density_60s",
        "later_log1p_entity_density_150s",
        "same_signature_gap_known",
        "log1p_same_signature_gap_seconds",
    }
)

GRAPH_CONTEXT_FEATURES = frozenset(
    {
        "earlier_log1p_prior_candidate_degree",
        "later_log1p_prior_candidate_degree",
        "log1p_common_prior_candidate_count",
        "prior_candidate_jaccard",
    }
)

ACCELERATION_FEATURES = frozenset(ACCELERATION_FEATURE_NAMES)
HISTORY_FEATURES = frozenset(HISTORY_FEATURE_NAMES)
ADVANCED_CONTEXT_FEATURES = ACCELERATION_FEATURES | HISTORY_FEATURES

# Signaux de compatibilité de progression. Les étapes observables viennent des
# règles/signatures disponibles au moment de l'alerte, jamais de la vérité
# terrain annotée après le scénario.
CAUSALITY_FEATURES = frozenset(
    {
        "causal_bridge_evidence",
        "stage_known_both",
        "same_stage",
        "forward_progression_compatible",
        "non_malicious_stage_present",
        "tactic_known_both",
        "tactic_jaccard",
    }
)

MITRE_FEATURES = frozenset({"tactic_known_both", "tactic_jaccard"})

# Cette ablation retire l'identité brute et la ressemblance lexicale de la
# signature, mais conserve son mapping causal fixe et auditable vers une étape.
SIGNATURE_TEXT_FEATURES = frozenset(
    {
        "same_signature",
        "signature_text_jaccard",
        "same_signature_gap_known",
        "log1p_same_signature_gap_seconds",
    }
)

SCIENTIFIC_ABLATION_PROFILES = (
    "similarity_only",
    "causality_only",
    "hybrid",
    "hybrid_without_mitre",
    "hybrid_without_signature_text",
)

FEATURE_PROFILES = (
    "all",
    "directional",
    "directional_graph",
    "directional_acceleration",
    "directional_history",
    "directional_acceleration_history",
    "context",
    "legacy",
)


def select_feature_profile(
    available: tuple[str, ...], profile: str
) -> tuple[str, ...]:
    if profile not in FEATURE_PROFILES:
        raise ValueError(f"Profil inconnu: {profile}")
    excluded = {
        "all": frozenset(),
        "directional": CONTEXT_FEATURES | GRAPH_CONTEXT_FEATURES | ADVANCED_CONTEXT_FEATURES,
        "directional_graph": CONTEXT_FEATURES | ADVANCED_CONTEXT_FEATURES,
        "directional_acceleration": CONTEXT_FEATURES | GRAPH_CONTEXT_FEATURES | HISTORY_FEATURES,
        "directional_history": CONTEXT_FEATURES | GRAPH_CONTEXT_FEATURES | ACCELERATION_FEATURES,
        "directional_acceleration_history": CONTEXT_FEATURES | GRAPH_CONTEXT_FEATURES,
        "context": DIRECTION_FEATURES,
        "legacy": DIRECTION_FEATURES | CONTEXT_FEATURES | GRAPH_CONTEXT_FEATURES | ADVANCED_CONTEXT_FEATURES,
    }[profile]
    return tuple(name for name in available if name not in excluded)


def select_scientific_ablation_profile(
    available: tuple[str, ...], profile: str
) -> tuple[str, ...]:
    """Construit les profils de l'ablation hybride verrouillée."""

    if profile not in SCIENTIFIC_ABLATION_PROFILES:
        raise ValueError(f"Profil d'ablation inconnu: {profile}")

    # L'hybride de référence est le profil directionnel retenu par l'ablation
    # v2, sans les densités/gaps qui n'ont pas amélioré la généralisation.
    hybrid = select_feature_profile(available, "directional")
    if profile == "similarity_only":
        return tuple(name for name in hybrid if name not in CAUSALITY_FEATURES)
    if profile == "causality_only":
        return tuple(name for name in hybrid if name in CAUSALITY_FEATURES)
    if profile == "hybrid_without_mitre":
        return tuple(name for name in hybrid if name not in MITRE_FEATURES)
    if profile == "hybrid_without_signature_text":
        return tuple(name for name in hybrid if name not in SIGNATURE_TEXT_FEATURES)
    return hybrid

