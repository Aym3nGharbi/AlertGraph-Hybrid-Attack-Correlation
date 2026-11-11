"""Caractéristiques observables et supervision séparée pour une paire."""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass

from audit_pair_candidates import AuditedMetaAlert
from candidates import PairCandidate
from causal_bridges import progression_compatible


_TOKEN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class PairFeatures:
    delta_seconds: float
    log1p_delta_seconds: float
    local_window_evidence: int
    causal_bridge_evidence: int
    shared_entity_count: int
    shared_host_count: int
    shared_ip_count: int
    entity_jaccard: float
    same_sensor: int
    same_signature: int
    signature_text_jaccard: float
    protocol_known_both: int
    protocol_overlap: int
    service_known_both: int
    service_overlap: int
    severity_known_both: int
    severity_distance: float
    stage_known_both: int
    same_stage: int
    forward_progression_compatible: int
    non_malicious_stage_present: int
    tactic_known_both: int
    tactic_jaccard: float
    network_direction_known_both: int
    shared_source_ip_count: int
    shared_destination_ip_count: int
    forward_network_handoff_count: int
    reverse_network_handoff_count: int
    earlier_log1p_entity_density_2s: float
    earlier_log1p_entity_density_10s: float
    earlier_log1p_entity_density_60s: float
    earlier_log1p_entity_density_150s: float
    later_log1p_entity_density_2s: float
    later_log1p_entity_density_10s: float
    later_log1p_entity_density_60s: float
    later_log1p_entity_density_150s: float
    same_signature_gap_known: int
    log1p_same_signature_gap_seconds: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PairSupervision:
    target: int | None
    confidence: str
    reason: str


@dataclass(frozen=True)
class PairExample:
    earlier_meta_id: str
    later_meta_id: str
    features: PairFeatures
    supervision: PairSupervision


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _tokens(value: str) -> set[str]:
    return set(_TOKEN.findall(value.casefold()))


def make_pair_features(
    earlier: AuditedMetaAlert,
    later: AuditedMetaAlert,
    candidate: PairCandidate,
) -> PairFeatures:
    """Calcule uniquement des variables disponibles en production."""

    left_entities = set(earlier.entities)
    right_entities = set(later.entities)
    shared = left_entities & right_entities
    protocols_left, protocols_right = set(earlier.protocols), set(later.protocols)
    services_left, services_right = set(earlier.services), set(later.services)
    tactics_left = set(earlier.observed_tactics)
    tactics_right = set(later.observed_tactics)
    src_left, src_right = set(earlier.src_ips), set(later.src_ips)
    dst_left, dst_right = set(earlier.dst_ips), set(later.dst_ips)
    stages_known = earlier.observed_stage is not None and later.observed_stage is not None
    severity_known = earlier.max_severity is not None and later.max_severity is not None
    sources = set(candidate.source.split("+"))

    return PairFeatures(
        delta_seconds=candidate.delta_seconds,
        log1p_delta_seconds=math.log1p(candidate.delta_seconds),
        local_window_evidence=int("local-window" in sources),
        causal_bridge_evidence=int("causal-bridge" in sources),
        shared_entity_count=len(shared),
        shared_host_count=sum(item.startswith("host:") for item in shared),
        shared_ip_count=sum(item.startswith("ip:") for item in shared),
        entity_jaccard=_jaccard(left_entities, right_entities),
        same_sensor=int(earlier.sensor == later.sensor),
        same_signature=int(
            earlier.sensor == later.sensor and earlier.signature == later.signature
        ),
        signature_text_jaccard=_jaccard(
            _tokens(earlier.signature_text), _tokens(later.signature_text)
        ),
        protocol_known_both=int(bool(protocols_left and protocols_right)),
        protocol_overlap=int(bool(protocols_left & protocols_right)),
        service_known_both=int(bool(services_left and services_right)),
        service_overlap=int(bool(services_left & services_right)),
        severity_known_both=int(severity_known),
        severity_distance=(
            float(abs(earlier.max_severity - later.max_severity))
            if severity_known
            else 0.0
        ),
        stage_known_both=int(stages_known),
        same_stage=int(
            stages_known and earlier.observed_stage == later.observed_stage
        ),
        forward_progression_compatible=int(
            progression_compatible(earlier.observed_stage, later.observed_stage)
        ),
        non_malicious_stage_present=int(
            "NON_MALICIOUS" in {earlier.observed_stage, later.observed_stage}
        ),
        tactic_known_both=int(bool(tactics_left and tactics_right)),
        tactic_jaccard=_jaccard(tactics_left, tactics_right),
        network_direction_known_both=int(
            bool((src_left or dst_left) and (src_right or dst_right))
        ),
        shared_source_ip_count=len(src_left & src_right),
        shared_destination_ip_count=len(dst_left & dst_right),
        forward_network_handoff_count=len(dst_left & src_right),
        reverse_network_handoff_count=len(src_left & dst_right),
        earlier_log1p_entity_density_2s=math.log1p(
            earlier.prior_entity_density_2s
        ),
        earlier_log1p_entity_density_10s=math.log1p(
            earlier.prior_entity_density_10s
        ),
        earlier_log1p_entity_density_60s=math.log1p(
            earlier.prior_entity_density_60s
        ),
        earlier_log1p_entity_density_150s=math.log1p(
            earlier.prior_entity_density_150s
        ),
        later_log1p_entity_density_2s=math.log1p(later.prior_entity_density_2s),
        later_log1p_entity_density_10s=math.log1p(
            later.prior_entity_density_10s
        ),
        later_log1p_entity_density_60s=math.log1p(
            later.prior_entity_density_60s
        ),
        later_log1p_entity_density_150s=math.log1p(
            later.prior_entity_density_150s
        ),
        same_signature_gap_known=int(
            later.seconds_since_same_signature_entity is not None
        ),
        log1p_same_signature_gap_seconds=(
            math.log1p(later.seconds_since_same_signature_entity)
            if later.seconds_since_same_signature_entity is not None
            else 0.0
        ),
    )


def make_pair_supervision(
    earlier: AuditedMetaAlert, later: AuditedMetaAlert
) -> PairSupervision:
    """Construit la cible sans l'injecter dans les caractéristiques."""

    if earlier.truth_is_mixed or later.truth_is_mixed:
        return PairSupervision(None, "unknown", "mixed-meta-alert")
    if earlier.is_attack is None or later.is_attack is None:
        return PairSupervision(None, "unknown", "unknown-alert-label")
    confidence = (
        "high"
        if earlier.truth_confidence == later.truth_confidence == "high"
        else "weak"
    )
    if earlier.is_attack and later.is_attack:
        if earlier.attack_instance_id == later.attack_instance_id:
            return PairSupervision(1, confidence, "same-attack-instance")
        return PairSupervision(0, confidence, "different-attack-instances")
    if earlier.is_attack != later.is_attack:
        return PairSupervision(0, confidence, "attack-versus-benign")
    return PairSupervision(0, confidence, "benign-pair")


def make_pair_example(
    earlier: AuditedMetaAlert,
    later: AuditedMetaAlert,
    candidate: PairCandidate,
) -> PairExample:
    return PairExample(
        earlier_meta_id=earlier.meta_id,
        later_meta_id=later.meta_id,
        features=make_pair_features(earlier, later, candidate),
        supervision=make_pair_supervision(earlier, later),
    )
