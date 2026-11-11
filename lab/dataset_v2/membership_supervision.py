"""Politique de provenance et labels forts événement–activité pour V2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker

from .validators import SCHEMA_DIR


MEMBER = "member-verified"
INDEPENDENT = "independent-verified"
UNRESOLVED = "unresolved"
TARGET_TELEMETRY = {
    "linux-journal", "windows-sysmon", "windows-security"
}

MATRIX_MEMBER = "member-verified"
MATRIX_NONMEMBER = "nonmember-verified"
MATRIX_EXCLUDED = "excluded"


def validate_membership_decisions(
    decisions: Sequence[Mapping[str, object]],
    *,
    raw_alert_ids: set[str],
    activity_ids: set[str],
    evidence_ids: set[str],
) -> None:
    """Valide la forme et les invariants scientifiques des décisions."""

    schema = json.loads(
        (SCHEMA_DIR / "membership-decision.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    seen_decisions: set[str] = set()
    seen_alerts: set[str] = set()
    errors: list[str] = []
    for index, item in enumerate(decisions):
        path = f"decisions[{index}]"
        errors.extend(f"{path}: {error.message}" for error in validator.iter_errors(item))
        decision_id = str(item.get("decision_id"))
        alert_id = str(item.get("wazuh_alert_id"))
        if decision_id in seen_decisions:
            errors.append(f"{path}: decision_id dupliqué")
        if alert_id in seen_alerts:
            errors.append(f"{path}: décision multiple pour la même alerte")
        seen_decisions.add(decision_id); seen_alerts.add(alert_id)
        if alert_id not in raw_alert_ids:
            errors.append(f"{path}: alerte brute inconnue")
        unknown_evidence = set(item.get("evidence_ids", [])) - evidence_ids
        if unknown_evidence:
            errors.append(f"{path}: preuves inconnues {sorted(unknown_evidence)}")

        decision = item.get("decision")
        activity_id = item.get("activity_id")
        other_activity_id = item.get("other_activity_id")
        families = set(item.get("proof_families", []))
        ml_use = item.get("ml_use")
        if decision == MEMBER:
            if activity_id not in activity_ids or other_activity_id is not None:
                errors.append(f"{path}: membre vérifié sans activité valide")
            if "execution-receipt" not in families or not (families & TARGET_TELEMETRY):
                errors.append(f"{path}: chemin sans reçu indépendant et télémétrie cible")
            if ml_use not in {"attack-membership-eligible", "verified-benign-negative-only"}:
                errors.append(f"{path}: usage ML incohérent pour un membre")
        elif decision == INDEPENDENT:
            if activity_id not in activity_ids or other_activity_id not in activity_ids:
                errors.append(f"{path}: indépendance sans deux activités connues")
            if activity_id == other_activity_id:
                errors.append(f"{path}: indépendance envers la même activité")
            if "execution-receipt" not in families or not (families & TARGET_TELEMETRY):
                errors.append(f"{path}: indépendance non prouvée techniquement")
            if ml_use != "verified-independent-negative-only":
                errors.append(f"{path}: usage ML incohérent pour une indépendance")
        elif decision == UNRESOLVED:
            if activity_id is not None or other_activity_id is not None:
                errors.append(f"{path}: un événement non résolu ne reçoit aucune activité")
            if ml_use != "excluded-unresolved":
                errors.append(f"{path}: un non-résolu doit être exclu")
    if seen_alerts != raw_alert_ids:
        errors.append("Chaque événement brut doit recevoir exactement une décision")
    if errors:
        raise ValueError("\n".join(errors))


def strong_pair_label(
    left_decision: Mapping[str, object],
    right_decision: Mapping[str, object],
    activities: Mapping[str, Mapping[str, object]],
) -> int | None:
    """Retourne 1/0 pour une paire forte, sinon ``None`` (exclue).

    Deux événements bénins d'une même activité ne deviennent jamais une paire
    positive : le modèle cible l'appartenance à une instance d'attaque.
    """

    if left_decision.get("decision") != MEMBER or right_decision.get("decision") != MEMBER:
        return None
    left = activities.get(str(left_decision.get("activity_id")))
    right = activities.get(str(right_decision.get("activity_id")))
    if not left or not right:
        return None
    left_class, right_class = left.get("class"), right.get("class")
    if left_class == right_class == "attack":
        a, b = left.get("attack_instance_id"), right.get("attack_instance_id")
        if a is None or b is None:
            return None
        return 1 if a == b else 0
    if {left_class, right_class} == {"attack", "benign"}:
        return 0
    if left_class == right_class == "benign":
        a, b = left.get("benign_activity_id"), right.get("benign_activity_id")
        if a is not None and b is not None and a != b:
            return 0
        return None
    return None


def validate_event_activity_matrix(
    decisions: Sequence[Mapping[str, object]],
    *,
    raw_alert_ids: set[str],
    activity_ids: set[str],
    evidence_ids: set[str],
    activity_identity_keys: Mapping[str, str],
) -> None:
    """Valide la matrice complète et les preuves de non-appartenance."""

    schema = json.loads(
        (SCHEMA_DIR / "event-activity-decision.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors: list[str] = []
    index: dict[tuple[str, str], Mapping[str, object]] = {}
    for pos, item in enumerate(decisions):
        path = f"matrix[{pos}]"
        errors.extend(f"{path}: {error.message}" for error in validator.iter_errors(item))
        alert_id = str(item.get("wazuh_alert_id")); studied = str(item.get("studied_activity_id"))
        key = (alert_id, studied)
        if key in index:
            errors.append(f"{path}: décision dupliquée")
        index[key] = item
        if alert_id not in raw_alert_ids or studied not in activity_ids:
            errors.append(f"{path}: événement ou activité inconnu")
        if set(item.get("evidence_ids", [])) - evidence_ids:
            errors.append(f"{path}: preuve inconnue")
    expected = {(event, activity) for event in raw_alert_ids for activity in activity_ids}
    if set(index) != expected:
        errors.append("La matrice événement × activité doit être complète")

    for (alert_id, studied), item in index.items():
        path = f"matrix[{alert_id},{studied}]"; status = item.get("decision")
        provenance = item.get("provenance_activity_id"); identity = item.get("exclusive_identity_key")
        families = set(item.get("proof_families", []))
        if status == MATRIX_MEMBER:
            if provenance != studied or identity != activity_identity_keys.get(studied):
                errors.append(f"{path}: identité membre incohérente")
            if item.get("ml_use") != "verified-member":
                errors.append(f"{path}: usage ML membre invalide")
            if "execution-receipt" not in families or not (families & TARGET_TELEMETRY):
                errors.append(f"{path}: preuve membre insuffisante")
        elif status == MATRIX_NONMEMBER:
            if provenance not in activity_ids or provenance == studied:
                errors.append(f"{path}: autre activité vérifiée obligatoire")
            member = index.get((alert_id, str(provenance)))
            if not member or member.get("decision") != MATRIX_MEMBER:
                errors.append(f"{path}: non-appartenance sans appartenance alternative")
            if identity != activity_identity_keys.get(str(provenance)):
                errors.append(f"{path}: identité de provenance incohérente")
            if activity_identity_keys.get(studied) == identity:
                errors.append(f"{path}: activités non exclusives")
            if item.get("ml_use") != "verified-nonmember":
                errors.append(f"{path}: usage ML non-membre invalide")
        elif status == MATRIX_EXCLUDED:
            if provenance is not None or identity is not None or item.get("ml_use") != "excluded":
                errors.append(f"{path}: exclusion incohérente")
    if errors:
        raise ValueError("\n".join(errors))
