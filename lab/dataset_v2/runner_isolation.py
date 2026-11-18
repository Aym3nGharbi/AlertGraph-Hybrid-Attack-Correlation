"""Garde-fous V2 séparant la télémétrie technique de la fenêtre expérimentale.

Ce module ne modifie ni la compression ni les candidats. Il formalise seulement
les conditions opérationnelles et la vérification de provenance appliquée après
la compression observable.
"""

from __future__ import annotations

from typing import Iterable, Mapping


DEFAULT_COLLAPSE_SECONDS = 2.0
DEFAULT_STABILIZATION_SECONDS = 3.0


def default_runner_isolation_policy() -> dict[str, object]:
    return {
        "preflight_before_experimental_window": True,
        "observers_open_before_experimental_window": True,
        "technical_tuples_must_be_captured": True,
        "diagnostic_connections_during_window": False,
        "collapse_seconds_unchanged": DEFAULT_COLLAPSE_SECONDS,
        "stabilization_after_ready_seconds": DEFAULT_STABILIZATION_SECONDS,
        "mixed_provenance_meta_action": "exclude-from-strict-supervision",
    }


def validate_runner_isolation_policy(
    policy: Mapping[str, object], *, collapse_seconds: float = DEFAULT_COLLAPSE_SECONDS,
) -> dict[str, object]:
    required_true = (
        "preflight_before_experimental_window",
        "observers_open_before_experimental_window",
        "technical_tuples_must_be_captured",
    )
    for name in required_true:
        if policy.get(name) is not True:
            raise ValueError(f"garde-fou d'isolation absent: {name}")
    if policy.get("diagnostic_connections_during_window") is not False:
        raise ValueError("les connexions de diagnostic sont interdites pendant la fenêtre")
    if policy.get("mixed_provenance_meta_action") != "exclude-from-strict-supervision":
        raise ValueError("une méta-alerte mixte doit être exclue de la supervision stricte")
    declared_collapse = float(policy.get("collapse_seconds_unchanged", -1))
    if declared_collapse != float(collapse_seconds):
        raise ValueError("le runner ne doit pas modifier le seuil de compression")
    stabilization = float(policy.get("stabilization_after_ready_seconds", -1))
    if stabilization <= declared_collapse:
        raise ValueError("la stabilisation doit dépasser strictement la fenêtre de compression")
    return {
        "collapse_seconds": declared_collapse,
        "stabilization_seconds": stabilization,
        "training_ready": False,
    }


def classify_meta_provenance(
    member_alert_ids: Iterable[str],
    event_decisions: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    """Vérifie l'exclusivité après compression, sans influencer les features."""

    members = [str(value) for value in member_alert_ids]
    if not members:
        return {"eligible": False, "reason": "empty-meta-alert", "activity_id": None}
    if any(value not in event_decisions for value in members):
        return {"eligible": False, "reason": "unverified-member-event", "activity_id": None}
    rows = [event_decisions[value] for value in members]
    if any(row.get("decision") != "member-verified" for row in rows):
        return {
            "eligible": False,
            "reason": "mixed-member-and-technical-or-excluded-provenance",
            "activity_id": None,
        }
    activities = {str(row.get("activity_id") or "") for row in rows}
    if "" in activities or len(activities) != 1:
        return {"eligible": False, "reason": "multiple-or-missing-activity-provenance", "activity_id": None}
    return {"eligible": True, "reason": "exclusive-verified-activity-provenance", "activity_id": next(iter(activities))}


def technical_session_receipt(
    *, role: str, process_id: int, connection_tuple: Mapping[str, object],
    opened_before_experimental_window: bool,
) -> dict[str, object]:
    required = ("source_ip", "source_port", "target_ip", "target_port")
    if not role or process_id <= 0 or any(name not in connection_tuple for name in required):
        raise ValueError("identité technique incomplète")
    if not opened_before_experimental_window:
        raise ValueError("une session technique ne doit pas être ouverte dans la fenêtre")
    return {
        "role": role,
        "process_id": process_id,
        "connection_tuple": {name: connection_tuple[name] for name in required},
        "opened_before_experimental_window": True,
        "eligible_for_supervision": False,
    }
