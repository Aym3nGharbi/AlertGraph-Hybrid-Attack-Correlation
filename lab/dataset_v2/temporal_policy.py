"""Validation partagée des politiques temporelles préenregistrées."""

from __future__ import annotations

from typing import Mapping


DEFAULT_TEMPORAL_POLICY = {
    "max_abs_offset_ms": 1000.0,
    "max_uncertainty_ms": 500.0,
    "require_synchronized": True,
    "required_roles": [
        "controller",
        "wazuh-manager",
        "linux-target",
        "windows-target",
    ],
}


def validate_temporal_policy(policy: Mapping[str, object]) -> dict[str, object]:
    required = {
        "max_abs_offset_ms",
        "max_uncertainty_ms",
        "require_synchronized",
        "required_roles",
    }
    if set(policy) != required:
        raise ValueError(
            f"Politique temporelle invalide: champs attendus {sorted(required)}"
        )
    result = dict(policy)
    for field in ("max_abs_offset_ms", "max_uncertainty_ms"):
        value = result[field]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{field} doit être un nombre positif ou nul")
        result[field] = float(value)
    if not isinstance(result["require_synchronized"], bool):
        raise ValueError("require_synchronized doit être booléen")
    roles = result["required_roles"]
    allowed = {"controller", "wazuh-manager", "linux-target", "windows-target"}
    if (
        not isinstance(roles, list)
        or len(roles) != len(set(roles))
        or not set(roles) <= allowed
    ):
        raise ValueError("required_roles invalide")
    return result
