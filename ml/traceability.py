"""Contrôle de la compression réversible des alertes Wazuh."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable


def audit_traceability(
    raw_alert_ids: Iterable[str],
    meta_member_ids: Iterable[Iterable[str]],
) -> dict[str, object]:
    raw = [str(value) for value in raw_alert_ids]
    members = [str(value) for group in meta_member_ids for value in group]
    raw_counts = Counter(raw)
    member_counts = Counter(members)
    duplicate_raw = sorted(value for value, count in raw_counts.items() if count != 1)
    duplicate_members = sorted(
        value for value, count in member_counts.items() if count != 1
    )
    missing = sorted(set(raw_counts) - set(member_counts))
    unexpected = sorted(set(member_counts) - set(raw_counts))
    complete = not (duplicate_raw or duplicate_members or missing or unexpected)
    return {
        "complete": complete,
        "raw_alerts": len(raw),
        "unique_raw_alerts": len(raw_counts),
        "member_references": len(members),
        "unique_member_references": len(member_counts),
        "missing_alert_ids": missing,
        "unexpected_alert_ids": unexpected,
        "duplicate_raw_alert_ids": duplicate_raw,
        "duplicate_member_alert_ids": duplicate_members,
        "coverage": len(set(raw_counts) & set(member_counts)) / len(raw_counts)
        if raw_counts
        else 1.0,
    }


def require_complete_traceability(report: dict[str, object]) -> None:
    if not report["complete"]:
        raise ValueError(
            "Compression non réversible: "
            f"missing={len(report['missing_alert_ids'])}, "
            f"unexpected={len(report['unexpected_alert_ids'])}, "
            f"duplicate_members={len(report['duplicate_member_alert_ids'])}"
        )
