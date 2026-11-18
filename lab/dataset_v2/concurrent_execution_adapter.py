"""Normalise les rapports séquentiels et concurrents sans altérer leur source."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from .io_utils import load_json, sha256_file, write_new_json


LEGACY_DIR = "execution-multiphase-fim-v2"
CONCURRENT_DIR = "execution-concurrent-multiphase-fim-v2"


def locate_execution(campaign: str | Path) -> tuple[Path, str]:
    campaign = Path(campaign)
    found = [(campaign / name, name) for name in (CONCURRENT_DIR, LEGACY_DIR)
             if (campaign / name / "execution-report.json").is_file()]
    if len(found) != 1:
        raise ValueError(f"exactement une exécution est requise, trouvé={len(found)}")
    return found[0]


def normalize_execution_report(report: Mapping[str, object], source_name: str) -> dict[str, object]:
    if source_name == LEGACY_DIR:
        rows = list(report.get("completed_activities") or [])
    elif source_name == CONCURRENT_DIR:
        rows = list((report.get("schedule") or {}).get("activities") or [])
    else:
        raise ValueError("source d'exécution inconnue")
    completed = []
    for row in rows:
        if row.get("status") != "completed" and source_name == CONCURRENT_DIR:
            continue
        result = dict(row.get("result") or {})
        completed.append({
            "activity_key": row["activity_key"],
            "planned_offset_seconds": row.get("planned_offset_seconds"),
            "actual_start_offset_seconds": row.get("actual_start_offset_seconds"),
            "completed_offset_seconds": row.get("completed_offset_seconds"),
            "receipt": result.get("receipt", row.get("receipt")),
            "proof_ok": result.get("proof_ok", row.get("proof_ok", False)),
            "source_status": row.get("status", "completed"),
        })
    failed_or_cancelled = [dict(row) for row in rows if row.get("status") in {
        "failed", "cancelled-before-start", "start-lateness-exceeded"
    }]
    starts = [float(row["actual_start_offset_seconds"]) for row in completed if row.get("actual_start_offset_seconds") is not None]
    ends = [float(row["completed_offset_seconds"]) for row in completed if row.get("completed_offset_seconds") is not None]
    normalized = dict(report)
    normalized.update({
        "execution_contract": "alertgraph-normalized-multiphase-execution/2.0",
        "source_execution_directory": source_name,
        "completed_activities": completed,
        "completed_activity_count": len(completed),
        "failed_or_cancelled_activities": failed_or_cancelled,
        "all_sealed_activities_completed": len(completed) == int(report.get("expected_activity_count", 7)) and not failed_or_cancelled,
        "actual_activity_span_seconds": max(ends) - min(starts) if starts and ends else None,
    })
    if failed_or_cancelled:
        normalized["status"] = "failed"
    return normalized


def load_normalized_execution(campaign: str | Path, *, persist_adapter: bool = False):
    directory, source = locate_execution(campaign)
    raw_path = directory / "execution-report.json"
    normalized = normalize_execution_report(load_json(raw_path), source)
    normalized["source_execution_report_sha256"] = sha256_file(raw_path)
    if persist_adapter:
        write_new_json(directory / "normalized-execution-report.json", normalized)
    return normalized, directory
