"""Agrège les matrices V2 sans transformer les données brutes."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from .build_event_activity_matrix import OUTPUT_DIR
from .io_utils import load_json, utc_now, write_new_json


def _jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def evaluate(root: str | Path, output: str | Path) -> dict[str, object]:
    root = Path(root); rows = []
    for report_path in sorted(root.glob(f"campaigns/*/*/{OUTPUT_DIR}/report.json")):
        campaign_dir = report_path.parents[1]
        report = load_json(report_path)
        decisions = _jsonl(report_path.with_name("decisions.jsonl"))
        events = _jsonl(campaign_dir / "raw" / "alerts.jsonl")
        by_id = {str(x["id"]): x for x in events}
        member_events = {str(x["wazuh_alert_id"]) for x in decisions if x["decision"] == "member-verified"}
        excluded_events = {str(x["wazuh_alert_id"]) for x in decisions if x["decision"] == "excluded"}
        event_types = defaultdict(Counter)
        for category, ids in (("member", member_events), ("excluded", excluded_events)):
            for alert_id in ids:
                event = by_id[alert_id]
                rule = event.get("rule") or {}
                data = event.get("data") or {}; win = data.get("win") or {}; system = win.get("system") or {}
                key = f"rule:{rule.get('id')}|event:{system.get('eventID', 'n/a')}|{rule.get('description', '')}"
                event_types[category][key] += 1
        per_activity = {}
        for decision in decisions:
            activity = str(decision["studied_activity_id"])
            per_activity.setdefault(activity, Counter())[str(decision["decision"])] += 1
        historical = None
        old_path = campaign_dir / "membership-review-evidence-graph-v2" / "review-manifest.json"
        if old_path.exists():
            old = load_json(old_path)
            historical = {
                "previous_member_verified": old["member_verified"],
                "previous_independent_verified": old["independent_verified"],
                "previous_unresolved": old["unresolved"],
            }
        rows.append({
            "campaign_id": report["campaign_id"], "run_id": report["run_id"],
            "raw_events": report["raw_events"], "activities": report["activities"],
            "matrix_cells": report["matrix_cells"], "member_verified": report["member-verified"],
            "nonmember_verified": report["nonmember-verified"], "excluded": report["excluded"],
            "resolved_cells_percent": report["resolved_cells_percent"],
            "events_with_verified_provenance": len(member_events),
            "event_resolution_percent": round(100 * len(member_events) / len(events), 3) if events else 0,
            "cross_associations": report["cross_associations"],
            "per_activity": {k: dict(v) for k, v in per_activity.items()},
            "member_event_types": dict(event_types["member"]),
            "excluded_event_types": dict(event_types["excluded"]),
            "historical_comparison": historical,
        })
    result = {
        "schema_version": "alertgraph-event-activity-matrix-comparison/2.0-experimental",
        "created_at_utc": utc_now(), "campaigns": rows,
        "totals": {
            "campaigns": len(rows), "raw_events": sum(x["raw_events"] for x in rows),
            "matrix_cells": sum(x["matrix_cells"] for x in rows),
            "member_verified": sum(x["member_verified"] for x in rows),
            "nonmember_verified": sum(x["nonmember_verified"] for x in rows),
            "excluded": sum(x["excluded"] for x in rows),
            "cross_associations": sum(x["cross_associations"] for x in rows),
        },
        "scientific_scope": "development-only; no independent generalization claim",
        "training_ready": False,
    }
    write_new_json(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path); parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.root, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
