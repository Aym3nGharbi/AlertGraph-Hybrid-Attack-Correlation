#!/usr/bin/env python3
"""Propose des labels traçables; les alertes non prouvées restent inconnues."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


def timestamp(value: str) -> float:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(text).timestamp()


def classified_phase(alert: dict, run_id: str) -> tuple[str, str] | None:
    rule = alert.get("rule", {})
    description = str(rule.get("description", "")).casefold()
    groups = {str(x).casefold() for x in rule.get("groups", [])}
    raw = json.dumps(alert, ensure_ascii=False).casefold()
    rule_id = str(rule.get("id"))
    if run_id.casefold() in raw and rule_id == "553":
        return "defense_evasion", "unique canary path + FIM deletion rule"
    if run_id.casefold() in raw and rule_id in {"550", "554"}:
        return "execution", "unique canary path + FIM create/change rule"
    if rule_id == "5402" or "successful sudo" in description:
        return "privilege_escalation", "sudo rule during controlled interval"
    if rule_id in {"5710", "5712", "5715", "40112"}:
        return "initial_access", "SSH authentication rule during controlled interval"
    if rule_id in {"5501", "5502"}:
        return "initial_access", "PAM session created by scenario SSH orchestration"
    if "authentication_failed" in groups or "invalid user" in raw:
        return "initial_access", "authentication rule during controlled interval"
    return None


def propose(activity_path: Path, alert_path: Path, output_path: Path) -> dict:
    activity = json.loads(activity_path.read_text(encoding="utf-8"))
    alerts = [json.loads(line) for line in alert_path.read_text(encoding="utf-8").splitlines() if line]
    proposals = {}
    run_start = timestamp(activity["started_at"]) - 1
    run_end = timestamp(activity["ended_at"]) + 8
    for alert in alerts:
        if alert.get("agent", {}).get("name") != activity["target_agent"]:
            continue
        moment = timestamp(alert["timestamp"])
        classification = classified_phase(alert, activity["run_id"])
        if run_start <= moment <= run_end and classification:
            phase, evidence = classification
            proposals[str(alert["id"])] = {
                "decision": "proposed-attack",
                "attack_instance_id": activity["attack_instance_id"],
                "ground_truth_phase": phase,
                "evidence": f"target + controlled interval + {evidence}",
                "reviewed": False,
            }
    document = {
        "run_id": activity["run_id"],
        "policy": "unlisted alerts are unknown, never implicitly benign",
        "proposals": proposals,
        "counts": {"alerts_read": len(alerts), "proposed_attack": len(proposals)},
    }
    output_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("activity", type=Path)
    parser.add_argument("alerts", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(propose(args.activity, args.alerts, args.output), indent=2))


if __name__ == "__main__":
    main()
