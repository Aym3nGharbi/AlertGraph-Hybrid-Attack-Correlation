"""Audit append-only des événements répétés entre campagnes Wazuh V2."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from lab.dataset_v2.io_utils import sha256_file, utc_now, write_new_json


def _event_identity(event: dict[str, Any]) -> str | None:
    event_id = event.get("id")
    if not event_id:
        return None
    agent = event.get("agent") or {}
    return f"{agent.get('id', 'manager')}:{event_id}"


def audit_raw_events(campaigns_root: Path, inventory_path: Path) -> dict[str, Any]:
    observations: dict[str, list[dict[str, str]]] = defaultdict(list)
    malformed: list[dict[str, Any]] = []
    raw_files = sorted(campaigns_root.glob("*/*/raw/alerts.jsonl"))
    total_lines = 0
    for path in raw_files:
        campaign_id = path.parents[2].name
        run_id = path.parents[1].name
        with path.open("rb") as source:
            for line_number, raw_line in enumerate(source, 1):
                if not raw_line.strip():
                    continue
                total_lines += 1
                try:
                    event = json.loads(raw_line)
                except Exception as exc:
                    malformed.append({"campaign_id": campaign_id, "line": line_number, "error": type(exc).__name__})
                    continue
                identity = _event_identity(event)
                if identity is None:
                    malformed.append({"campaign_id": campaign_id, "line": line_number, "error": "missing-event-identity"})
                    continue
                observations[identity].append({
                    "campaign_id": campaign_id,
                    "run_id": run_id,
                    "line": str(line_number),
                    "raw_line_sha256": hashlib.sha256(raw_line.rstrip(b"\r\n")).hexdigest(),
                    "timestamp": str(event.get("timestamp") or ""),
                    "rule_id": str((event.get("rule") or {}).get("id") or ""),
                })

    repeated = {key: rows for key, rows in observations.items() if len(rows) > 1}
    cross_campaign = {
        key: rows for key, rows in repeated.items()
        if len({row["campaign_id"] for row in rows}) > 1
    }
    exact_cross_campaign = {
        key: rows for key, rows in cross_campaign.items()
        if len({row["raw_line_sha256"] for row in rows}) == 1
    }
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    strict = [
        {
            "campaign_id": item["campaign_id"],
            "verified_meta_alerts": item.get("verified_meta_alerts", 0),
            "strict_positive_pairs": item.get("strict_positive_pairs", 0),
            "strict_negative_pairs": item.get("strict_negative_pairs", 0),
            "canonical_report": item.get("canonical_report"),
        }
        for item in inventory["campaigns"] if item.get("strict_pairs", 0)
    ]
    return {
        "schema_version": "alertgraph-dataset-consistency-audit/2.0",
        "created_at_utc": utc_now(),
        "training_ready": False,
        "inputs": {
            "campaigns_root": str(campaigns_root),
            "inventory": str(inventory_path),
            "inventory_sha256": sha256_file(inventory_path),
        },
        "raw_files": len(raw_files),
        "raw_observations": total_lines,
        "unique_event_identities": len(observations),
        "repeated_observations": total_lines - len(observations),
        "identities_repeated_anywhere": len(repeated),
        "identities_repeated_across_campaigns": len(cross_campaign),
        "byte_identical_identities_repeated_across_campaigns": len(exact_cross_campaign),
        "malformed_or_unidentified": malformed,
        "cross_campaign_repetitions": cross_campaign,
        "strict_ml_campaigns": strict,
        "counting_decision": "unique identity for event totals; campaign remains the partition unit; derived reports are not campaigns",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaigns-root", type=Path, default=Path("output/wazuh-supervised-v2/campaigns"))
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit_raw_events(args.campaigns_root, args.inventory)
    write_new_json(args.output, report)
    print(json.dumps({key: report[key] for key in (
        "raw_observations", "unique_event_identities", "repeated_observations",
        "identities_repeated_across_campaigns", "malformed_or_unidentified",
    )}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
