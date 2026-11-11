"""Combine des reçus V2 individuels en reçu V1 adaptable, sans écrasement."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .io_utils import load_json, write_new_json
from .prepare_campaign import verify_campaign_reservation


def combine_activity_receipts(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    verify_campaign_reservation(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json")
    steps = []
    for activity in plan["activities"]:
        path = campaign_dir / "receipts" / f"{activity['activity_key']}.json"
        receipt = load_json(path)
        if receipt.get("status") != "completed" or len(receipt.get("steps", [])) != 1:
            raise ValueError(f"Reçu individuel non concluant: {path}")
        step = receipt["steps"][0]
        if step.get("name") != activity["activity_name"]:
            raise ValueError(f"Activité et reçu incohérents: {activity['activity_key']}")
        steps.append(step)
    combined = {"status": "completed", "steps": steps}
    output = campaign_dir / "receipts" / "v1-truth.json"
    write_new_json(output, combined)
    return {"output": str(output), "activities": len(steps), "status": "completed"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(combine_activity_receipts(args.campaign_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
