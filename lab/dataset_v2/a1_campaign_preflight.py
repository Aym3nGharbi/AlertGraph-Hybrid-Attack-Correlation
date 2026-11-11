"""Pré-vol scientifique d'une instance SSH A1 strictement supervisée."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .io_utils import load_json, sha256_file, utc_now, write_new_json
from .prepare_campaign import verify_campaign_reservation


def validate_a1_preflight(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("A1 exige la partition development")
    plan = load_json(campaign_dir / "campaign-plan.json")
    activities = list(plan["activities"])
    errors: list[str] = []
    if len(activities) != 3 or any(x.get("class") != "attack" for x in activities):
        errors.append("A1 doit contenir exactement trois activités d'attaque")
    instances = {x.get("attack_instance_id") for x in activities}
    if len(instances) != 1 or None in instances:
        errors.append("les trois activités doivent partager une instance A1 non nulle")
    roles = Counter(str(x.get("activity_role")) for x in activities)
    if roles != Counter({"failed-authentication": 2, "authorized-login-in-simulation": 1}):
        errors.append("A1 exige deux échecs et un succès autorisé")
    supervision = plan.get("supervision_policy") or {}
    pairs = plan.get("pair_label_policy") or {}
    safety = plan.get("safety_policy") or {}
    if supervision.get("version") != "strict-verified-only-v2":
        errors.append("politique de supervision stricte absente")
    if supervision.get("time_or_host_alone_is_sufficient") is not False:
        errors.append("le temps ou l'hôte ne doit pas suffire")
    if supervision.get("absence_of_match_is_negative") is not False:
        errors.append("l'absence de correspondance ne doit pas devenir négative")
    if pairs.get("supervision_fields_are_features") is not False:
        errors.append("séparation features/supervision absente")
    if safety.get("maximum_failed_attempts_total") != 2:
        errors.append("la limite A1 doit être exactement deux échecs")
    if not safety.get("stop_conditions") or any(not x.get("proof_requirements") for x in activities):
        errors.append("conditions d'arrêt ou preuves requises absentes")
    if errors:
        raise ValueError("; ".join(errors))
    report = {
        "schema_version": "alertgraph-a1-campaign-preflight/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "created_at_utc": utc_now(), "status": "prepared-authorized-a1-only",
        "attack_instance_id": next(iter(instances)),
        "ordered_activities": [x["activity_id"] for x in activities],
        "failed_attempt_limit": 2,
        "stop_after_each_activity_without_complete_proof": True,
        "a2_or_b1_execution_allowed": False,
        "sealed_plan_sha256": sha256_file(campaign_dir / "campaign-plan.json"),
        "training_ready": False,
    }
    write_new_json(campaign_dir / "a1-preflight-report-v2.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args(); print(json.dumps(validate_a1_preflight(args.campaign_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
