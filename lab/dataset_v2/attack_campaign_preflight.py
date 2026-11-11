"""Valide sans exécution une campagne d'attaque V2 préenregistrée."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from .io_utils import load_json, sha256_file, utc_now, write_new_json
from .prepare_campaign import verify_campaign_reservation
from .strict_verified_pairs import conditional_pair_estimate


def validate_attack_campaign_preflight(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] != "development":
        raise PermissionError("Le pré-vol d'attaque exige development")
    plan = load_json(campaign_dir / "campaign-plan.json")
    errors = []
    supervision = plan.get("supervision_policy") or {}
    safety = plan.get("safety_policy") or {}
    pair_policy = plan.get("pair_label_policy") or {}
    if supervision.get("version") != "strict-verified-only-v2":
        errors.append("politique de supervision stricte absente")
    if supervision.get("absence_of_match_is_negative") is not False:
        errors.append("absence de correspondance ne doit jamais être négative")
    if pair_policy.get("supervision_fields_are_features") is not False:
        errors.append("séparation features/supervision non déclarée")
    activities = plan["activities"]
    attacks = defaultdict(list); benign = []
    for activity in activities:
        if activity["class"] == "attack":
            attacks[str(activity["attack_instance_id"])].append(activity)
        elif activity["class"] == "benign":
            benign.append(activity)
    if len(attacks) != 2:
        errors.append("exactement deux instances d'attaque distinctes sont requises")
    if len(benign) != 1:
        errors.append("exactement une activité bénigne indépendante est requise")
    failed_total = 0
    for instance, items in attacks.items():
        roles = Counter(str(x.get("activity_role")) for x in items)
        failed_total += roles["failed-authentication"]
        if roles["failed-authentication"] < 2 or roles["authorized-login-in-simulation"] < 1:
            errors.append(f"{instance}: deux échecs et un succès contrôlé sont requis")
        if any(not x.get("proof_requirements") for x in items):
            errors.append(f"{instance}: exigences de preuve manquantes")
    if benign and benign[0].get("activity_role") != "independent-benign-login":
        errors.append("rôle bénin indépendant invalide")
    if failed_total > int(safety.get("maximum_failed_attempts_total", -1)):
        errors.append("nombre d'échecs supérieur à la limite préenregistrée")
    if not safety.get("stop_conditions"):
        errors.append("conditions d'arrêt absentes")
    if errors:
        raise ValueError("; ".join(errors))
    estimate = conditional_pair_estimate({key: 2 for key in attacks}, 1)
    report = {
        "schema_version": "alertgraph-attack-campaign-preflight/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "created_at_utc": utc_now(), "status": "prepared-not-authorized-for-execution",
        "attack_instances": sorted(attacks), "attack_activity_counts": {k: len(v) for k, v in attacks.items()},
        "benign_activities": len(benign), "planned_failed_attempts": failed_total,
        "conditional_pair_estimate_assuming_exactly_two_verified_attack_meta_alerts_per_instance_and_one_benign": estimate,
        "pair_estimate_scope": "combinatorial before observable candidate generation; not an observed result or guaranteed yield",
        "required_before_execution": [
            "explicit-user-authorization", "fresh-accepted-clock-audit", "all-required-agents-active",
            "alerts-json-at-most-25MiB", "free-disk-at-least-5GiB", "read-only-collection-ready",
            "failed-auth-observability-pilot-or-stop-on-missing-alert"
        ],
        "training_ready": False,
        "sealed_plan_sha256": sha256_file(campaign_dir / "campaign-plan.json"),
    }
    write_new_json(campaign_dir / "attack-preflight-report-v2.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args(); print(json.dumps(validate_attack_campaign_preflight(args.campaign_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
