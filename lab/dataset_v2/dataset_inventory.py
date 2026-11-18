"""Inventaire canonique des campagnes supervisées Wazuh V2.

Une campagne est comptée une seule fois. Les réanalyses/corrections dérivées sont
conservées dans ``derived_views`` mais ne deviennent jamais de nouvelles campagnes.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from lab.dataset_v2.io_utils import sha256_file, utc_now, write_new_json


CANONICAL_REPORTS = (
    "supervision-multiphase-fim-v2/report.json",
    "supervision-multi-instance-v2-exclusive-correlation/report.json",
    "supervision-a1-v2/report.json",
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("rb") as source:
        return sum(1 for line in source if line.strip())


def _first_existing(root: Path, relatives: Iterable[str]) -> Path | None:
    return next((root / item for item in relatives if (root / item).exists()), None)


def _find_run(campaign_dir: Path, campaign_id: str) -> Path | None:
    runs = sorted(path for path in campaign_dir.iterdir() if path.is_dir() and path.name.startswith(campaign_id + "-r"))
    return runs[-1] if runs else None


def _raw_count(run: Path) -> int:
    manifest = run / "raw" / "collection-manifest.json"
    if manifest.exists():
        doc = _load(manifest)
        for key in ("event_count", "events", "line_count", "selected_events"):
            if isinstance(doc.get(key), int):
                return int(doc[key])
    candidates = list((run / "raw").glob("*.jsonl")) if (run / "raw").exists() else []
    return max((_jsonl_count(path) for path in candidates), default=0)


def _canonical_report(run: Path) -> tuple[Path | None, dict[str, Any]]:
    path = _first_existing(run, CANONICAL_REPORTS)
    return (path, _load(path)) if path else (None, {})


def _canonical_summary(run: Path) -> tuple[Path | None, dict[str, Any]]:
    priorities = (
        "supervision-multiphase-fim-v2/scientific-summary.json",
        "supervision-multi-instance-v2-exclusive-correlation/scientific-summary.json",
        "supervision-benign-fim-v2/scientific-summary.json",
    )
    path = _first_existing(run, priorities)
    return (path, _load(path)) if path else (None, {})


def _derived_views(run: Path, canonical: Path | None) -> list[str]:
    views: list[str] = []
    for path in sorted(run.rglob("report.json")):
        if canonical is None or path.resolve() != canonical.resolve():
            views.append(path.relative_to(run).as_posix())
    for path in sorted(run.rglob("scientific-summary.json")):
        views.append(path.relative_to(run).as_posix())
    return views


def _plan_index(plans_root: Path | None) -> dict[str, tuple[Path, dict[str, Any]]]:
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    if plans_root and plans_root.exists():
        for path in plans_root.glob("*.json"):
            result[sha256_file(path)] = (path, _load(path))
    return result


def _canonical_decisions(run: Path) -> tuple[Path | None, list[dict[str, Any]]]:
    priorities = (
        "supervision-input-multiphase-v2/event-decisions.jsonl",
        "supervision-input-exclusive-correlation-v2/event-decisions.jsonl",
        "supervision-a1-v2/event-decisions.jsonl",
        "supervision-benign-fim-v2/event-decisions.jsonl",
        "membership-review-evidence-graph-v2/membership-decisions.jsonl",
        "membership-review-evidence-graph-v1/membership-decisions.jsonl",
    )
    path = _first_existing(run, priorities)
    if not path:
        return None, []
    return path, [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def inventory_campaign(campaign_dir: Path, plans: dict[str, tuple[Path, dict[str, Any]]] | None = None) -> dict[str, Any]:
    campaign_id = campaign_dir.name
    run = _find_run(campaign_dir, campaign_id)
    if run is None:
        return {
            "campaign_id": campaign_id,
            "partition": "development",
            "execution_status": "planned-only",
            "dataset_eligibility": "not-eligible",
            "limitations": ["aucun run matériel trouvé"],
        }

    manifest_path = run / "campaign-manifest.json"
    manifest = _load(manifest_path) if manifest_path.exists() else {}
    plan_hash = manifest.get("configuration_hashes", {}).get("campaign_plan")
    sealed_plan = run / "campaign-plan.json"
    plan_entry = (sealed_plan, _load(sealed_plan)) if sealed_plan.exists() else (plans or {}).get(plan_hash)
    plan_path, plan = plan_entry if plan_entry else (None, {})
    activities = plan.get("activities", [])
    attack_instances = sorted({str(item.get("attack_instance_id") or item.get("attack_instance_key")) for item in activities if item.get("attack_instance_id") or item.get("attack_instance_key")})
    benign_instances = sorted({str(item.get("benign_activity_id") or item.get("benign_activity_key")) for item in activities if item.get("benign_activity_id") or item.get("benign_activity_key")})
    declared_behaviors = sorted({str(item["activity_role"]) for item in activities if item.get("activity_role")})
    report_path, report = _canonical_report(run)
    summary_path, summary = _canonical_summary(run)
    decisions_path, decisions = _canonical_decisions(run)
    raw_events = int(report.get("raw_events", _raw_count(run)))
    positive = int(report.get("verified_positive_pairs", 0))
    negative = int(report.get("verified_negative_pairs", 0))
    scopes = report.get("pair_scope_counts", {})
    if scopes:
        positive = sum(int(value) for key, value in scopes.items() if key.startswith("positive"))
        negative = sum(int(value) for key, value in scopes.items() if key.startswith("negative"))

    strict_pairs = positive + negative
    if strict_pairs and positive and negative:
        eligibility = "strict-binary-pairs"
    elif strict_pairs:
        eligibility = "partial-strict-pairs"
    elif raw_events:
        eligibility = "evidence-or-collection-only"
    else:
        eligibility = "not-eligible"

    limitations: list[str] = []
    if not report_path:
        limitations.append("aucun rapport canonique de paires strictes")
    if strict_pairs and not negative:
        limitations.append("aucun négatif strict dans cette campagne")
    if report.get("excluded_events"):
        limitations.append(f"{report['excluded_events']} événements exclus de la supervision")
    if report.get("weak_labels_used") is True:
        limitations.append("labels faibles présents: campagne non éligible au corpus strict")

    member_verified = int(report.get("member_verified", sum(row.get("decision") == "member-verified" for row in decisions)))
    nonmember_verified = int(report.get("nonmember_verified", sum(row.get("decision") == "nonmember-verified" for row in decisions)))
    observed_behaviors = sorted({str(row["behavior"]) for row in decisions if row.get("behavior") and row.get("decision") == "member-verified"})
    return {
        "campaign_id": campaign_id,
        "run_id": run.name,
        "partition": manifest.get("partition", "development"),
        "execution_status": "executed" if raw_events else "prepared",
        "raw_events": raw_events,
        "declared_attack_instances": attack_instances,
        "declared_benign_activities": benign_instances,
        "declared_behaviors": declared_behaviors,
        "observed_verified_behaviors": observed_behaviors,
        "member_verified_events": member_verified,
        "nonmember_verified_events": nonmember_verified,
        "meta_alerts": int(report.get("meta_alerts", summary.get("meta_alerts_total", 0))),
        "verified_meta_alerts": int(report.get("verified_meta_alerts", summary.get("meta_alerts_verified", 0))),
        "candidate_pairs": int(report.get("candidate_pairs", summary.get("candidates_total", 0))),
        "strict_positive_pairs": positive,
        "strict_negative_pairs": negative,
        "strict_pairs": strict_pairs,
        "pair_scope_counts": scopes,
        "dataset_eligibility": eligibility,
        "canonical_report": report_path.relative_to(run).as_posix() if report_path else None,
        "canonical_report_sha256": sha256_file(report_path) if report_path else None,
        "canonical_decisions": decisions_path.relative_to(run).as_posix() if decisions_path else None,
        "canonical_summary": summary_path.relative_to(run).as_posix() if summary_path else None,
        "campaign_plan": plan_path.name if plan_path else None,
        "campaign_plan_sha256": plan_hash,
        "derived_views_not_counted_as_campaigns": _derived_views(run, report_path),
        "training_ready": False,
        "limitations": limitations,
    }


def build_inventory(campaigns_root: Path, plans_root: Path | None = None) -> dict[str, Any]:
    if plans_root is None:
        plans_root = campaigns_root.parent / "plans"
    plans = _plan_index(plans_root)
    campaigns = [inventory_campaign(path, plans) for path in sorted(campaigns_root.iterdir()) if path.is_dir()]
    totals = {
        "campaigns": len(campaigns),
        "executed": sum(item.get("execution_status") == "executed" for item in campaigns),
        "raw_events": sum(int(item.get("raw_events", 0)) for item in campaigns),
        "verified_events": sum(int(item.get("member_verified_events", 0)) for item in campaigns),
        "verified_meta_alerts": sum(int(item.get("verified_meta_alerts", 0)) for item in campaigns),
        "strict_positive_pairs": sum(int(item.get("strict_positive_pairs", 0)) for item in campaigns),
        "strict_negative_pairs": sum(int(item.get("strict_negative_pairs", 0)) for item in campaigns),
    }
    return {
        "schema_version": "alertgraph-dataset-inventory/2.0",
        "created_at_utc": utc_now(),
        "counting_policy": "one physical campaign once; derived corrections are views",
        "training_ready": False,
        "totals": totals,
        "campaigns": campaigns,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaigns-root", type=Path, default=Path("output/wazuh-supervised-v2/campaigns"))
    parser.add_argument("--plans-root", type=Path, default=Path("output/wazuh-supervised-v2/plans"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = build_inventory(args.campaigns_root, args.plans_root)
    write_new_json(args.output, document)
    print(json.dumps(document["totals"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
