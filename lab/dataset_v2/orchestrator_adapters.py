"""Adaptateurs V2 des journaux produits par les orchestrateurs V1.

Ce module n'exécute aucune commande distante. Il convertit un résultat V1 déjà
produit, ou génère un résultat fictif en mode dry-run.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Mapping

from jsonschema import Draft202012Validator

from .io_utils import (
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
    utc_now,
    write_new_bytes,
)
from .prepare_campaign import verify_campaign_reservation
from .validators import SCHEMA_DIR


def _jsonl(items: list[Mapping[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        for item in items
    )


def _planned_by_name(plan: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    result = {}
    for item in plan["activities"]:
        for name in {str(item["activity_key"]), str(item["activity_name"])}:
            if name in result:
                raise ValueError(f"Nom d'activité ambigu dans le plan: {name}")
            result[name] = item
    return result


def _dry_v1_truth(plan: Mapping[str, object], platform: str) -> dict[str, object]:
    steps = []
    for item in plan["activities"]:
        if platform != "all" and item["platform"] != platform:
            continue
        started = utc_now()
        steps.append(
            {
                "name": item["activity_name"],
                "ground_truth_phase": item.get("true_activity_phase"),
                "started_at": started,
                "ended_at": started,
                "exit_code": 0,
                "result": {"dry_run": True, "platform": item["platform"]},
            }
        )
    return {"status": "dry-run", "steps": steps}


def adapt_v1_truth(
    manifest: Mapping[str, object],
    plan: Mapping[str, object],
    v1_truth: Mapping[str, object],
    *,
    dry_run: bool,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Convertit les reçus V1 en activités/preuves V2 sans les exécuter."""

    planned = _planned_by_name(plan)
    activities, evidence = [], []
    consumed: set[str] = set()
    for index, step in enumerate(v1_truth.get("steps", [])):
        name = str(step.get("name", ""))
        item = planned.get(name)
        if item is None:
            raise ValueError(f"Étape V1 absente du plan V2: {name!r}")
        activity_id = str(item["activity_id"])
        if activity_id in consumed:
            raise ValueError(f"Activité V1 répétée: {activity_id}")
        consumed.add(activity_id)
        identity_id = f"evidence:{activity_id}:command-hash"
        receipt_id = f"evidence:{activity_id}:execution-receipt"
        result = step.get("result", {})
        if not isinstance(result, Mapping):
            result = {"value": result}
        exit_code = int(step.get("exit_code", 0))
        status = "dry-run" if dry_run else ("completed" if exit_code == 0 else "failed")
        activity = {
            "schema_version": "alertgraph-activity/2.0",
            "campaign_id": manifest["campaign_id"],
            "run_id": manifest["run_id"],
            "activity_id": activity_id,
            "class": item["class"],
            "attack_instance_id": item.get("attack_instance_id"),
            "benign_activity_id": item.get("benign_activity_id"),
            "activity_name": item["activity_name"],
            "platform": item["platform"],
            "status": status,
            "result": {
                **dict(result),
                "adapter": "v1-truth-to-v2",
                "technical_evidence_pending_collection": True,
            },
            "true_activity_phase": item.get("true_activity_phase"),
            "started_at_utc": step.get("started_at") or step.get("started_at_utc"),
            "ended_at_utc": step.get("ended_at") or step.get("ended_at_utc"),
            "controller_started_at_utc": step.get("started_at") or step.get("started_at_utc"),
            "controller_ended_at_utc": step.get("ended_at") or step.get("ended_at_utc"),
            "target_started_at_utc": step.get("target_started_at_utc"),
            "target_ended_at_utc": step.get("target_ended_at_utc"),
            "target_agents": item.get("target_agents", []),
            "target_hosts": item.get("target_hosts", []),
            "marker_id": item["marker_id"],
            "command_spec_sha256": item["command_spec_sha256"],
            "exit_code": exit_code,
            "evidence_ids": [identity_id, receipt_id],
        }
        activities.append(activity)
        common = {
            "schema_version": "alertgraph-evidence/2.0",
            "campaign_id": manifest["campaign_id"],
            "run_id": manifest["run_id"],
            "activity_id": activity_id,
            "recorded_at_utc": activity["ended_at_utc"],
            "observed_in_alert_ids": [],
        }
        evidence.extend(
            [
                {
                    **common,
                    "evidence_id": identity_id,
                    "kind": "command-hash",
                    "source": "sealed-campaign-plan",
                    "payload_sha256": item["command_spec_sha256"],
                },
                {
                    **common,
                    "evidence_id": receipt_id,
                    "kind": "execution-receipt",
                    "source": "dry-run-adapter" if dry_run else "v1-orchestrator-receipt",
                    "payload_sha256": sha256_bytes(canonical_json_bytes(step)),
                },
            ]
        )
    return activities, evidence


def verify_orchestrator_records(campaign_dir: str | Path) -> dict[str, object]:
    execution = Path(campaign_dir) / "execution"
    manifest = load_json(execution / "execution-manifest.json")
    for filename, expected in manifest["files"].items():
        path = execution / filename
        if not path.is_file():
            raise FileNotFoundError(path)
        if sha256_file(path) != expected:
            raise ValueError(f"Sortie orchestrateur modifiée: {filename}")
    return manifest


def emit_orchestrator_records(
    campaign_dir: str | Path,
    *,
    platform: str = "all",
    dry_run: bool = False,
    v1_truth: Mapping[str, object] | None = None,
) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] == "final-test":
        raise PermissionError("Une campagne final-test réservée ne peut pas être orchestrée")
    if platform not in {"linux", "windows", "all"}:
        raise ValueError(f"Plateforme invalide: {platform}")
    if not dry_run and v1_truth is None:
        raise ValueError("Fournir un reçu V1 existant ou utiliser --dry-run")
    if not dry_run:
        from .clock_audit import require_clock_ready

        require_clock_ready(campaign_dir)
    plan = load_json(campaign_dir / "campaign-plan.json")
    truth = v1_truth if v1_truth is not None else _dry_v1_truth(plan, platform)
    activities, evidence = adapt_v1_truth(
        manifest, plan, truth, dry_run=dry_run
    )
    if not activities:
        raise ValueError(f"Aucune activité {platform} dans le plan")
    for items, schema_name in (
        (activities, "activity.schema.json"),
        (evidence, "evidence.schema.json"),
    ):
        schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        errors = [error for item in items for error in validator.iter_errors(item)]
        if errors:
            raise ValueError(
                f"Sortie orchestrateur invalide ({schema_name}): "
                + "; ".join(error.message for error in errors)
            )
    execution = campaign_dir / "execution"
    write_new_bytes(execution / "activities.jsonl", _jsonl(activities))
    write_new_bytes(execution / "evidence.jsonl", _jsonl(evidence))
    execution_manifest = {
        "schema_version": "alertgraph-execution-manifest/2.0",
        "campaign_id": manifest["campaign_id"],
        "run_id": manifest["run_id"],
        "partition": manifest["partition"],
        "mode": "dry-run" if dry_run else "adapted-v1-receipt",
        "created_at_utc": utc_now(),
        "activity_count": len(activities),
        "evidence_count": len(evidence),
        "files": {
            "activities.jsonl": sha256_bytes(_jsonl(activities)),
            "evidence.jsonl": sha256_bytes(_jsonl(evidence)),
        },
    }
    from .io_utils import write_new_json

    write_new_json(execution / "execution-manifest.json", execution_manifest)
    verify_orchestrator_records(campaign_dir)
    return execution_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--platform", choices=("linux", "windows", "all"), default="all")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--dry-run", action="store_true")
    source.add_argument("--v1-truth", type=Path)
    args = parser.parse_args()
    truth = load_json(args.v1_truth) if args.v1_truth else None
    report = emit_orchestrator_records(
        args.campaign_dir,
        platform=args.platform,
        dry_run=args.dry_run,
        v1_truth=truth,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
