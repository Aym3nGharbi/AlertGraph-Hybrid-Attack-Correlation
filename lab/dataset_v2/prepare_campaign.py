"""Réserve une campagne Wazuh V2 sans lancer de machine ni d'activité."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Mapping

from jsonschema import Draft202012Validator

from .io_utils import (
    canonical_json_bytes,
    load_json,
    replace_json_atomic,
    sha256_bytes,
    sha256_file,
    utc_now,
    write_new_json,
)
from .validators import SCHEMA_DIR, PARTITIONS
from .temporal_policy import DEFAULT_TEMPORAL_POLICY, validate_temporal_policy


ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,127}$")
FINAL_SENTINEL = "FINAL_TEST_RESERVED_DO_NOT_EXECUTE"


def _validate_id(name: str, value: str) -> None:
    if not ID_PATTERN.fullmatch(value):
        raise ValueError(f"{name} invalide: {value!r}")


def _schema_validator(filename: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / filename).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _require_schema(document: Mapping[str, object], filename: str) -> None:
    errors = sorted(_schema_validator(filename).iter_errors(document), key=lambda x: list(x.path))
    if errors:
        raise ValueError("; ".join(error.message for error in errors))


def _marker(campaign_id: str, run_id: str, seed: int, activity_key: str) -> str:
    material = f"alertgraph-v2|{campaign_id}|{run_id}|{seed}|{activity_key}".encode()
    return "agv2-" + hashlib.sha256(material).hexdigest()[:24]


def _prepare_activities(
    campaign_id: str, run_id: str, seed: int, plan: Mapping[str, object]
) -> list[dict[str, object]]:
    raw = plan.get("activities")
    if not isinstance(raw, list) or not raw:
        raise ValueError("Le plan doit contenir au moins une activité")
    seen: set[str] = set()
    prepared = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"activities[{index}] doit être un objet")
        key = str(item.get("key", ""))
        _validate_id(f"activities[{index}].key", key)
        if key in seen:
            raise ValueError(f"Clé d'activité réutilisée: {key}")
        seen.add(key)
        label_class = item.get("class")
        if label_class not in {"attack", "benign"}:
            raise ValueError(f"Classe invalide pour {key}")
        platform = item.get("platform")
        if platform not in {"linux", "windows"}:
            raise ValueError(f"Plateforme invalide pour {key}")
        identity_key = item.get(
            "attack_instance_key" if label_class == "attack" else "benign_activity_key"
        )
        if not isinstance(identity_key, str) or not identity_key:
            raise ValueError(f"Identité de supervision manquante pour {key}")
        command = str(item.get("command_template", ""))
        if not command:
            raise ValueError(f"command_template manquant pour {key}")
        prepared.append(
            {
                "activity_key": key,
                "activity_id": f"activity:{campaign_id}:{key}",
                "class": label_class,
                "attack_instance_id": (
                    f"attack:{campaign_id}:{identity_key}" if label_class == "attack" else None
                ),
                "benign_activity_id": (
                    f"benign:{campaign_id}:{identity_key}" if label_class == "benign" else None
                ),
                "activity_name": str(item.get("activity_name") or key),
                "true_activity_phase": item.get("true_activity_phase"),
                "platform": platform,
                "target_agents": list(item.get("target_agents", [])),
                "target_hosts": list(item.get("target_hosts", [])),
                "marker_id": _marker(campaign_id, run_id, seed, key),
                "command_template": command,
                "command_spec_sha256": sha256_bytes(command.encode("utf-8")),
                "activity_role": item.get("activity_role"),
                "expected_wazuh_rules": list(item.get("expected_wazuh_rules", [])),
                "proof_requirements": list(item.get("proof_requirements", [])),
            }
        )
    return prepared


def campaign_directory(root: str | Path, campaign_id: str, run_id: str) -> Path:
    return Path(root) / "campaigns" / campaign_id / run_id


def verify_campaign_reservation(directory: str | Path) -> dict[str, object]:
    directory = Path(directory)
    reservation = load_json(directory / "reservation.json")
    for filename, expected in reservation["sealed_files"].items():
        path = directory / filename
        if not path.is_file():
            raise FileNotFoundError(f"Fichier réservé absent: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"Campagne modifiée silencieusement: {filename}")
    manifest = load_json(directory / "campaign-manifest.json")
    if manifest["partition"] == "final-test" and not (directory / FINAL_SENTINEL).is_file():
        raise ValueError("Sentinelle final-test absente")
    return manifest


def prepare_campaign(
    root: str | Path,
    *,
    campaign_id: str,
    run_id: str,
    partition: str,
    scenario_plan: Mapping[str, object],
    parameter_seed: int,
    dataset_version: str = "wazuh-supervised-v2",
    reserve_final_test: bool = False,
) -> dict[str, object]:
    """Crée une réservation append-only et retourne ses chemins."""

    root = Path(root)
    _validate_id("campaign_id", campaign_id)
    _validate_id("run_id", run_id)
    if partition not in PARTITIONS:
        raise ValueError(f"Partition invalide: {partition}")
    if parameter_seed < 0:
        raise ValueError("parameter_seed doit être positif ou nul")
    if partition == "final-test" and not reserve_final_test:
        raise PermissionError(
            "Une réservation final-test exige --reserve-final-test et restera non exécutable"
        )

    target = campaign_directory(root, campaign_id, run_id)
    if target.exists():
        raise FileExistsError(f"La campagne existe déjà: {target}")
    registry_path = root / "campaign-registry.json"
    lock_path = root / ".campaign-registry.lock"
    root.mkdir(parents=True, exist_ok=True)
    lock_descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    os.close(lock_descriptor)
    try:
        if registry_path.exists():
            registry = load_json(registry_path)
        else:
            registry = {
                "schema_version": "alertgraph-campaign-registry/2.0",
                "dataset_version": dataset_version,
                "frozen_at_utc": utc_now(),
                "campaigns": [],
            }
        if registry.get("dataset_version") != dataset_version:
            raise ValueError("dataset_version incompatible avec le registre")
        if any(x.get("campaign_id") == campaign_id for x in registry["campaigns"]):
            raise ValueError(f"campaign_id déjà réservé: {campaign_id}")
        for existing_manifest in root.glob("campaigns/*/*/campaign-manifest.json"):
            existing = load_json(existing_manifest)
            if existing.get("run_id") == run_id:
                raise ValueError(f"run_id déjà réservé: {run_id}")

        prepared_activities = _prepare_activities(
            campaign_id, run_id, parameter_seed, scenario_plan
        )
        machines = []
        for item in scenario_plan.get("machines", []):
            machines.append(
                {
                    "role": item["role"],
                    "host": item["host"],
                    "agent_name": item.get("agent_name"),
                    "clock_audited_at_utc": None,
                    "clock_offset_ms": None,
                }
            )
        if not machines:
            raise ValueError("Le plan doit déclarer au moins une machine")

        plan_document = {
            "schema_version": "alertgraph-campaign-plan/2.0",
            "campaign_id": campaign_id,
            "run_id": run_id,
            "partition": partition,
            "parameter_seed": parameter_seed,
            "scenario_template": scenario_plan.get("scenario_template"),
            "temporal_policy": validate_temporal_policy(
                scenario_plan.get("temporal_policy", DEFAULT_TEMPORAL_POLICY)
            ),
            "activities": prepared_activities,
            "supervision_policy": scenario_plan.get("supervision_policy"),
            "pair_label_policy": scenario_plan.get("pair_label_policy"),
            "safety_policy": scenario_plan.get("safety_policy"),
        }
        plan_hash = sha256_bytes(canonical_json_bytes(plan_document))
        manifest = {
            "schema_version": "alertgraph-campaign-manifest/2.0",
            "campaign_id": campaign_id,
            "run_id": run_id,
            "partition": partition,
            "parameter_seed": parameter_seed,
            "created_at_utc": utc_now(),
            "started_at_utc": None,
            "ended_at_utc": None,
            "status": "planned",
            "machines": machines,
            "configuration_hashes": {"campaign_plan": plan_hash},
        }
        registry_entry = {
            "campaign_id": campaign_id,
            "partition": partition,
            "scenario_template": str(scenario_plan.get("scenario_template") or "unspecified"),
            "parameter_seed": parameter_seed,
            "status": "planned",
        }
        new_registry = dict(registry)
        new_registry["frozen_at_utc"] = utc_now()
        new_registry["campaigns"] = [*registry["campaigns"], registry_entry]
        _require_schema(manifest, "campaign-manifest.schema.json")
        _require_schema(new_registry, "campaign-registry.schema.json")

        target.mkdir(parents=True, exist_ok=False)
        write_new_json(target / "campaign-plan.json", plan_document)
        write_new_json(target / "campaign-manifest.json", manifest)
        if partition == "final-test":
            (target / FINAL_SENTINEL).touch(exist_ok=False)
        reservation = {
            "schema_version": "alertgraph-reservation/2.0",
            "created_at_utc": utc_now(),
            "sealed_files": {
                "campaign-plan.json": sha256_file(target / "campaign-plan.json"),
                "campaign-manifest.json": sha256_file(target / "campaign-manifest.json"),
            },
            "final_test_execution_allowed": False,
        }
        write_new_json(target / "reservation.json", reservation)
        if registry_path.exists():
            replace_json_atomic(registry_path, new_registry)
        else:
            write_new_json(registry_path, new_registry)
        return {
            "campaign_directory": str(target),
            "registry": str(registry_path),
            "campaign_id": campaign_id,
            "run_id": run_id,
            "partition": partition,
            "markers": [x["marker_id"] for x in prepared_activities],
            "final_test_execution_allowed": False,
        }
    finally:
        lock_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("campaign_id")
    parser.add_argument("run_id")
    parser.add_argument("--partition", required=True, choices=sorted(PARTITIONS))
    parser.add_argument("--scenario-plan", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--dataset-version", default="wazuh-supervised-v2")
    parser.add_argument("--reserve-final-test", action="store_true")
    args = parser.parse_args()
    plan = json.loads(args.scenario_plan.read_text(encoding="utf-8"))
    result = prepare_campaign(
        args.root,
        campaign_id=args.campaign_id,
        run_id=args.run_id,
        partition=args.partition,
        scenario_plan=plan,
        parameter_seed=args.seed,
        dataset_version=args.dataset_version,
        reserve_final_test=args.reserve_final_test,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
