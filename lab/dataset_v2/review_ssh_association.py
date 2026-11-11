"""Crée une révision traçable d'une association SSH V2 existante.

Le réviseur ne modifie aucun artefact historique. Il sépare la preuve
d'identité du reçu contrôleur/cible de la télémétrie Wazuh et écrit une vue
dérivée dans ``association-review-v2``.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Mapping

from .io_utils import (
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
    utc_now,
    write_new_bytes,
    write_new_json,
)
from .prepare_campaign import verify_campaign_reservation
from .validators import validate_bundle


def _jsonl(items: list[Mapping[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        for item in items
    )


def review_ssh_association(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if not (campaign_dir / "association-policy.json").is_file():
        raise FileNotFoundError("La politique préenregistrée est absente")
    association_dir = campaign_dir / "association"
    review_dir = campaign_dir / "association-review-v2"
    if review_dir.exists():
        raise FileExistsError("La révision scientifique existe déjà")

    collection = load_json(campaign_dir / "raw" / "collection-manifest.json")
    for item in collection["files"]:
        path = campaign_dir / str(item["path"])
        if sha256_file(path) != item["sha256"]:
            raise ValueError(f"Artefact brut altéré: {item['path']}")
    association_manifest = load_json(association_dir / "association-manifest.json")
    for filename, expected in association_manifest["files"].items():
        if sha256_file(association_dir / filename) != expected:
            raise ValueError(f"Artefact d'association altéré: {filename}")

    receipt = load_json(campaign_dir / "receipts" / "v1-truth.json")
    step = receipt["steps"][0]
    result = step["result"]
    if step["exit_code"] != 0 or not result.get("connection_tuple_match"):
        raise ValueError("Le reçu ne prouve pas un tuple SSH concordant")

    original_bundle = load_json(association_dir / "validation-bundle.json")
    annotations = deepcopy(original_bundle["annotations"])
    verified = [item for item in annotations if item["confidence"] == "verified"]
    if len(verified) != 1:
        raise ValueError("Une unique annotation vérifiée est attendue")
    annotation = verified[0]
    alert_id = str(annotation["wazuh_alert_id"])
    activity_id = str(annotation["activity_id"])
    now = utc_now()
    identity_id = f"evidence:{activity_id}:independent-execution-identity-review-v2"
    identity_payload = {
        "controller_socket": result["controller_socket"],
        "target_ssh_connection": result["target_ssh_connection"],
        "connection_tuple_match": True,
        "controller_process_id": result["ssh_pid"],
    }
    identity_evidence = {
        "schema_version": "alertgraph-evidence/2.0",
        "evidence_id": identity_id,
        "campaign_id": manifest["campaign_id"],
        "run_id": manifest["run_id"],
        "activity_id": activity_id,
        "kind": "artifact-identity",
        "recorded_at_utc": now,
        "source": "controller-socket+target-ssh-connection:historical-execution-receipt",
        "payload_sha256": sha256_bytes(canonical_json_bytes(identity_payload)),
        "observed_in_alert_ids": [alert_id],
    }
    technical_ids = [
        item["evidence_id"]
        for item in original_bundle["evidence"]
        if item["kind"] == "authentication-telemetry"
        and alert_id in item["observed_in_alert_ids"]
    ]
    if len(technical_ids) != 1:
        raise ValueError("Une unique preuve Wazuh technique est attendue")

    previous_ids = list(annotation["evidence_ids"])
    annotation["evidence_ids"] = [identity_id, technical_ids[0]]
    annotation["annotation_source"] = "controlled-ssh-independent-proof-review-v2"
    annotation["reviewer_id"] = "automatic-scientific-audit-v2"
    annotation["reviewed_at_utc"] = now
    annotation["revision"] = 2
    revision = {
        "schema_version": "alertgraph-annotation-revision/2.0",
        "revision_id": f"revision:{annotation['annotation_id']}:2",
        "annotation_id": annotation["annotation_id"],
        "revision": 2,
        "previous_revision_id": None,
        "created_at_utc": now,
        "reviewer_id": "automatic-scientific-audit-v2",
        "reason": "Séparer la preuve d'identité du reçu d'exécution de la télémétrie Wazuh, sans changer le label.",
        "changes": {
            "evidence_ids_before": previous_ids,
            "evidence_ids_after": annotation["evidence_ids"],
            "confidence_unchanged": "verified",
        },
    }
    bundle = {
        **original_bundle,
        "evidence": [*original_bundle["evidence"], identity_evidence],
        "annotations": annotations,
        "revisions": [*original_bundle.get("revisions", []), revision],
    }
    validate_bundle(bundle, base_dir=campaign_dir)

    write_new_bytes(review_dir / "evidence-additions.jsonl", _jsonl([identity_evidence]))
    write_new_bytes(review_dir / "annotations.jsonl", _jsonl(annotations))
    write_new_bytes(review_dir / "revisions.jsonl", _jsonl([revision]))
    write_new_json(review_dir / "validation-bundle.json", bundle)
    review_manifest = {
        "schema_version": "alertgraph-association-review/2.0-experimental",
        "campaign_id": manifest["campaign_id"],
        "run_id": manifest["run_id"],
        "created_at_utc": now,
        "policy_preregistered": True,
        "raw_integrity_verified": True,
        "association_integrity_verified": True,
        "confidence_changed": False,
        "verified": 1,
        "weak_unchanged": sum(x["confidence"] == "weak" for x in annotations),
        "training_ready": False,
        "files": {
            name: sha256_file(review_dir / name)
            for name in (
                "evidence-additions.jsonl",
                "annotations.jsonl",
                "revisions.jsonl",
                "validation-bundle.json",
            )
        },
    }
    write_new_json(review_dir / "review-manifest.json", review_manifest)
    return review_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(review_ssh_association(args.campaign_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
