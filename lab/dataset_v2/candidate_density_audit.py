"""Audit hors ligne de la densité des candidats, sans modifier leurs paramètres."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from lab.dataset_v2.io_utils import sha256_file, utc_now, write_new_json


def analyze(manifest_path: Path, pair_truth_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    n = int(manifest["meta_alerts"])
    edges = int(manifest["pair_candidates"])
    possible = n * (n - 1) // 2
    cap = int(manifest["parameters"]["cap"])
    truth = [json.loads(line) for line in pair_truth_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    positives = sum(int(row.get("target", -1)) == 1 for row in truth)
    negatives = sum(int(row.get("target", -1)) == 0 for row in truth)
    return {
        "schema_version": "alertgraph-candidate-density-audit/2.0",
        "created_at_utc": utc_now(),
        "training_ready": False,
        "inputs": {
            "manifest": str(manifest_path),
            "manifest_sha256": sha256_file(manifest_path),
            "pair_truth": str(pair_truth_path),
            "pair_truth_sha256": sha256_file(pair_truth_path),
        },
        "parameters_unchanged": manifest["parameters"],
        "meta_alerts": n,
        "candidate_pairs": edges,
        "all_possible_temporally_ordered_pairs": possible,
        "density": edges / possible if possible else 0.0,
        "missing_possible_pairs": possible - edges,
        "causal_candidates": int(manifest.get("causal_candidates", 0)),
        "strict_positive_pairs": positives,
        "strict_negative_pairs": negatives,
        "strict_binary_pairs": positives + negatives,
        "candidate_cap_active_in_this_run": n - 1 > cap,
        "local_candidate_upper_bound_at_scale": f"approximately {cap} * number_of_meta_alerts",
        "interpretation": [
            "La fenêtre de 60 s couvre presque toute cette campagne courte.",
            "Le cap 50 n'est pas actif avec 29 méta-alertes; il doit être audité sur des campagnes plus denses.",
            "Les ponts causaux sont une source séparée et doivent être mesurés lors du passage à l'échelle.",
            "Aucun seuil n'est modifié par cet audit.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--pair-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = analyze(args.manifest, args.pair_truth)
    write_new_json(args.output, document)
    print(json.dumps({key: document[key] for key in ("meta_alerts", "candidate_pairs", "density")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
