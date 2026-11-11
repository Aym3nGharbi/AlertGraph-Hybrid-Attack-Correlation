#!/usr/bin/env python3
"""Construit le cache externe DARPA avec le protocole candidat gelé."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import pyarrow.parquet as pq

from audit_pair_candidates import add_observable_context, collapse_labeled_records
from build_pair_dataset import _combined_candidate, _pair_row, _write_meta_tables, _write_pair_rows
from candidates import iter_local_candidates
from causal_bridges import generate_causal_bridges
from darpa_dataset import DARPA_SCENARIOS, iter_darpa_scenario


def build_scenario(dataset_root: Path, eve_root: Path, output_root: Path, scenario: str) -> dict:
    target = output_root / scenario
    target.mkdir(parents=True, exist_ok=False)
    meta_alerts = add_observable_context(
        collapse_labeled_records(iter_darpa_scenario(dataset_root, eve_root, scenario), 2.0)
    )
    _write_meta_tables(meta_alerts, target)
    observable = [item.to_meta_alert() for item in meta_alerts]
    index = {item.meta_id: item for item in meta_alerts}
    causal = generate_causal_bridges(observable, max_bridges_per_alert=5)
    remaining = {(item.earlier_meta_id, item.later_meta_id): item for item in causal}

    def rows():
        for local in iter_local_candidates(observable, 60.0, 50):
            key = (local.earlier_meta_id, local.later_meta_id)
            bridge = remaining.pop(key, None)
            yield _pair_row(
                scenario,
                _combined_candidate(local, bridge) if bridge is not None else local,
                index,
            )
        for key in sorted(remaining):
            yield _pair_row(scenario, remaining[key], index)

    pair_path = target / "pair_examples.parquet"
    pair_count = _write_pair_rows(rows(), pair_path)
    counts = Counter()
    if pair_count:
        for batch in pq.ParquetFile(pair_path).iter_batches(columns=["target"]):
            counts.update(batch.column(0).to_pylist())
    phases = Counter(
        phase for item in meta_alerts for phase in item.ground_truth_phases
    )
    manifest = {
        "cache_version": 2,
        "dataset": "DARPA 2000 LLDOS strict external validation",
        "scenario": scenario,
        "parameters": {
            "collapse_seconds": 2.0,
            "window_seconds": 60.0,
            "cap": 50,
            "max_causal_bridges": 5,
        },
        "raw_alerts": sum(len(item.member_alert_ids) for item in meta_alerts),
        "meta_alerts": len(meta_alerts),
        "attack_meta_alerts": sum(item.is_attack is True for item in meta_alerts),
        "benign_meta_alerts": sum(item.is_attack is False for item in meta_alerts),
        "phase_meta_alerts": dict(sorted(phases.items())),
        "pair_examples": pair_count,
        "positive_pairs": counts[1],
        "negative_pairs": counts[0],
        "causal_candidates": len(causal),
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("eve_root", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=False)
    manifests = []
    for scenario in DARPA_SCENARIOS:
        manifest = build_scenario(args.dataset_root, args.eve_root, args.output_root, scenario)
        manifests.append(manifest)
        print(json.dumps(manifest), flush=True)
    (args.output_root / "manifest.json").write_text(
        json.dumps({"cache_version": 2, "scenarios": manifests}, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

