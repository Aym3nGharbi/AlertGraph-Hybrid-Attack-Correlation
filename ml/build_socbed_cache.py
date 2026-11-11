#!/usr/bin/env python3
"""Construit le cache de paires externe SOCBED avec le protocole AIT figé."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from audit_pair_candidates import add_observable_context, collapse_labeled_records
from build_pair_dataset import (
    _combined_candidate,
    _pair_row,
    _write_meta_tables,
    _write_pair_rows,
)
from candidates import iter_local_candidates
from causal_bridges import generate_causal_bridges
from socbed_dataset import SOCBED_RUNS, iter_socbed_run


def build_run(archive_path: Path, output_root: Path, run_id: str) -> dict:
    target = output_root / run_id
    target.mkdir(parents=True, exist_ok=False)
    meta_alerts = add_observable_context(
        collapse_labeled_records(iter_socbed_run(archive_path, run_id), 2.0)
    )
    _write_meta_tables(meta_alerts, target)
    observable = [item.to_meta_alert() for item in meta_alerts]
    index = {item.meta_id: item for item in meta_alerts}
    causal = generate_causal_bridges(observable, max_bridges_per_alert=5)
    remaining_causal = {
        (item.earlier_meta_id, item.later_meta_id): item for item in causal
    }

    def rows():
        for local in iter_local_candidates(observable, 60.0, 50):
            key = (local.earlier_meta_id, local.later_meta_id)
            causal_match = remaining_causal.pop(key, None)
            yield _pair_row(
                run_id,
                _combined_candidate(local, causal_match) if causal_match else local,
                index,
            )
        for key in sorted(remaining_causal):
            yield _pair_row(run_id, remaining_causal[key], index)

    pair_path = target / "pair_examples.parquet"
    pair_count = _write_pair_rows(rows(), pair_path)
    target_counts = Counter()
    if pair_count:
        import pyarrow.parquet as pq

        for batch in pq.ParquetFile(pair_path).iter_batches(columns=["target"]):
            target_counts.update(batch.column(0).to_pylist())
    manifest = {
        "cache_version": 2,
        "dataset": "SOCBED ACSAC 2021 external validation",
        "scenario": run_id,
        "parameters": {
            "collapse_seconds": 2.0,
            "window_seconds": 60.0,
            "cap": 50,
            "max_causal_bridges": 5,
        },
        "raw_alerts": sum(len(item.member_alert_ids) for item in meta_alerts),
        "meta_alerts": len(meta_alerts),
        "pair_examples": pair_count,
        "positive_pairs": target_counts[1],
        "negative_pairs": target_counts[0],
        "causal_candidates": len(causal),
    }
    (target / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=False)
    manifests = []
    for run_id in SOCBED_RUNS:
        manifest = build_run(args.archive, args.output_root, run_id)
        manifests.append(manifest)
        print(json.dumps(manifest), flush=True)
    (args.output_root / "manifest.json").write_text(
        json.dumps({"cache_version": 2, "scenarios": manifests}, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
