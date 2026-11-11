#!/usr/bin/env python3
"""Vérifie hors ligne l'origine strictement antérieure du degré structurel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyarrow.parquet as pq

from experiment_old_causal_bridge_policies import _audit_prior_degree


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=Path("data/processed/ait_pairs_v3"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"Le rapport existe déjà: {args.output}")
    scenarios = {}
    for cache in sorted(args.cache_root.iterdir()):
        pair_path = cache / "pair_examples.parquet"
        meta_path = cache / "meta_observable.parquet"
        if not pair_path.exists() or not meta_path.exists():
            continue
        frame = pq.read_table(pair_path).to_pandas()
        meta = pq.read_table(meta_path).to_pandas()
        scenarios[cache.name] = _audit_prior_degree(frame, meta)
    result = {
        "kind": "old-causal-bridge-prior-degree-audit",
        "cache_root": str(args.cache_root),
        "uses_complete_candidate_cache_before_supervision_filter": True,
        "all_exact": all(
            item["exact_match_with_pair_id_predecessor_count"]
            for item in scenarios.values()
        ),
        "all_future_predecessor_violations": sum(
            item["future_predecessor_violations"] for item in scenarios.values()
        ),
        "ground_truth_used": False,
        "scenarios": scenarios,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["all_exact"] or result["all_future_predecessor_violations"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
