#!/usr/bin/env python3
"""Ajoute accélération et historique causal à un cache sans changer ses paires."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from advanced_context import ADVANCED_CONTEXT_FEATURE_NAMES, meta_advanced_context
from split_protocol import AIT_SCENARIOS


def augment_pairs(source: Path, destination: Path, context: dict) -> int:
    parquet = pq.ParquetFile(source)
    writer = None
    rows = 0
    try:
        for batch in parquet.iter_batches(batch_size=100_000):
            table = pa.Table.from_batches([batch])
            earlier = table["earlier_meta_id"].to_pylist()
            later = table["later_meta_id"].to_pylist()
            columns = {
                "earlier_activity_acceleration_2s_10s": [context[x]["activity_acceleration_2s_10s"] for x in earlier],
                "earlier_activity_acceleration_10s_60s": [context[x]["activity_acceleration_10s_60s"] for x in earlier],
                "earlier_activity_acceleration_60s_150s": [context[x]["activity_acceleration_60s_150s"] for x in earlier],
                "later_activity_acceleration_2s_10s": [context[x]["activity_acceleration_2s_10s"] for x in later],
                "later_activity_acceleration_10s_60s": [context[x]["activity_acceleration_10s_60s"] for x in later],
                "later_activity_acceleration_60s_150s": [context[x]["activity_acceleration_60s_150s"] for x in later],
                "earlier_compatible_history_known": [context[x]["compatible_history_known"] for x in earlier],
                "earlier_log1p_compatible_history_count": [context[x]["log1p_compatible_history_count"] for x in earlier],
                "earlier_compatible_history_distinct_stages": [context[x]["compatible_history_distinct_stages"] for x in earlier],
                "later_compatible_history_known": [context[x]["compatible_history_known"] for x in later],
                "later_log1p_compatible_history_count": [context[x]["log1p_compatible_history_count"] for x in later],
                "later_compatible_history_distinct_stages": [context[x]["compatible_history_distinct_stages"] for x in later],
            }
            for name in ADVANCED_CONTEXT_FEATURE_NAMES:
                table = table.append_column(name, pa.array(columns[name], type=pa.float32()))
            if writer is None:
                writer = pq.ParquetWriter(destination, table.schema, compression="zstd")
            writer.write_table(table)
            rows += len(table)
    finally:
        if writer is not None:
            writer.close()
    return rows


def augment_scenario(source_root: Path, target_root: Path, scenario: str) -> dict:
    source = source_root / scenario
    target = target_root / scenario
    target.mkdir(parents=True, exist_ok=False)
    for name in ("meta_observable.parquet", "meta_truth.parquet"):
        shutil.copy2(source / name, target / name)
    meta = pq.read_table(source / "meta_observable.parquet").to_pandas()
    context = meta_advanced_context(meta)
    rows = augment_pairs(source / "pair_examples.parquet", target / "pair_examples.parquet", context)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    if rows != manifest["pair_examples"]:
        raise ValueError(f"Nombre de paires modifié pour {scenario}")
    manifest["cache_version"] = 4
    manifest["derived_advanced_context_features"] = ADVANCED_CONTEXT_FEATURE_NAMES
    (target / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root")
    parser.add_argument("target_root")
    parser.add_argument("--scenarios", default=",".join(AIT_SCENARIOS))
    args = parser.parse_args()
    source_root = Path(args.source_root)
    target_root = Path(args.target_root)
    target_root.mkdir(parents=True, exist_ok=False)
    scenarios = tuple(x.strip() for x in args.scenarios.split(",") if x.strip())
    manifests = []
    for scenario in scenarios:
        manifest = augment_scenario(source_root, target_root, scenario)
        manifests.append(manifest)
        print(json.dumps({"scenario": scenario, "pairs": manifest["pair_examples"]}), flush=True)
    (target_root / "manifest.json").write_text(
        json.dumps({"cache_version": 4, "scenarios": manifests}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
