#!/usr/bin/env python3
"""Ajoute le contexte du DAG candidat à un cache existant, sans changer ses paires."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from graph_context import (
    GRAPH_CONTEXT_FEATURE_NAMES,
    pair_graph_context,
    predecessor_index,
)
from split_protocol import AIT_SCENARIOS


def _edges(pair_path: Path):
    parquet = pq.ParquetFile(pair_path)
    for batch in parquet.iter_batches(
        columns=["earlier_meta_id", "later_meta_id"], batch_size=100_000
    ):
        earlier = batch.column(0).to_pylist()
        later = batch.column(1).to_pylist()
        yield from zip(earlier, later)


def augment_pairs(source: Path, destination: Path) -> int:
    predecessors = predecessor_index(_edges(source))
    parquet = pq.ParquetFile(source)
    writer = None
    rows = 0
    try:
        for batch in parquet.iter_batches(batch_size=100_000):
            table = pa.Table.from_batches([batch])
            earlier = table["earlier_meta_id"].to_pylist()
            later = table["later_meta_id"].to_pylist()
            values = [
                pair_graph_context(left, right, predecessors)
                for left, right in zip(earlier, later)
            ]
            for index, name in enumerate(GRAPH_CONTEXT_FEATURE_NAMES):
                table = table.append_column(
                    name,
                    pa.array((item[index] for item in values), type=pa.float32()),
                )
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

    rows = augment_pairs(
        source / "pair_examples.parquet", target / "pair_examples.parquet"
    )
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    if rows != manifest["pair_examples"]:
        raise ValueError(
            f"Nombre de paires modifié pour {scenario}: {rows} != "
            f"{manifest['pair_examples']}"
        )
    manifest["cache_version"] = 3
    manifest["derived_graph_context_features"] = GRAPH_CONTEXT_FEATURE_NAMES
    (target / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
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
    scenarios = tuple(
        item.strip() for item in args.scenarios.split(",") if item.strip()
    )
    manifests = []
    for scenario in scenarios:
        manifest = augment_scenario(source_root, target_root, scenario)
        manifests.append(manifest)
        print(
            json.dumps(
                {"scenario": scenario, "pairs": manifest["pair_examples"]},
                ensure_ascii=False,
            ),
            flush=True,
        )
    (target_root / "manifest.json").write_text(
        json.dumps(
            {"cache_version": 3, "scenarios": manifests},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
