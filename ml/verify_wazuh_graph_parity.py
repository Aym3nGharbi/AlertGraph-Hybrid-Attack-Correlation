#!/usr/bin/env python3
"""Compare l'ancienne reconstruction Wazuh à la version alignée, sans mutation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq


def _hash_edges(frame, mask) -> str:
    rows = frame.loc[mask, ["earlier_meta_id", "later_meta_id"]]
    values = sorted(f"{a}|{b}" for a, b in rows.itertuples(index=False, name=None))
    return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest()


def compare_run(run_root: Path) -> dict:
    old_dir = run_root / "inference-v5"
    new_dir = run_root / "inference-parity-v1"
    old = pq.read_table(old_dir / "pair_predictions.parquet").to_pandas()
    new = pq.read_table(new_dir / "pair_predictions.parquet").to_pandas()
    old_nodes = pq.read_table(old_dir / "nodes.parquet").to_pandas()
    new_nodes = pq.read_table(new_dir / "nodes.parquet").to_pandas()
    ids_equal = (
        old["earlier_meta_id"].astype(str).tolist()
        == new["earlier_meta_id"].astype(str).tolist()
        and old["later_meta_id"].astype(str).tolist()
        == new["later_meta_id"].astype(str).tolist()
    )
    unchanged = {
        "pair_ids": ids_equal,
        "ml_probability": np.array_equal(
            old["ml_probability"].to_numpy(), new["ml_probability"].to_numpy()
        ),
        "ml_votes": np.array_equal(old["ml_votes"].to_numpy(), new["ml_votes"].to_numpy()),
        "ml_only": np.array_equal(old["ml_only"].to_numpy(), new["ml_only"].to_numpy()),
        "ml_and_manual": np.array_equal(
            old["ml_and_manual"].to_numpy(), new["ml_and_manual"].to_numpy()
        ),
    }
    old_legacy = old["manual_core_ml_bridges"].to_numpy(dtype=bool)
    new_legacy = new["manual_core_ml_bridges_legacy_mean"].to_numpy(dtype=bool)
    aligned = new["manual_core_ml_bridges"].to_numpy(dtype=bool)
    old_component = old_nodes["manual_core_ml_bridges_component"].to_numpy()
    new_legacy_component = new_nodes[
        "manual_core_ml_bridges_legacy_mean_component"
    ].to_numpy()
    episode = new["episode_constrained_bridges"].to_numpy(dtype=bool)
    legacy_exact = {
        "edge_decisions": np.array_equal(old_legacy, new_legacy),
        "edge_ids_sha256_old": _hash_edges(old, old_legacy),
        "edge_ids_sha256_new": _hash_edges(new, new_legacy),
        "components": np.array_equal(old_component, new_legacy_component),
    }
    return {
        "run_id": run_root.name,
        "unchanged_inference": unchanged,
        "legacy_reproduction": legacy_exact,
        "comparison": {
            "legacy_edges": int(new_legacy.sum()),
            "aligned_edges": int(aligned.sum()),
            "common_edges": int((new_legacy & aligned).sum()),
            "removed_from_legacy": int((new_legacy & ~aligned).sum()),
            "added_by_aligned": int((~new_legacy & aligned).sum()),
            "legacy_components": int(np.unique(new_legacy_component).size),
            "aligned_components": int(
                new_nodes["manual_core_ml_bridges_component"].nunique()
            ),
            "aligned_edge_ids_sha256": _hash_edges(new, aligned),
        },
        "episode_policy": {
            "edges": int(episode.sum()),
            "is_subset_of_aligned": bool(np.all(~episode | aligned)),
        },
        "passed_non_regression": bool(
            all(unchanged.values())
            and legacy_exact["edge_decisions"]
            and legacy_exact["components"]
            and legacy_exact["edge_ids_sha256_old"]
            == legacy_exact["edge_ids_sha256_new"]
            and np.all(~episode | aligned)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_roots", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    reports = [compare_run(path) for path in args.run_roots]
    result = {
        "kind": "wazuh-legacy-vs-scientific-parity-comparison",
        "all_non_regression_checks_passed": all(
            item["passed_non_regression"] for item in reports
        ),
        "runs": reports,
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists():
            raise FileExistsError(f"Rapport déjà présent: {args.output}")
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not result["all_non_regression_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
