#!/usr/bin/env python3
"""Évalue les graphes SOCBED avec les décisions externes strictement figées."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import igraph as ig
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from evaluate_attack_graphs import _edge_diagnostics, _partition_metrics, _phase_coverage
from socbed_dataset import SOCBED_RUNS


MODELS = ("similarity", "causality", "manual_hybrid", "ml_hybrid")


def _membership(meta: pd.DataFrame, edges: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    vertex = pd.Series(np.arange(len(meta), dtype=np.int32), index=meta["meta_id"])
    if edges.empty:
        graph = ig.Graph(n=len(meta), directed=False)
    else:
        sources = edges["earlier_meta_id"].map(vertex).to_numpy(dtype=np.int32)
        targets = edges["later_meta_id"].map(vertex).to_numpy(dtype=np.int32)
        graph = ig.Graph(
            n=len(meta), edges=np.column_stack((sources, targets)), directed=False
        )
    return (
        np.asarray(graph.connected_components().membership, dtype=np.int32),
        np.asarray(graph.degree(), dtype=np.int32),
    )


def _run_model_metrics(meta: pd.DataFrame, pairs: pd.DataFrame, model: str) -> tuple[dict, np.ndarray]:
    edges = pairs[pairs[f"{model}_prediction"] == 1].copy()
    membership, degrees = _membership(meta, edges)
    components, counts = np.unique(membership, return_counts=True)
    phase = _phase_coverage(meta, membership)["instances"][0]
    report = {
        "nodes": int(len(meta)),
        "predicted_edges": int(len(edges)),
        "components": int(len(components)),
        "largest_component_nodes": int(counts.max()),
        **_edge_diagnostics(meta, edges),
        "partition": _partition_metrics(meta, membership),
        "phase_coverage": phase,
    }
    return report, np.column_stack((membership, degrees))


def _aggregate(reports: list[dict]) -> dict:
    paths = {
        "edge_precision": lambda x: x["edge_precision_known"],
        "incorrect_edges": lambda x: x["incorrect_edges"],
        "bcubed_f1_meta": lambda x: x["partition"]["known_all"]["meta_unweighted"]["bcubed_f1"],
        "ari_meta": lambda x: x["partition"]["known_all"]["meta_unweighted"]["ari"],
        "bcubed_f1_raw": lambda x: x["partition"]["known_all"]["raw_alert_weighted"]["bcubed_f1"],
        "attack_fragmentation": lambda x: x["partition"]["attack_diagnostics_meta"]["mean_fragments_per_attack"],
        "largest_attack_fragment": lambda x: x["partition"]["attack_diagnostics_meta"]["mean_largest_fragment_coverage"],
        "phase_type_coverage": lambda x: x["phase_coverage"]["dominant_component_phase_coverage"],
        "macro_phase_alert_recall": lambda x: x["phase_coverage"]["macro_phase_recall_in_dominant_component"],
        "components": lambda x: x["components"],
        "largest_component_nodes": lambda x: x["largest_component_nodes"],
    }
    result = {}
    for name, getter in paths.items():
        values = np.array([getter(item) for item in reports], dtype=np.float64)
        result[name] = {
            "macro_mean": float(values.mean()),
            "macro_std": float(values.std(ddof=1)),
            "worst_run": float(values.min()),
            "best_run": float(values.max()),
            "total": float(values.sum()) if name == "incorrect_edges" else None,
        }
    return result


def evaluate(cache_root: Path, prediction_root: Path, output_root: Path) -> dict:
    output_root.mkdir(parents=True, exist_ok=False)
    per_run = []
    by_model = {model: [] for model in MODELS}
    for run_id in SOCBED_RUNS:
        observable = pq.read_table(cache_root / run_id / "meta_observable.parquet").to_pandas()
        truth = pq.read_table(cache_root / run_id / "meta_truth.parquet").to_pandas()
        meta = observable.merge(truth, on="meta_id", validate="one_to_one")
        meta["member_count"] = meta["member_alert_ids"].map(len)
        pairs = pq.read_table(
            prediction_root / run_id / "pair_predictions.parquet"
        ).to_pandas()
        model_reports = {}
        for model in MODELS:
            report, membership_degree = _run_model_metrics(meta, pairs, model)
            model_reports[model] = report
            by_model[model].append(report)
            meta[f"{model}_component"] = membership_degree[:, 0]
            meta[f"{model}_degree"] = membership_degree[:, 1]
        run_report = {"run_id": run_id, "models": model_reports}
        per_run.append(run_report)
        target = output_root / run_id
        target.mkdir()
        pq.write_table(
            pa.Table.from_pandas(meta, preserve_index=False),
            target / "nodes.parquet",
            compression="zstd",
        )
        (target / "metrics.json").write_text(
            json.dumps(run_report, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"run": run_id}), flush=True)

    report = {
        "kind": "strict-external-graph-evaluation",
        "external_dataset": "SOCBED ACSAC 2021",
        "external_tuning": False,
        "grouping": "connected components of frozen positive pair decisions",
        "per_run": per_run,
        "macro": {model: _aggregate(by_model[model]) for model in MODELS},
    }
    (output_root / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cache_root", type=Path)
    parser.add_argument("prediction_root", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    report = evaluate(args.cache_root, args.prediction_root, args.output_root)
    print(json.dumps(report["macro"], indent=2))


if __name__ == "__main__":
    main()
