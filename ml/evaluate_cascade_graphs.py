#!/usr/bin/env python3
"""Teste ML relationnel + filtre manuel figé pour la construction du graphe."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from evaluate_attack_graphs import _edge_diagnostics, _partition_metrics, _phase_coverage
from evaluate_nested_baselines import load_scores
from evaluate_socbed_external import decision_metrics
from optimize_graph_thresholds import component_membership, load_meta, load_pair_ids
from socbed_dataset import SOCBED_RUNS
from split_protocol import AIT_SCENARIOS


def graph_report(meta: pd.DataFrame, pairs: pd.DataFrame, prediction: np.ndarray) -> dict:
    membership, edges, _ = component_membership(
        meta, pairs, prediction.astype(np.float32), 0.5
    )
    phase_items = _phase_coverage(meta, membership)["instances"]
    phase_type = float(
        np.mean([item["dominant_component_phase_coverage"] for item in phase_items])
    ) if phase_items else 0.0
    phase_recall = float(
        np.mean([item["macro_phase_recall_in_dominant_component"] for item in phase_items])
    ) if phase_items else 0.0
    partition = _partition_metrics(meta, membership)
    edge = _edge_diagnostics(meta, edges)
    return {
        "predicted_edges": int(len(edges)),
        "edge_precision": edge["edge_precision_known"],
        "incorrect_edges": edge["incorrect_edges"],
        "bcubed_meta_all": partition["known_all"]["meta_unweighted"]["bcubed_f1"],
        "ari_meta_all": partition["known_all"]["meta_unweighted"]["ari"],
        "bcubed_raw_all": partition["known_all"]["raw_alert_weighted"]["bcubed_f1"],
        "bcubed_meta_attacks": partition["attacks_only"]["meta_unweighted"]["bcubed_f1"],
        "ari_meta_attacks": partition["attacks_only"]["meta_unweighted"]["ari"],
        "bcubed_raw_attacks": partition["attacks_only"]["raw_alert_weighted"]["bcubed_f1"],
        "attack_fragments": partition["attack_diagnostics_meta"]["mean_fragments_per_attack"],
        "largest_attack_fragment": partition["attack_diagnostics_meta"]["mean_largest_fragment_coverage"],
        "phase_type_coverage": phase_type,
        "phase_alert_recall": phase_recall,
    }


def aggregate(items: list[dict]) -> dict:
    result = {}
    for name in items[0]:
        values = np.array([item[name] for item in items], dtype=float)
        result[name] = {
            "macro_mean": float(values.mean()),
            "macro_std": float(values.std(ddof=1)),
            "total": int(values.sum()) if name in {"predicted_edges", "incorrect_edges"} else None,
        }
    return result


def evaluate_ait(cache: Path, graph_root: Path, alpha: float, threshold: float) -> dict:
    per_scenario = []
    reports = {"manual_graph": [], "hard_cascade": []}
    for scenario in AIT_SCENARIOS:
        pairs = load_pair_ids(cache, scenario)
        scores = load_scores(cache, scenario)
        manual = alpha * scores["similarity"] + (1.0 - alpha) * scores["causality"]
        ml_edges = pq.read_table(
            graph_root / scenario / "edges.parquet",
            columns=["earlier_meta_id", "later_meta_id"],
        ).to_pandas()
        positive_keys = set(zip(ml_edges["earlier_meta_id"], ml_edges["later_meta_id"]))
        ml_prediction = np.fromiter(
            (
                (left, right) in positive_keys
                for left, right in zip(pairs["earlier_meta_id"], pairs["later_meta_id"])
            ),
            dtype=bool,
            count=len(pairs),
        )
        manual_prediction = manual >= threshold
        prediction = ml_prediction & manual_prediction
        meta = load_meta(cache, scenario)
        manual_graph = graph_report(meta, pairs, manual_prediction)
        cascade_graph = graph_report(meta, pairs, prediction)
        relation = decision_metrics(
            pairs["target"].to_numpy(dtype=np.int8),
            prediction.astype(np.float32),
            prediction.astype(np.int8),
        )
        reports["manual_graph"].append(manual_graph)
        reports["hard_cascade"].append(cascade_graph)
        per_scenario.append(
            {
                "scenario": scenario,
                "cascade_relation": relation,
                "manual_graph": manual_graph,
                "hard_cascade_graph": cascade_graph,
            }
        )
    return {
        "per_scenario": per_scenario,
        "macro_graph": {name: aggregate(items) for name, items in reports.items()},
    }


def evaluate_socbed(cache: Path, prediction_root: Path, alpha: float, threshold: float) -> dict:
    per_run = []
    graph_reports = {"manual_graph": [], "hard_cascade": []}
    relation_reports = []
    for run_id in SOCBED_RUNS:
        pairs = pq.read_table(
            prediction_root / run_id / "pair_predictions.parquet"
        ).to_pandas()
        manual = (
            alpha * pairs["similarity_score"].to_numpy()
            + (1.0 - alpha) * pairs["causality_score"].to_numpy()
        )
        manual_prediction = manual >= threshold
        prediction = (
            pairs["ml_hybrid_prediction"].to_numpy(dtype=bool)
            & manual_prediction
        )
        relation = decision_metrics(
            pairs["target"].to_numpy(dtype=np.int8),
            pairs["ml_hybrid_score"].to_numpy(dtype=float),
            prediction.astype(np.int8),
        )
        meta = load_meta(cache, run_id)
        pair_ids = pairs[["earlier_meta_id", "later_meta_id", "target"]].copy()
        manual_graph = graph_report(meta, pair_ids, manual_prediction)
        cascade_graph = graph_report(meta, pair_ids, prediction)
        relation_reports.append(relation)
        graph_reports["manual_graph"].append(manual_graph)
        graph_reports["hard_cascade"].append(cascade_graph)
        per_run.append(
            {
                "run_id": run_id,
                "cascade_relation": relation,
                "manual_graph": manual_graph,
                "hard_cascade_graph": cascade_graph,
            }
        )
    relation_names = (
        "average_precision", "precision", "recall", "f1", "mcc", "balanced_accuracy"
    )
    macro_relation = {
        name: {
            "macro_mean": float(np.mean([item[name] for item in relation_reports])),
            "macro_std": float(np.std([item[name] for item in relation_reports], ddof=1)),
        }
        for name in relation_names
    }
    return {
        "per_run": per_run,
        "macro_relation": macro_relation,
        "macro_graph": {name: aggregate(items) for name, items in graph_reports.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ait_cache", type=Path)
    parser.add_argument("ait_graphs", type=Path)
    parser.add_argument("socbed_cache", type=Path)
    parser.add_argument("socbed_predictions", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--alpha", type=float, default=0.25)
    parser.add_argument("--manual-threshold", type=float, default=0.50)
    args = parser.parse_args()
    report = {
        "kind": "ml-ranking-manual-graph-gate",
        "rule": "ML positive AND manual hybrid positive",
        "alpha": args.alpha,
        "manual_threshold": args.manual_threshold,
        "parameter_source": "nested AIT internal validation; identical choice in 8/8 folds",
        "ait": evaluate_ait(args.ait_cache, args.ait_graphs, args.alpha, args.manual_threshold),
        "socbed": evaluate_socbed(
            args.socbed_cache,
            args.socbed_predictions,
            args.alpha,
            args.manual_threshold,
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ait": report["ait"]["macro_graph"], "socbed": report["socbed"] | {"per_run": "omitted"}}, indent=2))


if __name__ == "__main__":
    main()
