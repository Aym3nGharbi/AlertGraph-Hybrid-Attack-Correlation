#!/usr/bin/env python3
"""Reconstruit et évalue les graphes avec des prédictions strictement hors-fold."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import igraph as ig
import leidenalg
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from evaluate_nested_baselines import metrics as relation_metrics
from evaluate_nested_ml import available_feature_names
from evaluate_rarity_ml import load_rarity_data, training_idf
from graph_metrics import attack_group_diagnostics, clustering_metrics
from optimize_final_nested_ml import (
    FinalSearchConfiguration,
    _assemble_training,
    _positions,
    _transform,
    make_model,
)
from feature_sets import select_feature_profile
from split_protocol import nested_leave_one_scenario_out


PHASE_ORDER = {
    "network_scans": 0,
    "service_scans": 1,
    "wpscan": 2,
    "dirb": 3,
    "webshell": 4,
    "cracking": 5,
    "reverse_shell": 6,
    "privilege_escalation": 7,
    "service_stop": 0,
    "dnsteal": 1,
    **{f"step_{index}": index - 1 for index in range(1, 10)},
}


def _gold_labels(meta: pd.DataFrame) -> np.ndarray:
    labels = np.empty(len(meta), dtype=object)
    for index, row in enumerate(meta.itertuples(index=False)):
        if pd.isna(row.is_attack):
            labels[index] = None
        elif bool(row.is_attack):
            labels[index] = row.attack_instance_id
        else:
            labels[index] = f"benign:{row.meta_id}"
    return labels


def _partition_metrics(meta: pd.DataFrame, membership: np.ndarray) -> dict:
    gold = _gold_labels(meta)
    known = gold != None  # noqa: E711
    attack = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    member_weights = meta["member_count"].to_numpy(dtype=np.int64)
    report = {}
    for scope, mask in (("known_all", known), ("attacks_only", attack)):
        report[scope] = {
            "meta_unweighted": clustering_metrics(gold[mask], membership[mask]),
            "raw_alert_weighted": clustering_metrics(
                gold[mask], membership[mask], member_weights[mask]
            ),
        }
    report["attack_diagnostics_meta"] = attack_group_diagnostics(
        gold[attack], membership[attack], np.ones(int(attack.sum()), dtype=np.int64)
    )
    report["attack_diagnostics_raw"] = attack_group_diagnostics(
        gold[attack], membership[attack], member_weights[attack]
    )
    return report


def _edge_diagnostics(meta: pd.DataFrame, edge_frame: pd.DataFrame) -> dict:
    if edge_frame.empty:
        return {
            "predicted_edges": 0,
            "correct_attack_edges": 0,
            "incorrect_edges": 0,
            "unknown_truth_edges": 0,
            "edge_precision_known": 0.0,
            "phase_order_evaluable_edges": 0,
            "phase_order_coherent_rate": 0.0,
        }
    truth = meta.set_index("meta_id")
    left = truth.loc[edge_frame["earlier_meta_id"]]
    right = truth.loc[edge_frame["later_meta_id"]]
    left_attack = left["is_attack"].fillna(False).to_numpy(dtype=bool)
    right_attack = right["is_attack"].fillna(False).to_numpy(dtype=bool)
    same_instance = (
        left["attack_instance_id"].to_numpy()
        == right["attack_instance_id"].to_numpy()
    )
    correct = left_attack & right_attack & same_instance
    known = left["is_attack"].notna().to_numpy() & right["is_attack"].notna().to_numpy()
    incorrect = known & ~correct

    evaluable = []
    coherent = []
    for is_correct, left_phases, right_phases in zip(
        correct,
        left["ground_truth_phases"],
        right["ground_truth_phases"],
    ):
        if not is_correct or len(left_phases) != 1 or len(right_phases) != 1:
            evaluable.append(False)
            coherent.append(False)
            continue
        left_order = PHASE_ORDER.get(left_phases[0])
        right_order = PHASE_ORDER.get(right_phases[0])
        can_evaluate = left_order is not None and right_order is not None
        evaluable.append(can_evaluate)
        coherent.append(can_evaluate and right_order >= left_order)
    evaluable_array = np.asarray(evaluable, dtype=bool)
    coherent_array = np.asarray(coherent, dtype=bool)
    return {
        "predicted_edges": int(len(edge_frame)),
        "correct_attack_edges": int(correct.sum()),
        "incorrect_edges": int(incorrect.sum()),
        "unknown_truth_edges": int((~known).sum()),
        "edge_precision_known": float(correct.sum() / known.sum()) if known.any() else 0.0,
        "phase_order_evaluable_edges": int(evaluable_array.sum()),
        "phase_order_coherent_rate": (
            float(coherent_array[evaluable_array].mean()) if evaluable_array.any() else 0.0
        ),
    }


def _phase_coverage(meta: pd.DataFrame, membership: np.ndarray) -> dict:
    attack = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    weights = meta["member_count"].to_numpy(dtype=np.int64)
    instances = meta["attack_instance_id"].to_numpy()
    reports = []
    for instance in sorted(set(instances[attack])):
        mask = attack & (instances == instance)
        labels, inverse = np.unique(membership[mask], return_inverse=True)
        cluster_weights = np.bincount(inverse, weights=weights[mask])
        dominant = labels[int(cluster_weights.argmax())]
        dominant_mask = mask & (membership == dominant)
        all_phases = set().union(*meta.loc[mask, "ground_truth_phases"])
        dominant_phases = set().union(*meta.loc[dominant_mask, "ground_truth_phases"])
        recalls = []
        for phase in all_phases:
            phase_mask = mask & meta["ground_truth_phases"].map(lambda values: phase in values).to_numpy()
            recalls.append(float(weights[phase_mask & dominant_mask].sum() / weights[phase_mask].sum()))
        reports.append(
            {
                "attack_instance_id": instance,
                "phase_count": len(all_phases),
                "dominant_component_phase_coverage": (
                    len(dominant_phases & all_phases) / len(all_phases) if all_phases else 0.0
                ),
                "macro_phase_recall_in_dominant_component": float(np.mean(recalls)) if recalls else 0.0,
            }
        )
    return {"instances": reports}


def evaluate_graphs(cache_root: Path, optimization_report: Path, output_root: Path) -> dict:
    optimization = json.loads(optimization_report.read_text(encoding="utf-8"))
    available = available_feature_names(cache_root)
    master_features = select_feature_profile(available, "directional_graph")
    data = load_rarity_data(cache_root, master_features)
    outer_folds = {item.test_scenario: item for item in nested_leave_one_scenario_out()}
    output_root.mkdir(parents=True, exist_ok=False)
    scenario_reports = []

    for fold in optimization["folds"]:
        scenario = fold["test_scenario"]
        outer = outer_folds[scenario]
        configuration = FinalSearchConfiguration(**fold["selected_configuration"])
        positions = _positions(master_features, configuration)
        idf = training_idf(data, outer.development_scenarios) if configuration.use_rarity else None
        x_train, y_train, weights = _assemble_training(
            data, outer.development_scenarios, 50_000, positions, idf
        )
        model = make_model(
            configuration,
            max_iter=int(fold["selected_iterations"]),
            early_stopping=False,
        )
        model.fit(x_train, y_train, sample_weight=weights)
        test = data[scenario]
        probability = model.predict_proba(_transform(test, positions, idf))[:, 1]
        reproduced = relation_metrics(test.y, probability, fold["selected_threshold"])
        if abs(reproduced["average_precision"] - fold["test_metrics"]["average_precision"]) > 1e-10:
            raise ValueError(f"Prédictions non reproductibles pour {scenario}")

        pair_frame = pq.read_table(
            cache_root / scenario / "pair_examples.parquet",
            columns=["earlier_meta_id", "later_meta_id", "target"],
        ).to_pandas()
        pair_frame = pair_frame[pair_frame["target"].notna()].copy()
        pair_frame["probability"] = probability
        edge_frame = pair_frame[pair_frame["probability"] >= fold["selected_threshold"]].copy()

        observable = pq.read_table(cache_root / scenario / "meta_observable.parquet").to_pandas()
        truth = pq.read_table(cache_root / scenario / "meta_truth.parquet").to_pandas()
        meta = observable.merge(truth, on="meta_id", validate="one_to_one")
        meta["member_count"] = meta["member_alert_ids"].map(len)
        vertex = pd.Series(np.arange(len(meta), dtype=np.int32), index=meta["meta_id"])
        sources = edge_frame["earlier_meta_id"].map(vertex).to_numpy(dtype=np.int32)
        targets = edge_frame["later_meta_id"].map(vertex).to_numpy(dtype=np.int32)
        graph = ig.Graph(
            n=len(meta),
            edges=np.column_stack((sources, targets)),
            directed=False,
        )
        graph.es["weight"] = edge_frame["probability"].to_list()
        connected = np.asarray(graph.connected_components().membership, dtype=np.int32)
        leiden = np.asarray(
            leidenalg.find_partition(
                graph,
                leidenalg.ModularityVertexPartition,
                weights="weight",
                n_iterations=-1,
                seed=20261031,
            ).membership,
            dtype=np.int32,
        )
        degrees = np.asarray(graph.degree(), dtype=np.int32)
        meta["predicted_degree"] = degrees
        meta["connected_component"] = connected
        meta["leiden_community"] = leiden
        edge_report = _edge_diagnostics(meta, edge_frame)
        scenario_report = {
            "scenario": scenario,
            "configuration": fold["selected_configuration"],
            "threshold": fold["selected_threshold"],
            "relation_metrics_reproduced": reproduced,
            "nodes": len(meta),
            **edge_report,
            "connected_components": _partition_metrics(meta, connected),
            "leiden": _partition_metrics(meta, leiden),
            "connected_phase_coverage": _phase_coverage(meta, connected),
            "leiden_phase_coverage": _phase_coverage(meta, leiden),
        }
        scenario_reports.append(scenario_report)
        target_dir = output_root / scenario
        target_dir.mkdir()
        pq.write_table(pa.Table.from_pandas(meta, preserve_index=False), target_dir / "nodes.parquet", compression="zstd")
        pq.write_table(pa.Table.from_pandas(edge_frame, preserve_index=False), target_dir / "edges.parquet", compression="zstd")
        (target_dir / "metrics.json").write_text(
            json.dumps(scenario_report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"scenario": scenario, "nodes": len(meta), "edges": len(edge_frame)}, ensure_ascii=False), flush=True)

    report = {
        "kind": "strict-out-of-fold-attack-graph-evaluation",
        "optimization_report": str(optimization_report),
        "community_method": "Leiden weighted modularity, no test-tuned resolution",
        "scenarios": scenario_reports,
    }
    (output_root / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("optimization_report")
    parser.add_argument("output_root")
    args = parser.parse_args()
    evaluate_graphs(Path(args.cache_root), Path(args.optimization_report), Path(args.output_root))


if __name__ == "__main__":
    main()
