#!/usr/bin/env python3
"""Sélectionne le seuil graphique dans les validations internes uniquement."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import igraph as ig
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from evaluate_attack_graphs import (
    _edge_diagnostics,
    _gold_labels,
    _partition_metrics,
    _phase_coverage,
)
from evaluate_nested_baselines import metrics as relation_metrics
from evaluate_nested_ml import available_feature_names, balanced_validation_weights
from evaluate_rarity_ml import load_rarity_data, training_idf
from feature_sets import select_feature_profile
from graph_metrics import attack_group_diagnostics, clustering_metrics
from optimize_final_nested_ml import (
    FinalSearchConfiguration,
    _assemble_training,
    _positions,
    _transform,
    make_model,
)
from split_protocol import nested_leave_one_scenario_out


GRAPH_THRESHOLDS = (0.30, 0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95)


def select_graph_threshold(evaluations: list[dict]) -> dict:
    """Minimise les fusions, puis maximise B-cubed et le rappel des phases."""

    minimum_fused_scenarios = min(item["fused_scenarios"] for item in evaluations)
    eligible = [
        item for item in evaluations
        if item["fused_scenarios"] == minimum_fused_scenarios
    ]
    minimum_fused_clusters = min(item["total_fused_clusters"] for item in eligible)
    eligible = [
        item for item in eligible
        if item["total_fused_clusters"] == minimum_fused_clusters
    ]
    return max(
        eligible,
        key=lambda item: (
            item["macro_meta_bcubed_f1"],
            item["macro_phase_recall"],
            item["macro_edge_precision"],
            item["threshold"],
        ),
    )


def load_meta(cache_root: Path, scenario: str) -> pd.DataFrame:
    observable = pq.read_table(cache_root / scenario / "meta_observable.parquet").to_pandas()
    truth = pq.read_table(cache_root / scenario / "meta_truth.parquet").to_pandas()
    meta = observable.merge(truth, on="meta_id", validate="one_to_one")
    meta["member_count"] = meta["member_alert_ids"].map(len)
    return meta


def load_pair_ids(cache_root: Path, scenario: str) -> pd.DataFrame:
    frame = pq.read_table(
        cache_root / scenario / "pair_examples.parquet",
        columns=["earlier_meta_id", "later_meta_id", "target"],
    ).to_pandas()
    return frame[frame["target"].notna()].copy()


def component_membership(
    meta: pd.DataFrame,
    pairs: pd.DataFrame,
    probability: np.ndarray,
    threshold: float,
) -> tuple[np.ndarray, pd.DataFrame, np.ndarray]:
    edge_mask = probability >= threshold
    edges = pairs.loc[edge_mask, ["earlier_meta_id", "later_meta_id", "target"]].copy()
    edges["probability"] = probability[edge_mask]
    vertex = pd.Series(np.arange(len(meta), dtype=np.int32), index=meta["meta_id"])
    sources = edges["earlier_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    targets = edges["later_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    graph = ig.Graph(n=len(meta), edges=np.column_stack((sources, targets)), directed=False)
    return np.asarray(graph.connected_components().membership, dtype=np.int32), edges, np.asarray(graph.degree(), dtype=np.int32)


def graph_validation_metrics(
    meta: pd.DataFrame,
    membership: np.ndarray,
    edges: pd.DataFrame,
) -> dict[str, float | int]:
    gold = _gold_labels(meta)
    attack = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    clustering = clustering_metrics(gold[attack], membership[attack])
    diagnostics = attack_group_diagnostics(
        gold[attack], membership[attack], np.ones(int(attack.sum()), dtype=np.int64)
    )
    phase = _phase_coverage(meta, membership)["instances"]
    phase_recall = float(np.mean([x["macro_phase_recall_in_dominant_component"] for x in phase])) if phase else 0.0
    edge = _edge_diagnostics(meta, edges)
    return {
        "meta_bcubed_f1": clustering["bcubed_f1"],
        "meta_ari": clustering["ari"],
        "fused_attack_clusters": diagnostics["fused_attack_clusters"],
        "phase_recall": phase_recall,
        "edge_precision": edge["edge_precision_known"],
        "predicted_edges": edge["predicted_edges"],
    }


def prepare_fast_graph_truth(meta: pd.DataFrame) -> dict:
    """Encode une fois les vérités nécessaires aux dix seuils internes."""

    attack = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    attack_indices = np.flatnonzero(attack)
    instances, gold_codes = np.unique(
        meta.loc[attack, "attack_instance_id"].to_numpy(), return_inverse=True
    )
    phase_lists = meta.loc[attack, "ground_truth_phases"].to_list()
    phases = sorted(set().union(*phase_lists)) if phase_lists else []
    phase_masks = {
        phase: np.fromiter((phase in values for values in phase_lists), dtype=bool)
        for phase in phases
    }
    return {
        "attack_indices": attack_indices,
        "gold_codes": gold_codes,
        "instance_count": len(instances),
        "weights": meta.loc[attack, "member_count"].to_numpy(dtype=np.float64),
        "phase_masks": phase_masks,
    }


def fast_graph_validation_metrics(
    prepared: dict,
    membership: np.ndarray,
    selected_targets: np.ndarray,
) -> dict[str, float | int]:
    """Version vectorisée utilisée pendant la grille interne."""

    predicted = membership[prepared["attack_indices"]]
    gold = prepared["gold_codes"]
    weights = prepared["weights"]
    clustering = clustering_metrics(gold, predicted)

    unique_pairs = np.unique(np.column_stack((predicted, gold)), axis=0)
    gold_classes_per_cluster = np.bincount(unique_pairs[:, 0])
    fused = int(np.count_nonzero(gold_classes_per_cluster > 1))

    instance_phase_recalls = []
    for instance_code in range(prepared["instance_count"]):
        instance_mask = gold == instance_code
        labels, inverse = np.unique(predicted[instance_mask], return_inverse=True)
        cluster_weights = np.bincount(inverse, weights=weights[instance_mask])
        dominant = labels[int(cluster_weights.argmax())]
        recalls = []
        for phase_mask in prepared["phase_masks"].values():
            relevant = instance_mask & phase_mask
            denominator = weights[relevant].sum()
            if denominator:
                recalls.append(
                    float(weights[relevant & (predicted == dominant)].sum() / denominator)
                )
        if recalls:
            instance_phase_recalls.append(float(np.mean(recalls)))

    return {
        "meta_bcubed_f1": clustering["bcubed_f1"],
        "meta_ari": clustering["ari"],
        "fused_attack_clusters": fused,
        "phase_recall": float(np.mean(instance_phase_recalls)) if instance_phase_recalls else 0.0,
        "edge_precision": float(selected_targets.mean()) if len(selected_targets) else 0.0,
        "predicted_edges": int(len(selected_targets)),
    }


def optimize_graph_thresholds(cache_root: Path, optimization_report: Path, output_root: Path) -> dict:
    optimization = json.loads(optimization_report.read_text(encoding="utf-8"))
    available = available_feature_names(cache_root)
    master_features = select_feature_profile(available, "directional_graph")
    data = load_rarity_data(cache_root, master_features)
    outer_map = {item.test_scenario: item for item in nested_leave_one_scenario_out()}
    output_root.mkdir(parents=True, exist_ok=False)
    scenario_reports = []

    for fold in optimization["folds"]:
        scenario = fold["test_scenario"]
        outer = outer_map[scenario]
        configuration = FinalSearchConfiguration(**fold["selected_configuration"])
        positions = _positions(master_features, configuration)
        validation_reports = []
        for inner in outer.inner_folds:
            idf = training_idf(data, inner.train_scenarios) if configuration.use_rarity else None
            x_train, y_train, weights = _assemble_training(
                data, inner.train_scenarios, 20_000, positions, idf
            )
            validation = data[inner.validation_scenario]
            x_validation = _transform(validation, positions, idf)
            model = make_model(configuration)
            model.fit(
                x_train,
                y_train,
                sample_weight=weights,
                X_val=x_validation,
                y_val=validation.y,
                sample_weight_val=balanced_validation_weights(validation.y),
            )
            probability = model.predict_proba(x_validation)[:, 1]
            meta = load_meta(cache_root, inner.validation_scenario)
            pairs = load_pair_ids(cache_root, inner.validation_scenario)
            prepared = prepare_fast_graph_truth(meta)
            threshold_metrics = {}
            for threshold in GRAPH_THRESHOLDS:
                membership, edges, _ = component_membership(meta, pairs, probability, threshold)
                threshold_metrics[str(threshold)] = fast_graph_validation_metrics(
                    prepared,
                    membership,
                    edges["target"].to_numpy(dtype=np.int8),
                )
            validation_reports.append(
                {"validation_scenario": inner.validation_scenario, "thresholds": threshold_metrics}
            )

        evaluations = []
        for threshold in GRAPH_THRESHOLDS:
            items = [x["thresholds"][str(threshold)] for x in validation_reports]
            evaluations.append(
                {
                    "threshold": threshold,
                    "fused_scenarios": sum(x["fused_attack_clusters"] > 0 for x in items),
                    "total_fused_clusters": sum(x["fused_attack_clusters"] for x in items),
                    "macro_meta_bcubed_f1": float(np.mean([x["meta_bcubed_f1"] for x in items])),
                    "macro_meta_ari": float(np.mean([x["meta_ari"] for x in items])),
                    "macro_phase_recall": float(np.mean([x["phase_recall"] for x in items])),
                    "macro_edge_precision": float(np.mean([x["edge_precision"] for x in items])),
                    "mean_predicted_edges": float(np.mean([x["predicted_edges"] for x in items])),
                }
            )
        selected = select_graph_threshold(evaluations)

        idf = training_idf(data, outer.development_scenarios) if configuration.use_rarity else None
        x_train, y_train, weights = _assemble_training(
            data, outer.development_scenarios, 50_000, positions, idf
        )
        model = make_model(configuration, max_iter=int(fold["selected_iterations"]), early_stopping=False)
        model.fit(x_train, y_train, sample_weight=weights)
        test = data[scenario]
        probability = model.predict_proba(_transform(test, positions, idf))[:, 1]
        relation = relation_metrics(test.y, probability, fold["selected_threshold"])
        meta = load_meta(cache_root, scenario)
        pairs = load_pair_ids(cache_root, scenario)
        membership, edges, degree = component_membership(meta, pairs, probability, selected["threshold"])
        graph_metrics = graph_validation_metrics(meta, membership, edges)
        meta["predicted_degree"] = degree
        meta["connected_component"] = membership
        scenario_report = {
            "scenario": scenario,
            "configuration": fold["selected_configuration"],
            "pair_threshold": fold["selected_threshold"],
            "selected_graph_threshold": selected["threshold"],
            "inner_graph_threshold_evaluations": evaluations,
            "inner_graph_validation_details": validation_reports,
            "relation_metrics_reproduced": relation,
            "external_graph_summary": graph_metrics,
            "external_partitions": _partition_metrics(meta, membership),
            "external_phase_coverage": _phase_coverage(meta, membership),
            "external_edge_diagnostics": _edge_diagnostics(meta, edges),
        }
        scenario_reports.append(scenario_report)
        target = output_root / scenario
        target.mkdir()
        pq.write_table(pa.Table.from_pandas(meta, preserve_index=False), target / "nodes.parquet", compression="zstd")
        pq.write_table(pa.Table.from_pandas(edges, preserve_index=False), target / "edges.parquet", compression="zstd")
        (target / "metrics.json").write_text(json.dumps(scenario_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"scenario": scenario, "graph_threshold": selected["threshold"], "edges": len(edges), **graph_metrics}, ensure_ascii=False), flush=True)

    report = {
        "kind": "nested-internal-graph-threshold-optimization",
        "threshold_grid": GRAPH_THRESHOLDS,
        "selection_rule": "min fused scenarios/clusters, then meta B-cubed F1, phase recall, edge precision",
        "scenarios": scenario_reports,
    }
    (output_root / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("optimization_report")
    parser.add_argument("output_root")
    args = parser.parse_args()
    optimize_graph_thresholds(Path(args.cache_root), Path(args.optimization_report), Path(args.output_root))


if __name__ == "__main__":
    main()
