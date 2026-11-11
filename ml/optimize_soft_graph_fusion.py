#!/usr/bin/env python3
"""Optimise une fusion graphique souple ML/manuelle sans pénaliser l'inconnu."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from evaluate_attack_graphs import _edge_diagnostics, _partition_metrics, _phase_coverage
from evaluate_nested_baselines import load_scores
from evaluate_nested_ml import available_feature_names, balanced_validation_weights
from evaluate_rarity_ml import _signature_vocabulary, load_rarity_data, training_idf
from evaluate_socbed_external import (
    decision_metrics,
    external_rarity_values,
    load_external_runs,
)
from evaluate_socbed_graphs import _aggregate as aggregate_socbed_graphs
from evaluate_socbed_graphs import _run_model_metrics
from feature_sets import select_feature_profile
from optimize_final_nested_ml import (
    FinalSearchConfiguration,
    _assemble_training,
    _positions,
    _transform,
    make_model,
)
from optimize_graph_thresholds import (
    component_membership,
    fast_graph_validation_metrics,
    load_meta,
    load_pair_ids,
    prepare_fast_graph_truth,
)
from socbed_dataset import SOCBED_RUNS
from split_protocol import AIT_SCENARIOS, nested_leave_one_scenario_out


LAMBDAS = (0.70, 0.85, 1.00)
THRESHOLDS = (0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 0.95)
MANUAL_ALPHA = 0.25


def missing_aware_manual(scores: dict[str, np.ndarray]) -> np.ndarray:
    known_manual = (
        MANUAL_ALPHA * scores["similarity"]
        + (1.0 - MANUAL_ALPHA) * scores["causality"]
    )
    return np.where(scores["stage_known"], known_manual, scores["similarity"])


def select_configuration(evaluations: list[dict]) -> dict:
    minimum_fused_scenarios = min(item["fused_scenarios"] for item in evaluations)
    eligible = [x for x in evaluations if x["fused_scenarios"] == minimum_fused_scenarios]
    minimum_fused_clusters = min(item["total_fused_clusters"] for item in eligible)
    eligible = [x for x in eligible if x["total_fused_clusters"] == minimum_fused_clusters]
    return max(
        eligible,
        key=lambda item: (
            item["macro_meta_bcubed_f1"],
            item["macro_phase_recall"],
            item["macro_edge_precision"],
            item["lambda_ml"],
            item["threshold"],
        ),
    )


def full_graph_report(meta, pairs, score, threshold) -> dict:
    membership, edges, _ = component_membership(meta, pairs, score, threshold)
    partition = _partition_metrics(meta, membership)
    phase_items = _phase_coverage(meta, membership)["instances"]
    edge = _edge_diagnostics(meta, edges)
    return {
        "predicted_edges": int(len(edges)),
        "edge_precision": edge["edge_precision_known"],
        "incorrect_edges": edge["incorrect_edges"],
        "bcubed_meta_attacks": partition["attacks_only"]["meta_unweighted"]["bcubed_f1"],
        "ari_meta_attacks": partition["attacks_only"]["meta_unweighted"]["ari"],
        "bcubed_raw_attacks": partition["attacks_only"]["raw_alert_weighted"]["bcubed_f1"],
        "attack_fragments": partition["attack_diagnostics_meta"]["mean_fragments_per_attack"],
        "largest_attack_fragment": partition["attack_diagnostics_meta"]["mean_largest_fragment_coverage"],
        "phase_type_coverage": float(np.mean([x["dominant_component_phase_coverage"] for x in phase_items])) if phase_items else 0.0,
        "phase_alert_recall": float(np.mean([x["macro_phase_recall_in_dominant_component"] for x in phase_items])) if phase_items else 0.0,
    }


def aggregate(items: list[dict]) -> dict:
    result = {}
    for name in items[0]:
        values = np.asarray([item[name] for item in items], dtype=float)
        result[name] = {
            "macro_mean": float(values.mean()),
            "macro_std": float(values.std(ddof=1)),
            "total": int(values.sum()) if name in {"predicted_edges", "incorrect_edges"} else None,
        }
    return result


def optimize(
    ait_root: Path,
    socbed_root: Path,
    optimization_path: Path,
    output_path: Path,
) -> dict:
    optimization = json.loads(optimization_path.read_text(encoding="utf-8"))
    available = available_feature_names(ait_root)
    master_features = select_feature_profile(available, "directional_graph")
    ait_data = load_rarity_data(ait_root, master_features)
    external = load_external_runs(socbed_root, master_features)
    vocabulary = _signature_vocabulary(ait_root)
    outer_map = {item.test_scenario: item for item in nested_leave_one_scenario_out()}
    external_manual = {
        run_id: missing_aware_manual(load_scores(socbed_root, run_id))
        for run_id in SOCBED_RUNS
    }
    external_fold_scores = {run_id: [] for run_id in SOCBED_RUNS}
    external_fold_votes = {run_id: [] for run_id in SOCBED_RUNS}
    scenario_reports = []

    for outer_index, fold in enumerate(optimization["folds"], 1):
        scenario = fold["test_scenario"]
        outer = outer_map[scenario]
        configuration = FinalSearchConfiguration(**fold["selected_configuration"])
        positions = _positions(master_features, configuration)
        validation_reports = []

        for inner in outer.inner_folds:
            idf = training_idf(ait_data, inner.train_scenarios) if configuration.use_rarity else None
            x_train, y_train, weights = _assemble_training(
                ait_data, inner.train_scenarios, 20_000, positions, idf
            )
            validation = ait_data[inner.validation_scenario]
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
            manual = missing_aware_manual(load_scores(ait_root, inner.validation_scenario))
            if len(manual) != len(probability):
                raise ValueError("Désalignement des paires de validation")
            meta = load_meta(ait_root, inner.validation_scenario)
            pairs = load_pair_ids(ait_root, inner.validation_scenario)
            prepared = prepare_fast_graph_truth(meta)
            grid = {}
            for lambda_ml in LAMBDAS:
                score = lambda_ml * probability + (1.0 - lambda_ml) * manual
                for threshold in THRESHOLDS:
                    membership, edges, _ = component_membership(meta, pairs, score, threshold)
                    grid[f"{lambda_ml}:{threshold}"] = fast_graph_validation_metrics(
                        prepared,
                        membership,
                        edges["target"].to_numpy(dtype=np.int8),
                    )
            validation_reports.append(
                {"validation_scenario": inner.validation_scenario, "grid": grid}
            )

        evaluations = []
        for lambda_ml in LAMBDAS:
            for threshold in THRESHOLDS:
                key = f"{lambda_ml}:{threshold}"
                items = [item["grid"][key] for item in validation_reports]
                evaluations.append(
                    {
                        "lambda_ml": lambda_ml,
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
        selected = select_configuration(evaluations)

        idf = training_idf(ait_data, outer.development_scenarios) if configuration.use_rarity else None
        x_train, y_train, weights = _assemble_training(
            ait_data, outer.development_scenarios, 50_000, positions, idf
        )
        model = make_model(
            configuration,
            max_iter=int(fold["selected_iterations"]),
            early_stopping=False,
        )
        model.fit(x_train, y_train, sample_weight=weights)
        test = ait_data[scenario]
        probability = model.predict_proba(_transform(test, positions, idf))[:, 1]
        manual = missing_aware_manual(load_scores(ait_root, scenario))
        score = selected["lambda_ml"] * probability + (1.0 - selected["lambda_ml"]) * manual
        graph = full_graph_report(
            load_meta(ait_root, scenario),
            load_pair_ids(ait_root, scenario),
            score,
            selected["threshold"],
        )
        scenario_reports.append(
            {
                "scenario": scenario,
                "selected": selected,
                "inner_evaluations": evaluations,
                "external_graph": graph,
            }
        )

        unseen = None
        if idf is not None:
            total = float(np.sum([ait_data[x].raw_signature_counts for x in outer.development_scenarios]))
            unseen = float(np.log(total + 1.0) + 1.0)
        for run_id, item in external.items():
            x_test = item.x[:, positions]
            if idf is not None:
                left, right = external_rarity_values(item, vocabulary, idf, unseen)
                x_test = np.column_stack((x_test, left, right)).astype(np.float32)
            probability_external = model.predict_proba(x_test)[:, 1]
            fusion = (
                selected["lambda_ml"] * probability_external
                + (1.0 - selected["lambda_ml"]) * external_manual[run_id]
            )
            external_fold_scores[run_id].append(fusion)
            external_fold_votes[run_id].append(fusion >= selected["threshold"])
        print(json.dumps({"outer": outer_index, "scenario": scenario, "selected": selected}), flush=True)

    socbed_runs = []
    socbed_graphs = []
    socbed_relations = []
    for run_id, item in external.items():
        scores = np.stack(external_fold_scores[run_id])
        votes = np.stack(external_fold_votes[run_id])
        mean_score = scores.mean(axis=0)
        prediction = (votes.sum(axis=0) >= 4).astype(np.int8)
        relation = decision_metrics(item.y, mean_score, prediction)
        pairs = pq.read_table(
            socbed_root / run_id / "pair_examples.parquet",
            columns=["earlier_meta_id", "later_meta_id", "target"],
        ).to_pandas()
        pairs["soft_fusion_prediction"] = prediction
        graph, _ = _run_model_metrics(load_meta(socbed_root, run_id), pairs, "soft_fusion")
        socbed_relations.append(relation)
        socbed_graphs.append(graph)
        socbed_runs.append({"run_id": run_id, "relation": relation, "graph": graph})

    relation_names = ("average_precision", "precision", "recall", "f1", "mcc", "balanced_accuracy")
    report = {
        "kind": "nested-soft-graph-fusion",
        "manual_alpha": MANUAL_ALPHA,
        "unknown_causality_policy": "manual score equals similarity score",
        "lambdas": LAMBDAS,
        "thresholds": THRESHOLDS,
        "ait": {
            "scenarios": scenario_reports,
            "macro_graph": aggregate([x["external_graph"] for x in scenario_reports]),
        },
        "socbed": {
            "runs": socbed_runs,
            "macro_relation": {
                name: {
                    "macro_mean": float(np.mean([x[name] for x in socbed_relations])),
                    "macro_std": float(np.std([x[name] for x in socbed_relations], ddof=1)),
                }
                for name in relation_names
            },
            "macro_graph": aggregate_socbed_graphs(socbed_graphs),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ait_root", type=Path)
    parser.add_argument("socbed_root", type=Path)
    parser.add_argument("optimization", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = optimize(args.ait_root, args.socbed_root, args.optimization, args.output)
    print(json.dumps({"ait": report["ait"]["macro_graph"], "socbed_relation": report["socbed"]["macro_relation"], "socbed_graph": report["socbed"]["macro_graph"]}, indent=2))


if __name__ == "__main__":
    main()
