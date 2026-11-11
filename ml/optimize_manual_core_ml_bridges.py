#!/usr/bin/env python3
"""Noyau manuel précis complété par un minimum de ponts ML."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from evaluate_nested_baselines import load_scores
from evaluate_nested_ml import available_feature_names, balanced_validation_weights
from evaluate_rarity_ml import _signature_vocabulary, load_rarity_data, training_idf
from evaluate_socbed_external import external_rarity_values, load_external_runs
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
from evaluate_cascade_graphs import aggregate, graph_report
from socbed_dataset import SOCBED_RUNS
from split_protocol import AIT_SCENARIOS, nested_leave_one_scenario_out
from graph_reconstruction import (
    DisjointSet,
    MANUAL_ALPHA,
    MANUAL_THRESHOLD,
    bridge_prediction,
    manual_score,
)


BRIDGE_THRESHOLDS = (0.50, 0.60, 0.70, 0.80, 0.90, 0.95)


def select_threshold(evaluations: list[dict]) -> dict:
    """B-cubed équilibre directement fragmentation et fusion."""

    return max(
        evaluations,
        key=lambda item: (
            item["macro_meta_bcubed_f1"],
            item["macro_meta_ari"],
            item["macro_phase_recall"],
            -item["fused_scenarios"],
            item["macro_edge_precision"],
            item["threshold"],
        ),
    )


def optimize(ait_root: Path, socbed_root: Path, optimization_path: Path, output_path: Path) -> dict:
    optimization = json.loads(optimization_path.read_text(encoding="utf-8"))
    master_features = select_feature_profile(
        available_feature_names(ait_root), "directional_graph"
    )
    ait_data = load_rarity_data(ait_root, master_features)
    external = load_external_runs(socbed_root, master_features)
    vocabulary = _signature_vocabulary(ait_root)
    outer_map = {item.test_scenario: item for item in nested_leave_one_scenario_out()}
    external_scores = {run: load_scores(socbed_root, run) for run in SOCBED_RUNS}
    external_votes = {run: [] for run in SOCBED_RUNS}
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
            meta = load_meta(ait_root, inner.validation_scenario)
            pairs = load_pair_ids(ait_root, inner.validation_scenario)
            scores = load_scores(ait_root, inner.validation_scenario)
            prepared = prepare_fast_graph_truth(meta)
            grid = {}
            for threshold in BRIDGE_THRESHOLDS:
                prediction = bridge_prediction(
                    meta,
                    pairs,
                    probability,
                    scores,
                    float(fold["selected_threshold"]),
                    threshold,
                )
                membership, edges, _ = component_membership(
                    meta, pairs, prediction.astype(np.float32), 0.5
                )
                grid[str(threshold)] = fast_graph_validation_metrics(
                    prepared,
                    membership,
                    edges["target"].to_numpy(dtype=np.int8),
                )
            validation_reports.append(
                {"validation_scenario": inner.validation_scenario, "grid": grid}
            )

        evaluations = []
        for threshold in BRIDGE_THRESHOLDS:
            items = [item["grid"][str(threshold)] for item in validation_reports]
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
        selected = select_threshold(evaluations)

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
        meta = load_meta(ait_root, scenario)
        pairs = load_pair_ids(ait_root, scenario)
        prediction = bridge_prediction(
            meta,
            pairs,
            probability,
            load_scores(ait_root, scenario),
            float(fold["selected_threshold"]),
            selected["threshold"],
        )
        graph = graph_report(meta, pairs, prediction)
        scenario_reports.append(
            {
                "scenario": scenario,
                "selected_bridge_threshold": selected,
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
                left_rarity, right_rarity = external_rarity_values(
                    item, vocabulary, idf, unseen
                )
                x_test = np.column_stack((x_test, left_rarity, right_rarity)).astype(np.float32)
            probability_external = model.predict_proba(x_test)[:, 1]
            pairs_external = pq.read_table(
                socbed_root / run_id / "pair_examples.parquet",
                columns=["earlier_meta_id", "later_meta_id", "target"],
            ).to_pandas()
            prediction_external = bridge_prediction(
                load_meta(socbed_root, run_id),
                pairs_external,
                probability_external,
                external_scores[run_id],
                float(fold["selected_threshold"]),
                selected["threshold"],
            )
            external_votes[run_id].append(prediction_external)
        print(json.dumps({"outer": outer_index, "scenario": scenario, "selected": selected}), flush=True)

    socbed_reports = []
    for run_id in SOCBED_RUNS:
        votes = np.stack(external_votes[run_id])
        prediction = (votes.sum(axis=0) >= 4).astype(float)
        meta = load_meta(socbed_root, run_id)
        pairs = load_pair_ids(socbed_root, run_id)
        socbed_reports.append(
            {
                "run_id": run_id,
                "graph": graph_report(meta, pairs, prediction.astype(bool)),
            }
        )

    report = {
        "kind": "nested-manual-core-ml-maximum-spanning-bridges",
        "manual_alpha": MANUAL_ALPHA,
        "manual_threshold": MANUAL_THRESHOLD,
        "bridge_thresholds": BRIDGE_THRESHOLDS,
        "bridge_policy": "descending ML probability, union only different components, reject explicit known incompatibility",
        "ait": {
            "scenarios": scenario_reports,
            "macro_graph": aggregate([x["external_graph"] for x in scenario_reports]),
        },
        "socbed": {
            "runs": socbed_reports,
            "macro_graph": aggregate([x["graph"] for x in socbed_reports]),
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
    print(json.dumps({"ait": report["ait"]["macro_graph"], "socbed": report["socbed"]["macro_graph"]}, indent=2))


if __name__ == "__main__":
    main()
