#!/usr/bin/env python3
"""Test externe gelé des graphes ML, cascade et cœur manuel + ponts ML."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from darpa_dataset import DARPA_SCENARIOS
from evaluate_cascade_graphs import aggregate, graph_report
from evaluate_nested_baselines import load_scores
from evaluate_nested_ml import AIT_SCENARIOS, available_feature_names
from evaluate_rarity_ml import _signature_vocabulary, load_rarity_data, training_idf
from evaluate_socbed_external import ExternalRun, decision_metrics, external_rarity_values
from feature_sets import select_feature_profile
from optimize_final_nested_ml import FinalSearchConfiguration, _assemble_training, _positions, make_model
from optimize_graph_thresholds import load_meta, load_pair_ids
from optimize_manual_core_ml_bridges import bridge_prediction


MANUAL_ALPHA = 0.25
MANUAL_THRESHOLD = 0.50
BRIDGE_THRESHOLD = 0.50


def load_external(root: Path, features: tuple[str, ...]) -> dict[str, ExternalRun]:
    result = {}
    for scenario in DARPA_SCENARIOS:
        meta = pq.read_table(
            root / scenario / "meta_observable.parquet", columns=["meta_id", "signature"]
        ).to_pandas()
        signatures = dict(zip(meta["meta_id"], meta["signature"]))
        frame = pq.read_table(
            root / scenario / "pair_examples.parquet",
            columns=["earlier_meta_id", "later_meta_id", *features, "target"],
        ).to_pandas()
        frame = frame[frame["target"].notna()].reset_index(drop=True)
        earlier = frame["earlier_meta_id"].to_numpy(dtype=str)
        later = frame["later_meta_id"].to_numpy(dtype=str)
        result[scenario] = ExternalRun(
            x=frame.loc[:, features].to_numpy(dtype=np.float32),
            y=frame["target"].to_numpy(dtype=np.int8),
            earlier_ids=earlier,
            later_ids=later,
            earlier_signatures=np.array([signatures[x] for x in earlier], dtype=object),
            later_signatures=np.array([signatures[x] for x in later], dtype=object),
        )
    return result


def evaluate(ait_root: Path, darpa_root: Path, optimization_path: Path, output_path: Path) -> dict:
    optimization = json.loads(optimization_path.read_text(encoding="utf-8"))
    master_features = select_feature_profile(
        available_feature_names(ait_root), "directional_graph"
    )
    ait_data = load_rarity_data(ait_root, master_features)
    external = load_external(darpa_root, master_features)
    vocabulary = _signature_vocabulary(ait_root)
    probabilities = {scenario: [] for scenario in DARPA_SCENARIOS}
    ml_votes = {scenario: [] for scenario in DARPA_SCENARIOS}
    bridge_votes = {scenario: [] for scenario in DARPA_SCENARIOS}
    fold_reports = []

    metas = {scenario: load_meta(darpa_root, scenario) for scenario in DARPA_SCENARIOS}
    pairs = {scenario: load_pair_ids(darpa_root, scenario) for scenario in DARPA_SCENARIOS}
    scores = {scenario: load_scores(darpa_root, scenario) for scenario in DARPA_SCENARIOS}

    for fold_index, fold in enumerate(optimization["folds"], 1):
        configuration = FinalSearchConfiguration(**fold["selected_configuration"])
        positions = _positions(master_features, configuration)
        development = tuple(
            scenario for scenario in AIT_SCENARIOS if scenario != fold["test_scenario"]
        )
        idf = training_idf(ait_data, development) if configuration.use_rarity else None
        x_train, y_train, weights = _assemble_training(
            ait_data, development, 50_000, positions, idf
        )
        model = make_model(
            configuration,
            max_iter=int(fold["selected_iterations"]),
            early_stopping=False,
        )
        model.fit(x_train, y_train, sample_weight=weights)
        pair_threshold = float(fold["selected_threshold"])
        unseen = None
        if idf is not None:
            total = float(
                np.sum([ait_data[x].raw_signature_counts for x in development])
            )
            unseen = float(np.log(total + 1.0) + 1.0)

        for scenario, item in external.items():
            x_test = item.x[:, positions]
            if idf is not None:
                left, right = external_rarity_values(item, vocabulary, idf, unseen)
                x_test = np.column_stack((x_test, left, right)).astype(np.float32)
            probability = model.predict_proba(x_test)[:, 1]
            probabilities[scenario].append(probability)
            ml_votes[scenario].append(probability >= pair_threshold)
            bridge_votes[scenario].append(
                bridge_prediction(
                    metas[scenario],
                    pairs[scenario],
                    probability,
                    scores[scenario],
                    pair_threshold,
                    BRIDGE_THRESHOLD,
                )
            )
        fold_reports.append(
            {
                "fold": fold_index,
                "ait_held_out_scenario": fold["test_scenario"],
                "configuration": configuration.name,
                "relation_threshold": pair_threshold,
                "bridge_threshold": BRIDGE_THRESHOLD,
            }
        )
        print(json.dumps({"trained_fold": fold_index, "configuration": configuration.name}), flush=True)

    scenario_reports = []
    graph_reports = {"ml_only": [], "ml_and_manual": [], "manual_core_ml_bridges": []}
    relation_reports = {name: [] for name in graph_reports}
    for scenario, item in external.items():
        probability = np.stack(probabilities[scenario]).mean(axis=0)
        ml_prediction = np.stack(ml_votes[scenario]).sum(axis=0) >= 4
        manual = (
            MANUAL_ALPHA * scores[scenario]["similarity"]
            + (1.0 - MANUAL_ALPHA) * scores[scenario]["causality"]
        )
        cascade_prediction = ml_prediction & (manual >= MANUAL_THRESHOLD)
        bridge_prediction_final = np.stack(bridge_votes[scenario]).sum(axis=0) >= 4
        predictions = {
            "ml_only": ml_prediction,
            "ml_and_manual": cascade_prediction,
            "manual_core_ml_bridges": bridge_prediction_final,
        }
        scenario_graphs = {}
        scenario_relations = {}
        for name, prediction in predictions.items():
            scenario_graphs[name] = graph_report(metas[scenario], pairs[scenario], prediction)
            scenario_relations[name] = decision_metrics(
                item.y, probability, prediction.astype(np.int8)
            )
            graph_reports[name].append(scenario_graphs[name])
            relation_reports[name].append(scenario_relations[name])
        scenario_reports.append(
            {
                "scenario": scenario,
                "classification_ml": decision_metrics(
                    item.y, probability, ml_prediction.astype(np.int8)
                ),
                "relation_decisions": scenario_relations,
                "graphs": scenario_graphs,
            }
        )

    names = ("precision", "recall", "f1", "mcc", "balanced_accuracy")
    report = {
        "kind": "strict-external-darpa2000-graph-comparison",
        "training_dataset": "AIT-ADS v1 only",
        "external_dataset": "DARPA 2000 LLDOS 1.0 and 2.0.2",
        "external_tuning": False,
        "labels": "official MIT phase session XML matched by timestamp and endpoints",
        "ensemble_rule": "eight frozen AIT outer-fold models; at least 4 votes",
        "manual_alpha": MANUAL_ALPHA,
        "manual_threshold": MANUAL_THRESHOLD,
        "bridge_threshold": BRIDGE_THRESHOLD,
        "folds": fold_reports,
        "scenarios": scenario_reports,
        "macro_relation_decisions": {
            method: {
                metric: {
                    "macro_mean": float(np.mean([x[metric] for x in values])),
                    "macro_std": float(np.std([x[metric] for x in values], ddof=1)),
                }
                for metric in names
            }
            for method, values in relation_reports.items()
        },
        "macro_graph": {
            method: aggregate(values) for method, values in graph_reports.items()
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ait_root", type=Path)
    parser.add_argument("darpa_root", type=Path)
    parser.add_argument("optimization", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = evaluate(args.ait_root, args.darpa_root, args.optimization, args.output)
    print(json.dumps({
        "macro_relation_decisions": report["macro_relation_decisions"],
        "macro_graph": report["macro_graph"],
    }, indent=2))


if __name__ == "__main__":
    main()
