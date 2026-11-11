#!/usr/bin/env python3
"""Validation externe SOCBED sans réglage, via l'ensemble des huit folds AIT."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
    roc_auc_score,
)

from evaluate_nested_baselines import load_scores
from evaluate_nested_ml import AIT_SCENARIOS, available_feature_names
from evaluate_rarity_ml import _signature_vocabulary, load_rarity_data, training_idf
from feature_sets import select_feature_profile
from optimize_final_nested_ml import (
    FinalSearchConfiguration,
    _assemble_training,
    _positions,
    make_model,
)
from socbed_dataset import SOCBED_RUNS


@dataclass(frozen=True)
class ExternalRun:
    x: np.ndarray
    y: np.ndarray
    earlier_ids: np.ndarray
    later_ids: np.ndarray
    earlier_signatures: np.ndarray
    later_signatures: np.ndarray


def load_external_runs(root: Path, features: tuple[str, ...]) -> dict[str, ExternalRun]:
    result = {}
    for run_id in SOCBED_RUNS:
        meta = pq.read_table(
            root / run_id / "meta_observable.parquet",
            columns=["meta_id", "signature"],
        ).to_pandas()
        signature_by_id = dict(zip(meta["meta_id"], meta["signature"]))
        frame = pq.read_table(
            root / run_id / "pair_examples.parquet",
            columns=["earlier_meta_id", "later_meta_id", *features, "target"],
        ).to_pandas()
        frame = frame[frame["target"].notna()]
        earlier_ids = frame["earlier_meta_id"].to_numpy(dtype=str)
        later_ids = frame["later_meta_id"].to_numpy(dtype=str)
        result[run_id] = ExternalRun(
            x=frame.loc[:, features].to_numpy(dtype=np.float32),
            y=frame["target"].to_numpy(dtype=np.int8),
            earlier_ids=earlier_ids,
            later_ids=later_ids,
            earlier_signatures=np.array(
                [signature_by_id[item] for item in earlier_ids], dtype=object
            ),
            later_signatures=np.array(
                [signature_by_id[item] for item in later_ids], dtype=object
            ),
        )
    return result


def external_rarity_values(
    item: ExternalRun,
    vocabulary: dict[str, int],
    idf: np.ndarray,
    unseen: float,
) -> tuple[np.ndarray, np.ndarray]:
    def values(signatures: np.ndarray) -> np.ndarray:
        return np.array(
            [idf[vocabulary[value]] if value in vocabulary else unseen for value in signatures],
            dtype=np.float32,
        )

    return values(item.earlier_signatures), values(item.later_signatures)


def decision_metrics(y: np.ndarray, score: np.ndarray, prediction: np.ndarray) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, prediction, average="binary", zero_division=0
    )
    return {
        "average_precision": float(average_precision_score(y, score)),
        "roc_auc": float(roc_auc_score(y, score)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "mcc": float(matthews_corrcoef(y, prediction)),
        "balanced_accuracy": float(balanced_accuracy_score(y, prediction)),
        "positive_support": int(y.sum()),
        "negative_support": int(len(y) - y.sum()),
        "predicted_positive": int(prediction.sum()),
    }


def ensemble_metrics(y: np.ndarray, scores: np.ndarray, votes: np.ndarray) -> dict:
    mean_score = scores.mean(axis=0)
    prediction = (votes.sum(axis=0) >= (votes.shape[0] / 2)).astype(np.int8)
    result = decision_metrics(y, mean_score, prediction)
    result["ensemble_size"] = int(votes.shape[0])
    result["decision_rule"] = "at least 4 of 8 frozen AIT fold votes"
    return result


def aggregate(per_run: list[dict]) -> dict:
    names = (
        "average_precision",
        "roc_auc",
        "precision",
        "recall",
        "f1",
        "mcc",
        "balanced_accuracy",
    )
    return {
        name: {
            "macro_mean": float(np.mean([item[name] for item in per_run])),
            "macro_std": float(np.std([item[name] for item in per_run], ddof=1)),
            "worst_run": float(np.min([item[name] for item in per_run])),
        }
        for name in names
    }


def evaluate(
    ait_root: Path,
    external_root: Path,
    optimization_path: Path,
    baselines_path: Path,
    output_root: Path,
) -> dict:
    optimization = json.loads(optimization_path.read_text(encoding="utf-8"))
    baseline_report = json.loads(baselines_path.read_text(encoding="utf-8"))
    available = available_feature_names(ait_root)
    master_features = select_feature_profile(available, "directional_graph")
    ait_data = load_rarity_data(ait_root, master_features)
    external = load_external_runs(external_root, master_features)
    vocabulary = _signature_vocabulary(ait_root)

    ml_scores = {run_id: [] for run_id in SOCBED_RUNS}
    ml_votes = {run_id: [] for run_id in SOCBED_RUNS}
    trained_folds = []
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
        threshold = float(fold["selected_threshold"])
        unseen = None
        if idf is not None:
            total = float(
                np.sum([ait_data[scenario].raw_signature_counts for scenario in development])
            )
            unseen = float(np.log(total + 1.0) + 1.0)

        for run_id, item in external.items():
            x_test = item.x[:, positions]
            if idf is not None:
                left, right = external_rarity_values(item, vocabulary, idf, unseen)
                x_test = np.column_stack((x_test, left, right)).astype(np.float32)
            probability = model.predict_proba(x_test)[:, 1]
            ml_scores[run_id].append(probability)
            ml_votes[run_id].append(probability >= threshold)
        trained_folds.append(
            {
                "fold": fold_index,
                "ait_held_out_scenario": fold["test_scenario"],
                "configuration": fold["selected_configuration"],
                "threshold": threshold,
                "iterations": int(fold["selected_iterations"]),
                "training_rows": int(len(y_train)),
            }
        )
        print(json.dumps({"trained_fold": fold_index, "configuration": configuration.name}), flush=True)

    baseline_folds = {item["test_scenario"]: item for item in baseline_report["folds"]}
    per_run = []
    output_root.mkdir(parents=True, exist_ok=False)
    concatenated = {name: {"y": [], "score": [], "prediction": []} for name in (
        "similarity", "causality", "manual_hybrid", "ml_hybrid"
    )}
    for run_id, item in external.items():
        baseline = load_scores(external_root, run_id)
        model_results = {}
        prediction_columns = {"earlier_meta_id": item.earlier_ids, "later_meta_id": item.later_ids, "target": item.y}
        for name in ("similarity", "causality", "manual_hybrid"):
            scores, votes = [], []
            for scenario in AIT_SCENARIOS:
                selected = baseline_folds[scenario][name]
                if name == "manual_hybrid":
                    score = (
                        float(selected["alpha"]) * baseline["similarity"]
                        + (1.0 - float(selected["alpha"])) * baseline["causality"]
                    )
                else:
                    score = baseline[name]
                scores.append(score)
                votes.append(score >= float(selected["threshold"]))
            scores_array = np.stack(scores)
            votes_array = np.stack(votes)
            result = ensemble_metrics(item.y, scores_array, votes_array)
            model_results[name] = result
            mean_score = scores_array.mean(axis=0)
            prediction = (votes_array.sum(axis=0) >= 4).astype(np.int8)
            prediction_columns[f"{name}_score"] = mean_score
            prediction_columns[f"{name}_prediction"] = prediction
            concatenated[name]["y"].append(item.y)
            concatenated[name]["score"].append(mean_score)
            concatenated[name]["prediction"].append(prediction)

        scores_array = np.stack(ml_scores[run_id])
        votes_array = np.stack(ml_votes[run_id])
        model_results["ml_hybrid"] = ensemble_metrics(item.y, scores_array, votes_array)
        mean_score = scores_array.mean(axis=0)
        prediction = (votes_array.sum(axis=0) >= 4).astype(np.int8)
        prediction_columns["ml_hybrid_score"] = mean_score
        prediction_columns["ml_hybrid_votes"] = votes_array.sum(axis=0).astype(np.int8)
        prediction_columns["ml_hybrid_prediction"] = prediction
        concatenated["ml_hybrid"]["y"].append(item.y)
        concatenated["ml_hybrid"]["score"].append(mean_score)
        concatenated["ml_hybrid"]["prediction"].append(prediction)

        run_target = output_root / run_id
        run_target.mkdir()
        pq.write_table(
            pa.Table.from_pydict(prediction_columns),
            run_target / "pair_predictions.parquet",
            compression="zstd",
        )
        per_run.append({"run_id": run_id, "models": model_results})

    models = ("similarity", "causality", "manual_hybrid", "ml_hybrid")
    overall = {}
    for name in models:
        values = concatenated[name]
        overall[name] = decision_metrics(
            np.concatenate(values["y"]),
            np.concatenate(values["score"]),
            np.concatenate(values["prediction"]),
        )
    report = {
        "kind": "strict-external-validation",
        "training_dataset": "AIT-ADS v1",
        "external_dataset": "SOCBED ACSAC 2021",
        "external_tuning": False,
        "ensemble_rule": "eight AIT outer-fold models, each with its frozen AIT threshold; >=4 votes",
        "trained_folds": trained_folds,
        "per_run": per_run,
        "macro": {
            name: aggregate([item["models"][name] for item in per_run]) for name in models
        },
        "micro": overall,
    }
    (output_root / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ait_root", type=Path)
    parser.add_argument("external_root", type=Path)
    parser.add_argument("optimization", type=Path)
    parser.add_argument("baselines", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    report = evaluate(
        args.ait_root,
        args.external_root,
        args.optimization,
        args.baselines,
        args.output_root,
    )
    print(json.dumps({"macro": report["macro"], "micro": report["micro"]}, indent=2))


if __name__ == "__main__":
    main()
