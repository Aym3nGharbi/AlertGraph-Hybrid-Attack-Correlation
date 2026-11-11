#!/usr/bin/env python3
"""Évaluation ML groupée : seuil interne, scénario externe jamais vu."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pyarrow.parquet as pq
from sklearn.ensemble import HistGradientBoostingClassifier

from evaluate_nested_baselines import THRESHOLDS, metrics
from advanced_context import ADVANCED_CONTEXT_FEATURE_NAMES
from feature_sets import FEATURE_PROFILES, select_feature_profile
from graph_context import GRAPH_CONTEXT_FEATURE_NAMES
from pair_features import PairFeatures
from split_protocol import AIT_SCENARIOS, nested_leave_one_scenario_out


FEATURE_NAMES = (
    *tuple(PairFeatures.__dataclass_fields__),
    *GRAPH_CONTEXT_FEATURE_NAMES,
    *ADVANCED_CONTEXT_FEATURE_NAMES,
)
RANDOM_SEED = 20261031


def available_feature_names(
    cache_root: str | Path,
    scenario: str = "fox",
) -> tuple[str, ...]:
    available = set(
        pq.ParquetFile(
            Path(cache_root) / scenario / "pair_examples.parquet"
        ).schema_arrow.names
    )
    selected = tuple(name for name in FEATURE_NAMES if name in available)
    if not selected:
        raise ValueError("Aucune caractéristique reconnue dans le cache")
    return selected


def load_arrays(
    cache_root: str | Path,
    scenario: str,
    feature_names: tuple[str, ...] | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    selected_features = feature_names or available_feature_names(
        cache_root, scenario
    )
    table = pq.read_table(
        Path(cache_root) / scenario / "pair_examples.parquet",
        columns=[*selected_features, "target"],
    )
    frame = table.to_pandas()
    frame = frame[frame["target"].notna()]
    return (
        frame.loc[:, selected_features].to_numpy(dtype=np.float32),
        frame["target"].to_numpy(dtype=np.int8),
    )


def deterministic_indices(
    y: np.ndarray,
    cap_per_class: int,
    seed: int,
) -> np.ndarray:
    if cap_per_class <= 0:
        raise ValueError("cap_per_class doit être strictement positif")
    rng = np.random.default_rng(seed)
    selected = []
    for target in (0, 1):
        indices = np.flatnonzero(y == target)
        if len(indices) > cap_per_class:
            indices = rng.choice(indices, cap_per_class, replace=False)
        selected.append(np.sort(indices))
    return np.concatenate(selected)


def assemble_weighted_training(
    data: dict[str, tuple[np.ndarray, np.ndarray]],
    scenarios: tuple[str, ...],
    cap_per_class: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x_parts, y_parts, weight_parts = [], [], []
    for scenario_index, scenario in enumerate(scenarios):
        x, y = data[scenario]
        indices = deterministic_indices(
            y, cap_per_class, RANDOM_SEED + 100 * scenario_index
        )
        selected_y = y[indices]
        selected_weights = np.empty(len(indices), dtype=np.float64)
        for target in (0, 1):
            mask = selected_y == target
            selected_weights[mask] = 1.0 / max(int(mask.sum()), 1)
        x_parts.append(x[indices])
        y_parts.append(selected_y)
        weight_parts.append(selected_weights)

    combined_x = np.concatenate(x_parts)
    combined_y = np.concatenate(y_parts)
    combined_weights = np.concatenate(weight_parts)
    combined_weights /= combined_weights.mean()
    return combined_x, combined_y, combined_weights


def balanced_validation_weights(y: np.ndarray) -> np.ndarray:
    weights = np.empty(len(y), dtype=np.float64)
    for target in (0, 1):
        mask = y == target
        weights[mask] = 1.0 / max(int(mask.sum()), 1)
    return weights / weights.mean()


def new_model(*, max_iter: int = 150, early_stopping: bool = True):
    return HistGradientBoostingClassifier(
        learning_rate=0.08,
        max_iter=max_iter,
        max_leaf_nodes=15,
        min_samples_leaf=50,
        l2_regularization=1.0,
        early_stopping=early_stopping,
        n_iter_no_change=12,
        random_state=RANDOM_SEED,
    )


def _binary_f1(y: np.ndarray, probability: np.ndarray, threshold: float) -> float:
    prediction = probability >= threshold
    positive = y == 1
    true_positive = np.count_nonzero(prediction & positive)
    false_positive = np.count_nonzero(prediction & ~positive)
    false_negative = np.count_nonzero(~prediction & positive)
    denominator = 2 * true_positive + false_positive + false_negative
    return float(2 * true_positive / denominator) if denominator else 0.0


def select_macro_threshold(
    predictions: dict[str, tuple[np.ndarray, np.ndarray]],
) -> tuple[float, float]:
    ranked = []
    for threshold in THRESHOLDS:
        values = [
            _binary_f1(y, probability, threshold)
            for y, probability in predictions.values()
        ]
        ranked.append((float(np.mean(values)), threshold))
    return max(ranked, key=lambda item: (item[0], item[1]))[::-1]


def evaluate_nested_ml(
    cache_root: str | Path,
    inner_cap_per_class: int = 20_000,
    final_cap_per_class: int = 50_000,
    models_dir: str | Path | None = None,
    progress=None,
    feature_names: tuple[str, ...] | None = None,
) -> dict[str, object]:
    selected_features = feature_names or available_feature_names(cache_root)
    data = {
        scenario: load_arrays(cache_root, scenario, selected_features)
        for scenario in AIT_SCENARIOS
    }
    model_path = Path(models_dir) if models_dir else None
    if model_path:
        model_path.mkdir(parents=True, exist_ok=True)

    folds = []
    for outer_index, outer in enumerate(nested_leave_one_scenario_out(), 1):
        inner_predictions = {}
        inner_iterations = []
        inner_rows = []
        for inner in outer.inner_folds:
            x_train, y_train, train_weights = assemble_weighted_training(
                data, inner.train_scenarios, inner_cap_per_class
            )
            x_validation, y_validation = data[inner.validation_scenario]
            model = new_model()
            model.fit(
                x_train,
                y_train,
                sample_weight=train_weights,
                X_val=x_validation,
                y_val=y_validation,
                sample_weight_val=balanced_validation_weights(y_validation),
            )
            inner_predictions[inner.validation_scenario] = (
                y_validation,
                model.predict_proba(x_validation)[:, 1],
            )
            inner_iterations.append(int(model.n_iter_))
            inner_rows.append(len(y_train))

        threshold, inner_macro_f1 = select_macro_threshold(inner_predictions)
        final_iterations = max(1, int(round(float(np.median(inner_iterations)))))
        x_development, y_development, development_weights = assemble_weighted_training(
            data, outer.development_scenarios, final_cap_per_class
        )
        final_model = new_model(
            max_iter=final_iterations,
            early_stopping=False,
        )
        final_model.fit(
            x_development,
            y_development,
            sample_weight=development_weights,
        )
        x_test, y_test = data[outer.test_scenario]
        probability = final_model.predict_proba(x_test)[:, 1]
        fold = {
            "test_scenario": outer.test_scenario,
            "inner_validation_scenarios": tuple(inner_predictions),
            "inner_training_rows": inner_rows,
            "inner_iterations": inner_iterations,
            "selected_iterations": final_iterations,
            "selected_threshold": threshold,
            "inner_macro_f1": inner_macro_f1,
            "final_training_rows": len(y_development),
            "test_metrics": metrics(y_test, probability, threshold),
        }
        folds.append(fold)
        if model_path:
            joblib.dump(final_model, model_path / f"{outer.test_scenario}.joblib")
        if progress:
            progress(outer_index, len(AIT_SCENARIOS), fold)

    metric_names = (
        "average_precision",
        "roc_auc",
        "precision",
        "recall",
        "f1",
        "mcc",
        "balanced_accuracy",
    )
    aggregate = {}
    for name in metric_names:
        values = np.array([fold["test_metrics"][name] for fold in folds])
        aggregate[name] = {
            "macro_mean": float(values.mean()),
            "macro_std": float(values.std(ddof=1)),
        }
    return {
        "kind": "fixed-configuration-nested-group-evaluation",
        "protocol": "nested-leave-one-scenario-out",
        "features": selected_features,
        "inner_cap_per_class_per_scenario": inner_cap_per_class,
        "final_cap_per_class_per_scenario": final_cap_per_class,
        "hyperparameters": new_model().get_params(),
        "folds": folds,
        "aggregate": aggregate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--output", default="output/nested-ml.json")
    parser.add_argument("--models-dir", default="output/nested-ml-models")
    parser.add_argument("--inner-cap-per-class", type=int, default=20_000)
    parser.add_argument("--final-cap-per-class", type=int, default=50_000)
    parser.add_argument(
        "--feature-profile", choices=FEATURE_PROFILES, default="all"
    )
    args = parser.parse_args()

    def show_progress(index, total, fold):
        summary = {
            "fold": f"{index}/{total}",
            "test_scenario": fold["test_scenario"],
            "threshold": fold["selected_threshold"],
            "iterations": fold["selected_iterations"],
            "test_f1": fold["test_metrics"]["f1"],
            "test_ap": fold["test_metrics"]["average_precision"],
        }
        print(json.dumps(summary, ensure_ascii=False), flush=True)

    features = select_feature_profile(
        available_feature_names(args.cache_root), args.feature_profile
    )
    report = evaluate_nested_ml(
        args.cache_root,
        args.inner_cap_per_class,
        args.final_cap_per_class,
        args.models_dir,
        show_progress,
        features,
    )
    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"aggregate": report["aggregate"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
