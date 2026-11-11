#!/usr/bin/env python3
"""Évalue un ensemble ML calibré par scénarios internes indépendants."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator

from evaluate_nested_baselines import metrics
from evaluate_nested_ml import (
    AIT_SCENARIOS,
    assemble_weighted_training,
    load_arrays,
    new_model,
    select_macro_threshold,
)
from split_protocol import nested_leave_one_scenario_out


def mean_positive_probability(models, x: np.ndarray) -> np.ndarray:
    if not models:
        raise ValueError("Au moins un modèle calibré est nécessaire")
    probabilities = np.zeros(len(x), dtype=np.float64)
    for model in models:
        probabilities += model.predict_proba(x)[:, 1]
    return probabilities / len(models)


def evaluate_calibrated_ml(
    cache_root: str | Path,
    cap_per_class: int = 20_000,
    base_iterations: int = 100,
    models_dir: str | Path | None = None,
    progress=None,
) -> dict[str, object]:
    data = {scenario: load_arrays(cache_root, scenario) for scenario in AIT_SCENARIOS}
    model_path = Path(models_dir) if models_dir else None
    if model_path:
        model_path.mkdir(parents=True, exist_ok=True)

    folds = []
    for outer_index, outer in enumerate(nested_leave_one_scenario_out(), 1):
        calibrated_models = []
        calibration_predictions = {}
        training_rows = []
        for inner in outer.inner_folds:
            x_train, y_train, train_weights = assemble_weighted_training(
                data, inner.train_scenarios, cap_per_class
            )
            base_model = new_model(
                max_iter=base_iterations,
                early_stopping=False,
            )
            base_model.fit(x_train, y_train, sample_weight=train_weights)
            x_calibration, y_calibration = data[inner.validation_scenario]
            calibrated = CalibratedClassifierCV(
                FrozenEstimator(base_model),
                method="sigmoid",
            )
            # La calibration conserve ici la prévalence réelle du scénario ;
            # aucun poids de classe n'est appliqué à ce stade.
            calibrated.fit(x_calibration, y_calibration)
            calibrated_models.append(calibrated)
            calibration_predictions[inner.validation_scenario] = (
                y_calibration,
                calibrated.predict_proba(x_calibration)[:, 1],
            )
            training_rows.append(len(y_train))

        threshold, calibration_macro_f1 = select_macro_threshold(
            calibration_predictions
        )
        x_test, y_test = data[outer.test_scenario]
        probability = mean_positive_probability(calibrated_models, x_test)
        fold = {
            "test_scenario": outer.test_scenario,
            "calibration_scenarios": tuple(calibration_predictions),
            "base_training_rows": training_rows,
            "base_iterations": base_iterations,
            "selected_threshold": threshold,
            "calibration_macro_f1": calibration_macro_f1,
            "test_metrics": metrics(y_test, probability, threshold),
        }
        folds.append(fold)
        if model_path:
            joblib.dump(
                calibrated_models,
                model_path / f"{outer.test_scenario}-ensemble.joblib",
            )
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
        "kind": "group-cross-calibrated-ensemble",
        "protocol": "outer-leave-one-scenario-out",
        "calibration": "sigmoid-on-held-out-inner-scenario",
        "base_iterations": base_iterations,
        "cap_per_class_per_training_scenario": cap_per_class,
        "folds": folds,
        "aggregate": aggregate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--output", default="output/calibrated-ml.json")
    parser.add_argument("--models-dir", default="output/calibrated-ml-models")
    parser.add_argument("--cap-per-class", type=int, default=20_000)
    parser.add_argument("--base-iterations", type=int, default=100)
    args = parser.parse_args()

    def show_progress(index, total, fold):
        summary = {
            "fold": f"{index}/{total}",
            "test_scenario": fold["test_scenario"],
            "threshold": fold["selected_threshold"],
            "test_f1": fold["test_metrics"]["f1"],
            "test_ap": fold["test_metrics"]["average_precision"],
        }
        print(json.dumps(summary, ensure_ascii=False), flush=True)

    report = evaluate_calibrated_ml(
        args.cache_root,
        args.cap_per_class,
        args.base_iterations,
        args.models_dir,
        show_progress,
    )
    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"aggregate": report["aggregate"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
