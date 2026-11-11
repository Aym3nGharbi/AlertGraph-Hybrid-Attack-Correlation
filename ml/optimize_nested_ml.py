#!/usr/bin/env python3
"""Optimisation imbriquée bornée du profil et du gradient boosting."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score

from evaluate_nested_baselines import metrics
from evaluate_nested_ml import (
    AIT_SCENARIOS,
    RANDOM_SEED,
    assemble_weighted_training,
    available_feature_names,
    balanced_validation_weights,
    load_arrays,
    select_macro_threshold,
)
from feature_sets import select_feature_profile
from split_protocol import nested_leave_one_scenario_out


@dataclass(frozen=True)
class SearchConfiguration:
    name: str
    profile: str
    learning_rate: float
    max_iter: int
    max_leaf_nodes: int
    min_samples_leaf: int
    l2_regularization: float
    max_features: float


SEARCH_CONFIGURATIONS = (
    SearchConfiguration("directional-current", "directional", 0.08, 150, 15, 50, 1.0, 1.0),
    SearchConfiguration("directional-regularized", "directional", 0.05, 220, 15, 200, 5.0, 0.7),
    SearchConfiguration("directional-shallow", "directional", 0.05, 220, 7, 200, 10.0, 1.0),
    SearchConfiguration("directional-flexible", "directional", 0.05, 220, 31, 50, 5.0, 0.7),
    SearchConfiguration("all-current", "all", 0.08, 150, 15, 50, 1.0, 1.0),
)


def make_model(
    configuration: SearchConfiguration,
    *,
    max_iter: int | None = None,
    early_stopping: bool = True,
) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        learning_rate=configuration.learning_rate,
        max_iter=max_iter or configuration.max_iter,
        max_leaf_nodes=configuration.max_leaf_nodes,
        min_samples_leaf=configuration.min_samples_leaf,
        l2_regularization=configuration.l2_regularization,
        max_features=configuration.max_features,
        early_stopping=early_stopping,
        n_iter_no_change=12,
        random_state=RANDOM_SEED,
    )


def select_configuration(
    evaluations: list[dict[str, object]],
    ap_tolerance: float = 0.01,
) -> dict[str, object]:
    """Garde les AP proches, puis favorise F1, pire fold et simplicité."""

    best_ap = max(item["macro_average_precision"] for item in evaluations)
    eligible = [
        item
        for item in evaluations
        if item["macro_average_precision"] >= best_ap - ap_tolerance
    ]
    return max(
        eligible,
        key=lambda item: (
            item["macro_f1"],
            item["worst_scenario_average_precision"],
            -item["std_average_precision"],
            -item["feature_count"],
        ),
    )


def _profile_data(all_data, all_features, selected_features):
    positions = tuple(all_features.index(name) for name in selected_features)
    if positions == tuple(range(len(positions))):
        return {scenario: (x[:, : len(positions)], y) for scenario, (x, y) in all_data.items()}
    return {
        scenario: (x[:, positions], y) for scenario, (x, y) in all_data.items()
    }


def optimize_nested(
    cache_root: str | Path,
    inner_cap_per_class: int = 20_000,
    final_cap_per_class: int = 50_000,
    models_dir: str | Path | None = None,
    progress=None,
) -> dict[str, object]:
    all_features = available_feature_names(cache_root)
    all_data = {
        scenario: load_arrays(cache_root, scenario, all_features)
        for scenario in AIT_SCENARIOS
    }
    profile_features = {
        profile: select_feature_profile(all_features, profile)
        for profile in {config.profile for config in SEARCH_CONFIGURATIONS}
    }
    profile_data = {
        profile: _profile_data(all_data, all_features, features)
        for profile, features in profile_features.items()
    }
    model_path = Path(models_dir) if models_dir else None
    if model_path:
        model_path.mkdir(parents=True, exist_ok=True)

    outer_results = []
    for outer_index, outer in enumerate(nested_leave_one_scenario_out(), 1):
        configuration_results = []
        for config_index, configuration in enumerate(SEARCH_CONFIGURATIONS, 1):
            data = profile_data[configuration.profile]
            predictions = {}
            iterations = []
            training_rows = []
            for inner in outer.inner_folds:
                x_train, y_train, weights = assemble_weighted_training(
                    data, inner.train_scenarios, inner_cap_per_class
                )
                x_validation, y_validation = data[inner.validation_scenario]
                model = make_model(configuration)
                model.fit(
                    x_train,
                    y_train,
                    sample_weight=weights,
                    X_val=x_validation,
                    y_val=y_validation,
                    sample_weight_val=balanced_validation_weights(y_validation),
                )
                predictions[inner.validation_scenario] = (
                    y_validation,
                    model.predict_proba(x_validation)[:, 1],
                )
                iterations.append(int(model.n_iter_))
                training_rows.append(len(y_train))

            threshold, macro_f1 = select_macro_threshold(predictions)
            ap_values = np.array(
                [
                    average_precision_score(y, probability)
                    for y, probability in predictions.values()
                ]
            )
            result = {
                "configuration": asdict(configuration),
                "feature_count": len(profile_features[configuration.profile]),
                "features": profile_features[configuration.profile],
                "selected_threshold": threshold,
                "macro_f1": macro_f1,
                "macro_average_precision": float(ap_values.mean()),
                "std_average_precision": float(ap_values.std(ddof=1)),
                "worst_scenario_average_precision": float(ap_values.min()),
                "iterations": iterations,
                "median_iterations": max(1, int(round(float(np.median(iterations))))),
                "training_rows": training_rows,
            }
            configuration_results.append(result)
            if progress:
                progress(
                    "configuration",
                    outer_index,
                    len(AIT_SCENARIOS),
                    config_index,
                    len(SEARCH_CONFIGURATIONS),
                    outer.test_scenario,
                    result,
                )

        selected = select_configuration(configuration_results)
        selected_config = SearchConfiguration(**selected["configuration"])
        selected_data = profile_data[selected_config.profile]
        x_development, y_development, weights = assemble_weighted_training(
            selected_data, outer.development_scenarios, final_cap_per_class
        )
        final_model = make_model(
            selected_config,
            max_iter=selected["median_iterations"],
            early_stopping=False,
        )
        final_model.fit(x_development, y_development, sample_weight=weights)
        x_test, y_test = selected_data[outer.test_scenario]
        probability = final_model.predict_proba(x_test)[:, 1]
        outer_result = {
            "test_scenario": outer.test_scenario,
            "configuration_evaluations": configuration_results,
            "selected_configuration": selected["configuration"],
            "selected_features": selected["features"],
            "selected_threshold": selected["selected_threshold"],
            "selected_iterations": selected["median_iterations"],
            "final_training_rows": len(y_development),
            "test_metrics": metrics(
                y_test, probability, selected["selected_threshold"]
            ),
        }
        outer_results.append(outer_result)
        if model_path:
            joblib.dump(final_model, model_path / f"{outer.test_scenario}.joblib")
        if progress:
            progress(
                "fold",
                outer_index,
                len(AIT_SCENARIOS),
                None,
                None,
                outer.test_scenario,
                outer_result,
            )

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
        values = np.array([fold["test_metrics"][name] for fold in outer_results])
        aggregate[name] = {
            "macro_mean": float(values.mean()),
            "macro_std": float(values.std(ddof=1)),
            "worst_fold": float(values.min()),
        }
    return {
        "kind": "joint-profile-hyperparameter-nested-optimization",
        "protocol": "nested-leave-one-scenario-out",
        "selection_rule": "AP within 0.01 of best, then macro F1, worst AP, AP std, simplicity",
        "search_configurations": [asdict(item) for item in SEARCH_CONFIGURATIONS],
        "folds": outer_results,
        "aggregate": aggregate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--output", default="output/nested-optimized-ml.json")
    parser.add_argument("--models-dir", default="output/nested-optimized-models")
    parser.add_argument("--inner-cap-per-class", type=int, default=20_000)
    parser.add_argument("--final-cap-per-class", type=int, default=50_000)
    args = parser.parse_args()

    def show_progress(stage, outer, outer_total, config, config_total, scenario, result):
        if stage == "configuration":
            summary = {
                "outer": f"{outer}/{outer_total}",
                "test_scenario_locked": scenario,
                "configuration": f"{config}/{config_total}",
                "name": result["configuration"]["name"],
                "inner_ap": result["macro_average_precision"],
                "inner_f1": result["macro_f1"],
            }
        else:
            summary = {
                "outer": f"{outer}/{outer_total}",
                "test_scenario": scenario,
                "selected": result["selected_configuration"]["name"],
                "test_ap": result["test_metrics"]["average_precision"],
                "test_f1": result["test_metrics"]["f1"],
            }
        print(json.dumps(summary, ensure_ascii=False), flush=True)

    report = optimize_nested(
        args.cache_root,
        args.inner_cap_per_class,
        args.final_cap_per_class,
        args.models_dir,
        show_progress,
    )
    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"aggregate": report["aggregate"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
