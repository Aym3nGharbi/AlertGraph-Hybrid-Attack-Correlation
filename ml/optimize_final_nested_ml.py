#!/usr/bin/env python3
"""Recherche finale bornée : profil, rareté et gradient boosting imbriqués."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score

from evaluate_nested_baselines import metrics
from evaluate_nested_ml import (
    AIT_SCENARIOS,
    RANDOM_SEED,
    available_feature_names,
    balanced_validation_weights,
    deterministic_indices,
    select_macro_threshold,
)
from evaluate_rarity_ml import RarityScenarioData, load_rarity_data, training_idf
from feature_sets import MITRE_FEATURES, select_feature_profile
from rarity_features import RARITY_FEATURE_NAMES, append_pair_rarity
from split_protocol import nested_leave_one_scenario_out


@dataclass(frozen=True)
class FinalSearchConfiguration:
    name: str
    feature_variant: str
    use_rarity: bool
    learning_rate: float
    max_iter: int
    max_leaf_nodes: int
    min_samples_leaf: int
    l2_regularization: float
    max_features: float


FINAL_SEARCH_CONFIGURATIONS = (
    FinalSearchConfiguration("directional-current", "directional", False, 0.08, 150, 15, 50, 1.0, 1.0),
    FinalSearchConfiguration("directional-regularized", "directional", False, 0.05, 220, 15, 200, 5.0, 0.7),
    FinalSearchConfiguration("directional-shallow", "directional", False, 0.05, 220, 7, 200, 10.0, 1.0),
    FinalSearchConfiguration("directional-flexible", "directional", False, 0.05, 220, 31, 50, 5.0, 0.7),
    FinalSearchConfiguration("directional-low-rate", "directional", False, 0.03, 220, 15, 200, 10.0, 0.7),
    FinalSearchConfiguration("no-mitre-current", "directional_without_mitre", False, 0.08, 150, 15, 50, 1.0, 1.0),
    FinalSearchConfiguration("no-mitre-regularized", "directional_without_mitre", False, 0.05, 220, 15, 200, 5.0, 0.7),
    FinalSearchConfiguration("graph-current", "directional_graph", False, 0.08, 150, 15, 50, 1.0, 1.0),
    FinalSearchConfiguration("graph-regularized", "directional_graph", False, 0.05, 220, 15, 200, 5.0, 0.7),
    FinalSearchConfiguration("rarity-current", "directional", True, 0.08, 150, 15, 50, 1.0, 1.0),
    FinalSearchConfiguration("rarity-regularized", "directional", True, 0.05, 220, 15, 200, 5.0, 0.7),
    FinalSearchConfiguration("rarity-shallow", "directional", True, 0.05, 220, 7, 200, 10.0, 1.0),
    FinalSearchConfiguration("rarity-graph", "directional_graph", True, 0.05, 220, 15, 200, 5.0, 0.7),
)


def configuration_features(
    available: tuple[str, ...], configuration: FinalSearchConfiguration
) -> tuple[str, ...]:
    if configuration.feature_variant == "directional_without_mitre":
        base = select_feature_profile(available, "directional")
        selected = tuple(name for name in base if name not in MITRE_FEATURES)
    else:
        selected = select_feature_profile(available, configuration.feature_variant)
    if configuration.use_rarity:
        return (*selected, *RARITY_FEATURE_NAMES)
    return selected


def make_model(
    configuration: FinalSearchConfiguration,
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
    evaluations: list[dict[str, object]], ap_tolerance: float = 0.01
) -> dict[str, object]:
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


def _positions(
    master_features: tuple[str, ...], configuration: FinalSearchConfiguration
) -> tuple[int, ...]:
    names = configuration_features(master_features, configuration)
    return tuple(master_features.index(name) for name in names if name in master_features)


def _transform(
    item: RarityScenarioData,
    positions: tuple[int, ...],
    idf: np.ndarray | None,
    indices: np.ndarray | None = None,
) -> np.ndarray:
    x = item.x[:, positions]
    if idf is None:
        return x if indices is None else x[indices]
    return append_pair_rarity(
        x, item.earlier_codes, item.later_codes, idf, indices
    )


def _assemble_training(
    data: dict[str, RarityScenarioData],
    scenarios: tuple[str, ...],
    cap_per_class: int,
    positions: tuple[int, ...],
    idf: np.ndarray | None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x_parts, y_parts, weight_parts = [], [], []
    for scenario_index, scenario in enumerate(scenarios):
        item = data[scenario]
        indices = deterministic_indices(
            item.y, cap_per_class, RANDOM_SEED + 100 * scenario_index
        )
        selected_y = item.y[indices]
        weights = np.empty(len(indices), dtype=np.float64)
        for target in (0, 1):
            mask = selected_y == target
            weights[mask] = 1.0 / max(int(mask.sum()), 1)
        x_parts.append(_transform(item, positions, idf, indices))
        y_parts.append(selected_y)
        weight_parts.append(weights)
    combined_weights = np.concatenate(weight_parts)
    combined_weights /= combined_weights.mean()
    return np.concatenate(x_parts), np.concatenate(y_parts), combined_weights


def optimize_final_nested(
    cache_root: str | Path,
    inner_cap_per_class: int = 20_000,
    final_cap_per_class: int = 50_000,
    progress=None,
) -> dict[str, object]:
    available = available_feature_names(cache_root)
    master_features = select_feature_profile(available, "directional_graph")
    data = load_rarity_data(cache_root, master_features)
    folds = []
    for outer_index, outer in enumerate(nested_leave_one_scenario_out(), 1):
        evaluations = []
        for config_index, configuration in enumerate(FINAL_SEARCH_CONFIGURATIONS, 1):
            positions = _positions(master_features, configuration)
            predictions = {}
            iterations = []
            training_rows = []
            for inner in outer.inner_folds:
                idf = (
                    training_idf(data, inner.train_scenarios)
                    if configuration.use_rarity
                    else None
                )
                x_train, y_train, weights = _assemble_training(
                    data,
                    inner.train_scenarios,
                    inner_cap_per_class,
                    positions,
                    idf,
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
                predictions[inner.validation_scenario] = (
                    validation.y,
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
            feature_names = configuration_features(master_features, configuration)
            result = {
                "configuration": asdict(configuration),
                "feature_count": len(feature_names),
                "features": feature_names,
                "selected_threshold": threshold,
                "macro_f1": macro_f1,
                "macro_average_precision": float(ap_values.mean()),
                "std_average_precision": float(ap_values.std(ddof=1)),
                "worst_scenario_average_precision": float(ap_values.min()),
                "iterations": iterations,
                "median_iterations": max(1, int(round(float(np.median(iterations))))),
                "training_rows": training_rows,
            }
            evaluations.append(result)
            if progress:
                progress("configuration", outer_index, config_index, outer.test_scenario, result)

        selected = select_configuration(evaluations)
        configuration = FinalSearchConfiguration(**selected["configuration"])
        positions = _positions(master_features, configuration)
        idf = (
            training_idf(data, outer.development_scenarios)
            if configuration.use_rarity
            else None
        )
        x_train, y_train, weights = _assemble_training(
            data,
            outer.development_scenarios,
            final_cap_per_class,
            positions,
            idf,
        )
        model = make_model(
            configuration,
            max_iter=selected["median_iterations"],
            early_stopping=False,
        )
        model.fit(x_train, y_train, sample_weight=weights)
        test = data[outer.test_scenario]
        probability = model.predict_proba(_transform(test, positions, idf))[:, 1]
        fold = {
            "test_scenario": outer.test_scenario,
            "configuration_evaluations": evaluations,
            "selected_configuration": selected["configuration"],
            "selected_features": selected["features"],
            "selected_threshold": selected["selected_threshold"],
            "selected_iterations": selected["median_iterations"],
            "final_training_rows": len(y_train),
            "test_metrics": metrics(test.y, probability, selected["selected_threshold"]),
        }
        folds.append(fold)
        if progress:
            progress("fold", outer_index, None, outer.test_scenario, fold)

    metric_names = (
        "average_precision", "roc_auc", "precision", "recall", "f1", "mcc", "balanced_accuracy"
    )
    aggregate = {}
    for name in metric_names:
        values = np.array([fold["test_metrics"][name] for fold in folds])
        aggregate[name] = {
            "macro_mean": float(values.mean()),
            "macro_std": float(values.std(ddof=1)),
            "worst_fold": float(values.min()),
        }
    return {
        "kind": "final-profile-rarity-hyperparameter-nested-optimization",
        "protocol": "nested-leave-one-scenario-out",
        "selection_rule": "AP within 0.01, then F1, worst AP, AP std, simplicity",
        "search_configurations": [asdict(item) for item in FINAL_SEARCH_CONFIGURATIONS],
        "folds": folds,
        "aggregate": aggregate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--output", default="output/final-nested-optimization.json")
    parser.add_argument("--inner-cap-per-class", type=int, default=20_000)
    parser.add_argument("--final-cap-per-class", type=int, default=50_000)
    args = parser.parse_args()

    def show_progress(stage, outer, config, scenario, result):
        if stage == "configuration":
            summary = {
                "outer": f"{outer}/{len(AIT_SCENARIOS)}",
                "test_scenario_locked": scenario,
                "configuration": f"{config}/{len(FINAL_SEARCH_CONFIGURATIONS)}",
                "name": result["configuration"]["name"],
                "inner_ap": result["macro_average_precision"],
                "inner_f1": result["macro_f1"],
            }
        else:
            summary = {
                "outer": f"{outer}/{len(AIT_SCENARIOS)}",
                "test_scenario": scenario,
                "selected": result["selected_configuration"]["name"],
                "test_ap": result["test_metrics"]["average_precision"],
                "test_f1": result["test_metrics"]["f1"],
            }
        print(json.dumps(summary, ensure_ascii=False), flush=True)

    report = optimize_final_nested(
        args.cache_root,
        args.inner_cap_per_class,
        args.final_cap_per_class,
        show_progress,
    )
    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"aggregate": report["aggregate"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
