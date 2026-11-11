#!/usr/bin/env python3
"""Pilote ML sur un fold strict avant l'évaluation imbriquée complète."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import precision_recall_curve

from evaluate_nested_baselines import metrics
from pair_features import PairFeatures


FEATURE_NAMES = tuple(PairFeatures.__dataclass_fields__)
DEFAULT_TRAIN = ("fox", "harrison", "santos", "shaw", "wheeler", "wilson")


def load_labeled_frame(cache_root: str | Path, scenario: str) -> pd.DataFrame:
    columns = [*FEATURE_NAMES, "target"]
    frame = pq.read_table(
        Path(cache_root) / scenario / "pair_examples.parquet", columns=columns
    ).to_pandas()
    frame = frame[frame["target"].notna()].copy()
    frame["target"] = frame["target"].astype(np.int8)
    frame["scenario"] = scenario
    return frame


def deterministic_training_sample(
    cache_root: str | Path,
    scenarios: tuple[str, ...],
    max_per_class_per_scenario: int = 50_000,
    seed: int = 20261031,
) -> pd.DataFrame:
    parts = []
    for scenario_index, scenario in enumerate(scenarios):
        frame = load_labeled_frame(cache_root, scenario)
        for target in (0, 1):
            group = frame[frame["target"] == target]
            if len(group) > max_per_class_per_scenario:
                group = group.sample(
                    n=max_per_class_per_scenario,
                    random_state=seed + 10 * scenario_index + target,
                )
            parts.append(group)
    return pd.concat(parts, ignore_index=True)


def scenario_class_weights(frame: pd.DataFrame) -> np.ndarray:
    """Donne la même masse à chaque scénario et classe présente."""

    counts = frame.groupby(["scenario", "target"])["target"].transform("size")
    weights = 1.0 / counts.to_numpy(dtype=np.float64)
    return weights / weights.mean()


def best_f1_threshold(y: np.ndarray, probability: np.ndarray) -> tuple[float, float]:
    precision, recall, thresholds = precision_recall_curve(y, probability)
    denominator = precision + recall
    f1 = np.divide(
        2 * precision * recall,
        denominator,
        out=np.zeros_like(denominator),
        where=denominator > 0,
    )
    if not len(thresholds):
        return 0.5, float(f1[0])
    index = int(np.argmax(f1[:-1]))
    return float(thresholds[index]), float(f1[index])


def run_pilot(
    cache_root: str | Path,
    train_scenarios: tuple[str, ...] = DEFAULT_TRAIN,
    validation_scenario: str = "wardbeck",
    test_scenario: str = "russellmitchell",
    max_per_class_per_scenario: int = 50_000,
) -> tuple[dict[str, object], HistGradientBoostingClassifier]:
    if set(train_scenarios) & {validation_scenario, test_scenario}:
        raise ValueError("Les scénarios train/validation/test doivent être disjoints")
    if validation_scenario == test_scenario:
        raise ValueError("Validation et test doivent être distincts")

    train = deterministic_training_sample(
        cache_root, train_scenarios, max_per_class_per_scenario
    )
    validation = load_labeled_frame(cache_root, validation_scenario)
    test = load_labeled_frame(cache_root, test_scenario)
    train_weights = scenario_class_weights(train)
    validation_weights = scenario_class_weights(validation)

    model = HistGradientBoostingClassifier(
        learning_rate=0.08,
        max_iter=150,
        max_leaf_nodes=15,
        min_samples_leaf=50,
        l2_regularization=1.0,
        early_stopping=True,
        n_iter_no_change=12,
        random_state=20261031,
    )
    model.fit(
        train.loc[:, FEATURE_NAMES],
        train["target"],
        sample_weight=train_weights,
        X_val=validation.loc[:, FEATURE_NAMES],
        y_val=validation["target"],
        sample_weight_val=validation_weights,
    )

    validation_probability = model.predict_proba(
        validation.loc[:, FEATURE_NAMES]
    )[:, 1]
    threshold, validation_f1 = best_f1_threshold(
        validation["target"].to_numpy(), validation_probability
    )
    test_probability = model.predict_proba(test.loc[:, FEATURE_NAMES])[:, 1]
    report = {
        "kind": "technical-pilot-not-final-nested-result",
        "features": FEATURE_NAMES,
        "train_scenarios": train_scenarios,
        "validation_scenario": validation_scenario,
        "test_scenario": test_scenario,
        "max_per_class_per_scenario": max_per_class_per_scenario,
        "train_rows": len(train),
        "validation_rows": len(validation),
        "test_rows": len(test),
        "model_iterations": model.n_iter_,
        "selected_threshold": threshold,
        "validation_f1_at_selected_threshold": validation_f1,
        "test_metrics": metrics(
            test["target"].to_numpy(), test_probability, threshold
        ),
    }
    return report, model


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--output", default="output/ml-pilot.json")
    parser.add_argument("--model-output", default="output/ml-pilot.joblib")
    parser.add_argument("--max-per-class-per-scenario", type=int, default=50_000)
    args = parser.parse_args()
    report, model = run_pilot(
        args.cache_root,
        max_per_class_per_scenario=args.max_per_class_per_scenario,
    )
    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    joblib.dump(model, args.model_output)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
