#!/usr/bin/env python3
"""Évalue les trois baselines avec sélection interne par scénario."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
    roc_auc_score,
)

from split_protocol import AIT_SCENARIOS, nested_leave_one_scenario_out


FEATURE_COLUMNS = (
    "delta_seconds",
    "shared_ip_count",
    "shared_host_count",
    "service_overlap",
    "signature_text_jaccard",
    "non_malicious_stage_present",
    "stage_known_both",
    "forward_progression_compatible",
    "same_stage",
    "target",
)
ALPHAS = (0.25, 0.5, 0.65, 0.75)
THRESHOLDS = tuple(round(value * 0.05, 2) for value in range(1, 20))


def load_scores(
    cache_root: str | Path,
    scenario: str,
    window_seconds: float = 60.0,
) -> dict[str, np.ndarray]:
    if window_seconds <= 0:
        raise ValueError("window_seconds doit être strictement positif")
    table = pq.read_table(
        Path(cache_root) / scenario / "pair_examples.parquet",
        columns=list(FEATURE_COLUMNS),
    )
    frame = table.to_pandas()
    frame = frame[frame["target"].notna()]
    y = frame["target"].to_numpy(dtype=np.int8)
    delta = frame["delta_seconds"].to_numpy(dtype=np.float32)
    temporal = np.where(
        delta <= window_seconds,
        np.exp(-delta / max(window_seconds / 3.0, 1.0)),
        0.0,
    )
    similarity = (
        0.35 * (frame["shared_ip_count"].to_numpy() > 0)
        + 0.15 * (frame["shared_host_count"].to_numpy() > 0)
        + 0.10 * frame["service_overlap"].to_numpy()
        + 0.15 * frame["signature_text_jaccard"].to_numpy()
        + 0.25 * temporal
    ).astype(np.float32)

    non_malicious = frame["non_malicious_stage_present"].to_numpy(bool)
    known = frame["stage_known_both"].to_numpy(bool)
    compatible = frame["forward_progression_compatible"].to_numpy(bool)
    same = frame["same_stage"].to_numpy(bool)
    causal = np.full(len(frame), 0.05, dtype=np.float32)
    causal[~known] = 0.15
    causal[known & same] = 0.55
    causal[known & compatible] = 1.0
    causal[non_malicious] = 0.05
    return {
        "y": y,
        "similarity": similarity,
        "causality": causal,
        "stage_known": known,
        "same_stage": frame["same_stage"].to_numpy(dtype=bool),
        "compatible": frame["forward_progression_compatible"].to_numpy(dtype=bool),
    }


def metrics(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, object]:
    prediction = (score >= threshold).astype(np.int8)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, prediction, average="binary", zero_division=0
    )
    return {
        "threshold": threshold,
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


def _binary_f1(y: np.ndarray, score: np.ndarray, threshold: float) -> float:
    prediction = score >= threshold
    positive = y == 1
    true_positive = int(np.count_nonzero(prediction & positive))
    false_positive = int(np.count_nonzero(prediction & ~positive))
    false_negative = int(np.count_nonzero(~prediction & positive))
    denominator = 2 * true_positive + false_positive + false_negative
    return 2 * true_positive / denominator if denominator else 0.0


def _f1_cache(
    data: dict[str, dict[str, np.ndarray]],
) -> dict[tuple[str, float | None, str, float], float]:
    cache = {}
    configurations = (("similarity", None), ("causality", None)) + tuple(
        ("similarity", alpha) for alpha in ALPHAS
    )
    for scenario, item in data.items():
        for score_name, alpha in configurations:
            score = item[score_name]
            if alpha is not None:
                score = alpha * item["similarity"] + (1 - alpha) * item["causality"]
            for threshold in THRESHOLDS:
                cache[(score_name, alpha, scenario, threshold)] = _binary_f1(
                    item["y"], score, threshold
                )
    return cache


def _macro_f1(
    cache: dict[tuple[str, float | None, str, float], float],
    scenarios: tuple[str, ...],
    score_name: str,
    threshold: float,
    alpha: float | None = None,
) -> float:
    return float(
        np.mean(
            [
                cache[(score_name, alpha, scenario, threshold)]
                for scenario in scenarios
            ]
        )
    )


def choose_threshold(
    cache: dict[tuple[str, float | None, str, float], float],
    scenarios: tuple[str, ...],
    score_name: str,
    alpha: float | None = None,
) -> tuple[float, float]:
    ranked = [
        (_macro_f1(cache, scenarios, score_name, threshold, alpha), threshold)
        for threshold in THRESHOLDS
    ]
    macro_f1, threshold = max(ranked, key=lambda item: (item[0], item[1]))
    return threshold, macro_f1


def evaluate(
    cache_root: str | Path, window_seconds: float = 60.0
) -> dict[str, object]:
    data = {
        scenario: load_scores(cache_root, scenario, window_seconds)
        for scenario in AIT_SCENARIOS
    }
    cached_f1 = _f1_cache(data)
    fold_results = []
    for outer in nested_leave_one_scenario_out():
        development = outer.development_scenarios
        similarity_threshold, similarity_inner_f1 = choose_threshold(
            cached_f1, development, "similarity"
        )
        causal_threshold, causal_inner_f1 = choose_threshold(
            cached_f1, development, "causality"
        )
        hybrid_choices = []
        for alpha in ALPHAS:
            threshold, inner_f1 = choose_threshold(
                cached_f1, development, "similarity", alpha
            )
            hybrid_choices.append((inner_f1, alpha, threshold))
        hybrid_inner_f1, alpha, hybrid_threshold = max(
            hybrid_choices, key=lambda item: (item[0], item[1], item[2])
        )

        test = data[outer.test_scenario]
        hybrid_score = alpha * test["similarity"] + (1 - alpha) * test["causality"]
        fold_results.append(
            {
                "test_scenario": outer.test_scenario,
                "similarity": {
                    "inner_macro_f1": similarity_inner_f1,
                    **metrics(test["y"], test["similarity"], similarity_threshold),
                },
                "causality": {
                    "inner_macro_f1": causal_inner_f1,
                    **metrics(test["y"], test["causality"], causal_threshold),
                },
                "manual_hybrid": {
                    "alpha": alpha,
                    "inner_macro_f1": hybrid_inner_f1,
                    **metrics(test["y"], hybrid_score, hybrid_threshold),
                },
            }
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
    for model in ("similarity", "causality", "manual_hybrid"):
        aggregate[model] = {}
        for name in metric_names:
            values = np.array([fold[model][name] for fold in fold_results])
            aggregate[model][name] = {
                "macro_mean": float(values.mean()),
                "macro_std": float(values.std(ddof=1)),
            }
    return {
        "protocol": "nested-leave-one-scenario-out",
        "window_seconds": window_seconds,
        "selection_metric": "macro-f1-across-inner-scenarios",
        "alphas": ALPHAS,
        "thresholds": THRESHOLDS,
        "folds": fold_results,
        "aggregate": aggregate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--output")
    parser.add_argument("--window-seconds", type=float, default=60.0)
    args = parser.parse_args()
    report = evaluate(args.cache_root, args.window_seconds)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
