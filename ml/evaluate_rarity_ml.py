#!/usr/bin/env python3
"""Évalue la rareté de signature sans fuite dans les folds groupés imbriqués."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from evaluate_nested_baselines import metrics
from evaluate_nested_ml import (
    AIT_SCENARIOS,
    RANDOM_SEED,
    available_feature_names,
    balanced_validation_weights,
    deterministic_indices,
    new_model,
    select_macro_threshold,
)
from feature_sets import FEATURE_PROFILES, select_feature_profile
from rarity_features import RARITY_FEATURE_NAMES, append_pair_rarity, signature_idf
from split_protocol import nested_leave_one_scenario_out


@dataclass(frozen=True)
class RarityScenarioData:
    x: np.ndarray
    y: np.ndarray
    earlier_codes: np.ndarray
    later_codes: np.ndarray
    raw_signature_counts: np.ndarray


def _signature_vocabulary(cache_root: Path) -> dict[str, int]:
    signatures: set[str] = set()
    for scenario in AIT_SCENARIOS:
        table = pq.read_table(
            cache_root / scenario / "meta_observable.parquet",
            columns=["signature"],
        )
        signatures.update(table["signature"].to_pylist())
    return {value: index for index, value in enumerate(sorted(signatures))}


def load_rarity_data(
    cache_root: str | Path,
    selected_features: tuple[str, ...],
) -> dict[str, RarityScenarioData]:
    root = Path(cache_root)
    vocabulary = _signature_vocabulary(root)
    data = {}
    for scenario in AIT_SCENARIOS:
        meta = pq.read_table(
            root / scenario / "meta_observable.parquet",
            columns=["meta_id", "signature", "member_alert_ids"],
        ).to_pandas()
        meta_codes = meta["signature"].map(vocabulary).to_numpy(dtype=np.int32)
        member_counts = meta["member_alert_ids"].map(len).to_numpy(dtype=np.int64)
        raw_counts = np.bincount(
            meta_codes,
            weights=member_counts,
            minlength=len(vocabulary),
        ).astype(np.int64)
        id_to_code = dict(zip(meta["meta_id"], meta_codes))

        frame = pq.read_table(
            root / scenario / "pair_examples.parquet",
            columns=[
                "earlier_meta_id",
                "later_meta_id",
                *selected_features,
                "target",
            ],
        ).to_pandas()
        frame = frame[frame["target"].notna()]
        earlier_codes = frame["earlier_meta_id"].map(id_to_code).to_numpy(dtype=np.int32)
        later_codes = frame["later_meta_id"].map(id_to_code).to_numpy(dtype=np.int32)
        if np.any(earlier_codes < 0) or np.any(later_codes < 0):
            raise ValueError(f"Signature introuvable pour une paire de {scenario}")
        data[scenario] = RarityScenarioData(
            x=frame.loc[:, selected_features].to_numpy(dtype=np.float32),
            y=frame["target"].to_numpy(dtype=np.int8),
            earlier_codes=earlier_codes,
            later_codes=later_codes,
            raw_signature_counts=raw_counts,
        )
    return data


def training_idf(
    data: dict[str, RarityScenarioData], scenarios: tuple[str, ...]
) -> np.ndarray:
    counts = np.sum(
        [data[scenario].raw_signature_counts for scenario in scenarios], axis=0
    )
    return signature_idf(counts)


def assemble_rarity_training(
    data: dict[str, RarityScenarioData],
    scenarios: tuple[str, ...],
    cap_per_class: int,
    idf: np.ndarray,
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
        x_parts.append(
            append_pair_rarity(
                item.x,
                item.earlier_codes,
                item.later_codes,
                idf,
                indices,
            )
        )
        y_parts.append(selected_y)
        weight_parts.append(weights)
    combined_weights = np.concatenate(weight_parts)
    combined_weights /= combined_weights.mean()
    return np.concatenate(x_parts), np.concatenate(y_parts), combined_weights


def transformed(item: RarityScenarioData, idf: np.ndarray) -> np.ndarray:
    return append_pair_rarity(
        item.x, item.earlier_codes, item.later_codes, idf
    )


def evaluate_rarity_nested(
    cache_root: str | Path,
    profile: str = "directional",
    inner_cap_per_class: int = 20_000,
    final_cap_per_class: int = 50_000,
    progress=None,
) -> dict[str, object]:
    base_features = select_feature_profile(
        available_feature_names(cache_root), profile
    )
    data = load_rarity_data(cache_root, base_features)
    folds = []
    for outer_index, outer in enumerate(nested_leave_one_scenario_out(), 1):
        inner_predictions = {}
        inner_iterations = []
        inner_rows = []
        for inner in outer.inner_folds:
            idf = training_idf(data, inner.train_scenarios)
            x_train, y_train, weights = assemble_rarity_training(
                data, inner.train_scenarios, inner_cap_per_class, idf
            )
            validation = data[inner.validation_scenario]
            x_validation = transformed(validation, idf)
            model = new_model()
            model.fit(
                x_train,
                y_train,
                sample_weight=weights,
                X_val=x_validation,
                y_val=validation.y,
                sample_weight_val=balanced_validation_weights(validation.y),
            )
            inner_predictions[inner.validation_scenario] = (
                validation.y,
                model.predict_proba(x_validation)[:, 1],
            )
            inner_iterations.append(int(model.n_iter_))
            inner_rows.append(len(y_train))

        threshold, inner_macro_f1 = select_macro_threshold(inner_predictions)
        iterations = max(1, int(round(float(np.median(inner_iterations)))))
        idf = training_idf(data, outer.development_scenarios)
        x_development, y_development, weights = assemble_rarity_training(
            data, outer.development_scenarios, final_cap_per_class, idf
        )
        model = new_model(max_iter=iterations, early_stopping=False)
        model.fit(x_development, y_development, sample_weight=weights)
        test = data[outer.test_scenario]
        probability = model.predict_proba(transformed(test, idf))[:, 1]
        fold = {
            "test_scenario": outer.test_scenario,
            "inner_validation_scenarios": tuple(inner_predictions),
            "inner_training_rows": inner_rows,
            "inner_iterations": inner_iterations,
            "selected_iterations": iterations,
            "selected_threshold": threshold,
            "inner_macro_f1": inner_macro_f1,
            "final_training_rows": len(y_development),
            "test_metrics": metrics(test.y, probability, threshold),
        }
        folds.append(fold)
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
        "kind": "train-only-signature-rarity-nested-evaluation",
        "protocol": "nested-leave-one-scenario-out",
        "base_profile": profile,
        "features": (*base_features, *RARITY_FEATURE_NAMES),
        "rarity_count_unit": "raw-member-alerts-in-training-scenarios-only",
        "folds": folds,
        "aggregate": aggregate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--feature-profile", choices=FEATURE_PROFILES, default="directional")
    parser.add_argument("--output", default="output/nested-rarity-ml.json")
    parser.add_argument("--inner-cap-per-class", type=int, default=20_000)
    parser.add_argument("--final-cap-per-class", type=int, default=50_000)
    args = parser.parse_args()

    def show_progress(index, total, fold):
        print(
            json.dumps(
                {
                    "fold": f"{index}/{total}",
                    "test_scenario": fold["test_scenario"],
                    "test_f1": fold["test_metrics"]["f1"],
                    "test_ap": fold["test_metrics"]["average_precision"],
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

    report = evaluate_rarity_nested(
        args.cache_root,
        args.feature_profile,
        args.inner_cap_per_class,
        args.final_cap_per_class,
        show_progress,
    )
    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"aggregate": report["aggregate"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
