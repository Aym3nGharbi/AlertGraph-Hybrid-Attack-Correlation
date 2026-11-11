#!/usr/bin/env python3
"""Réentraîne et sérialise les huit modèles finaux gelés pour l'inférence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np

from evaluate_nested_ml import AIT_SCENARIOS, available_feature_names
from evaluate_rarity_ml import _signature_vocabulary, load_rarity_data, training_idf
from feature_sets import select_feature_profile
from optimize_final_nested_ml import (
    FinalSearchConfiguration,
    _assemble_training,
    _positions,
    make_model,
)


def export(cache_root: Path, optimization_path: Path, output_path: Path) -> dict:
    report = json.loads(optimization_path.read_text(encoding="utf-8"))
    master_features = select_feature_profile(
        available_feature_names(cache_root), "directional_graph"
    )
    data = load_rarity_data(cache_root, master_features)
    vocabulary = _signature_vocabulary(cache_root)
    folds = []
    for fold in report["folds"]:
        configuration = FinalSearchConfiguration(**fold["selected_configuration"])
        positions = _positions(master_features, configuration)
        development = tuple(
            scenario for scenario in AIT_SCENARIOS
            if scenario != fold["test_scenario"]
        )
        idf = training_idf(data, development) if configuration.use_rarity else None
        x_train, y_train, weights = _assemble_training(
            data, development, 50_000, positions, idf
        )
        model = make_model(
            configuration,
            max_iter=int(fold["selected_iterations"]),
            early_stopping=False,
        )
        model.fit(x_train, y_train, sample_weight=weights)
        unseen = None
        if idf is not None:
            total = float(sum(data[x].raw_signature_counts.sum() for x in development))
            unseen = float(np.log(total + 1.0) + 1.0)
        folds.append({
            "held_out_scenario": fold["test_scenario"],
            "configuration": fold["selected_configuration"],
            "feature_names": tuple(master_features[index] for index in positions),
            "threshold": float(fold["selected_threshold"]),
            "iterations": int(fold["selected_iterations"]),
            "model": model,
            "idf": idf,
            "unseen_rarity": unseen,
        })
        print(json.dumps({"exported": fold["test_scenario"], "rows": len(y_train)}), flush=True)
    bundle = {
        "kind": "frozen-final-ait-ensemble",
        "decision_rule": "at least 4 of 8 fold-specific threshold votes",
        "cache_root": str(cache_root),
        "optimization_report": str(optimization_path),
        "signature_vocabulary": vocabulary,
        "folds": folds,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path, compress=3)
    return {"output": str(output_path), "folds": len(folds)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path("data/processed/ait_pairs_v3"))
    parser.add_argument("--optimization", type=Path, default=Path("output/final-nested-optimization.json"))
    parser.add_argument("--output", type=Path, default=Path("output/final-ensemble.joblib"))
    args = parser.parse_args()
    print(json.dumps(export(args.cache, args.optimization, args.output), indent=2))


if __name__ == "__main__":
    main()
