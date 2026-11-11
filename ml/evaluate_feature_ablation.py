#!/usr/bin/env python3
"""Ablation groupée des nouvelles caractéristiques directionnelles et contextuelles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evaluate_nested_ml import available_feature_names, evaluate_nested_ml
from feature_sets import select_feature_profile


def ablation_feature_sets(cache_root: str | Path) -> dict[str, tuple[str, ...]]:
    all_features = available_feature_names(cache_root)
    return {
        "context_without_direction": select_feature_profile(
            all_features, "context"
        ),
        "direction_without_context": select_feature_profile(
            all_features, "directional"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root")
    parser.add_argument("--output", default="output/feature-ablation.json")
    parser.add_argument("--inner-cap-per-class", type=int, default=20_000)
    parser.add_argument("--final-cap-per-class", type=int, default=50_000)
    args = parser.parse_args()

    reports = {}
    for variant, features in ablation_feature_sets(args.cache_root).items():
        def show_progress(index, total, fold, variant=variant):
            print(
                json.dumps(
                    {
                        "variant": variant,
                        "fold": f"{index}/{total}",
                        "test_scenario": fold["test_scenario"],
                        "test_f1": fold["test_metrics"]["f1"],
                        "test_ap": fold["test_metrics"]["average_precision"],
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

        reports[variant] = evaluate_nested_ml(
            args.cache_root,
            args.inner_cap_per_class,
            args.final_cap_per_class,
            models_dir=None,
            progress=show_progress,
            feature_names=features,
        )
        print(
            json.dumps(
                {variant: reports[variant]["aggregate"]}, ensure_ascii=False
            ),
            flush=True,
        )

    Path(args.output).write_text(
        json.dumps(reports, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
