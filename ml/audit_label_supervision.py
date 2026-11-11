#!/usr/bin/env python3
"""Audit hors ligne des labels, erreurs OOF et poids d'entraînement AIT.

Le script utilise les caches et les huit modèles gelés sans réentraînement.
Il refuse d'écraser son dossier de sortie.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
)

from evaluate_nested_ml import RANDOM_SEED, deterministic_indices
from experiment_old_causal_bridge_policies import _rarity
from split_protocol import AIT_SCENARIOS


AUDIT_COLUMNS = (
    "earlier_meta_id", "later_meta_id", "target", "label_confidence",
    "label_reason", "candidate_source", "delta_seconds",
    "local_window_evidence", "causal_bridge_evidence", "same_signature",
    "stage_known_both", "same_stage", "forward_progression_compatible",
    "non_malicious_stage_present", "shared_host_count", "shared_ip_count",
    "protocol_overlap", "service_overlap", "forward_network_handoff_count",
    "reverse_network_handoff_count",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _nested_counts(frame: pd.DataFrame, columns: list[str]) -> list[dict]:
    counts = frame.groupby(columns, dropna=False, sort=True).size().reset_index(name="count")
    result = []
    for row in counts.to_dict("records"):
        result.append({key: (None if pd.isna(value) else value) for key, value in row.items()})
    return result


def _confusion(y: np.ndarray, prediction: np.ndarray) -> dict:
    y = np.asarray(y, dtype=np.int8)
    prediction = np.asarray(prediction, dtype=bool)
    positive = y == 1
    tp = int((prediction & positive).sum())
    fp = int((prediction & ~positive).sum())
    fn = int((~prediction & positive).sum())
    tn = int((~prediction & ~positive).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {
        "examples": len(y), "positive": int(positive.sum()), "negative": int((~positive).sum()),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "specificity": specificity,
        "f1": f1, "errors": fp + fn,
    }


def _threshold_metrics(y: np.ndarray, probability: np.ndarray, threshold: float) -> dict:
    prediction = probability >= threshold
    result = _confusion(y, prediction)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, prediction, average="binary", zero_division=0
    )
    result.update(
        {
            "average_precision": float(average_precision_score(y, probability)),
            "precision_sklearn": float(precision),
            "recall_sklearn": float(recall),
            "f1_sklearn": float(f1),
            "mcc": float(matthews_corrcoef(y, prediction)),
            "balanced_accuracy": float(balanced_accuracy_score(y, prediction)),
            "threshold": threshold,
        }
    )
    return result


def _aggregate_confusions(items: list[dict]) -> dict:
    keys = ("examples", "positive", "negative", "tp", "fp", "fn", "tn", "errors")
    total = {key: int(sum(item[key] for item in items)) for key in keys}
    tp, fp, fn, tn = total["tp"], total["fp"], total["fn"], total["tn"]
    total.update(
        {
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "specificity": tn / (tn + fp) if tn + fp else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        }
    )
    return total


def _family_masks(frame: pd.DataFrame, signatures: dict[str, str]) -> dict[str, np.ndarray]:
    left_signature = frame["earlier_meta_id"].map(signatures).astype(str)
    right_signature = frame["later_meta_id"].map(signatures).astype(str)
    delta = frame["delta_seconds"].to_numpy(dtype=float)
    local = frame["local_window_evidence"].to_numpy(dtype=bool)
    causal = frame["causal_bridge_evidence"].to_numpy(dtype=bool)
    return {
        "candidate_local_only": local & ~causal,
        "candidate_causal_only": causal & ~local,
        "candidate_local_and_causal": local & causal,
        "same_signature": frame["same_signature"].to_numpy(dtype=bool),
        "generic_signature_A_All_Evt": left_signature.eq("A-All-Evt").to_numpy() | right_signature.eq("A-All-Evt").to_numpy(),
        "stage_unknown_at_least_one": ~frame["stage_known_both"].to_numpy(dtype=bool),
        "stage_same": frame["same_stage"].to_numpy(dtype=bool),
        "stage_forward_compatible": frame["forward_progression_compatible"].to_numpy(dtype=bool),
        "stage_explicit_incompatible": frame["stage_known_both"].to_numpy(dtype=bool) & ~frame["same_stage"].to_numpy(dtype=bool) & ~frame["forward_progression_compatible"].to_numpy(dtype=bool),
        "non_malicious_stage_present": frame["non_malicious_stage_present"].to_numpy(dtype=bool),
        "shared_host": frame["shared_host_count"].to_numpy(dtype=np.int64) > 0,
        "shared_ip": frame["shared_ip_count"].to_numpy(dtype=np.int64) > 0,
        "protocol_or_service_overlap": frame["protocol_overlap"].to_numpy(dtype=bool) | frame["service_overlap"].to_numpy(dtype=bool),
        "network_handoff": (frame["forward_network_handoff_count"].to_numpy(dtype=np.int64) > 0) | (frame["reverse_network_handoff_count"].to_numpy(dtype=np.int64) > 0),
        "delta_0_2s": delta <= 2,
        "delta_gt2_10s": (delta > 2) & (delta <= 10),
        "delta_gt10_60s": (delta > 10) & (delta <= 60),
        "delta_gt60s": delta > 60,
    }


def _error_family_report(
    frame: pd.DataFrame,
    y: np.ndarray,
    prediction: np.ndarray,
    signatures: dict[str, str],
) -> dict[str, dict]:
    positive = y == 1
    fp = prediction & ~positive
    fn = ~prediction & positive
    confidence = frame["label_confidence"].astype(str).to_numpy()
    result = {}
    for name, mask in _family_masks(frame, signatures).items():
        negative_support = int((mask & ~positive).sum())
        positive_support = int((mask & positive).sum())
        result[name] = {
            "support": int(mask.sum()),
            "positive_support": positive_support,
            "negative_support": negative_support,
            "false_positive": int((mask & fp).sum()),
            "false_negative": int((mask & fn).sum()),
            "false_positive_weak": int((mask & fp & (confidence == "weak")).sum()),
            "false_positive_high": int((mask & fp & (confidence == "high")).sum()),
            "false_negative_weak": int((mask & fn & (confidence == "weak")).sum()),
            "false_negative_high": int((mask & fn & (confidence == "high")).sum()),
            "false_positive_rate": float((mask & fp).sum() / negative_support) if negative_support else None,
            "false_negative_rate": float((mask & fn).sum() / positive_support) if positive_support else None,
        }
    return result


def _top_signature_errors(
    frame: pd.DataFrame,
    y: np.ndarray,
    prediction: np.ndarray,
    signatures: dict[str, str],
    limit: int = 20,
) -> list[dict]:
    error = prediction != (y == 1)
    subset = frame.loc[error, ["earlier_meta_id", "later_meta_id", "target", "label_confidence", "label_reason"]].copy()
    subset["earlier_signature"] = subset["earlier_meta_id"].map(signatures)
    subset["later_signature"] = subset["later_meta_id"].map(signatures)
    grouped = subset.groupby(
        ["target", "label_confidence", "label_reason", "earlier_signature", "later_signature"],
        dropna=False,
    ).size().reset_index(name="errors")
    return grouped.sort_values("errors", ascending=False).head(limit).to_dict("records")


def _meta_distribution(cache: Path) -> dict:
    observable = pq.read_table(cache / "meta_observable.parquet", columns=["meta_id", "member_alert_ids"]).to_pandas()
    truth = pq.read_table(cache / "meta_truth.parquet").to_pandas()
    frame = truth.merge(observable, on="meta_id", validate="one_to_one")
    frame["member_count"] = frame["member_alert_ids"].map(len)
    frame["truth_class"] = np.where(
        frame["is_attack"].eq(True), "attack",
        np.where(frame["is_attack"].eq(False), "benign", "unknown"),
    )
    by_meta = _nested_counts(frame, ["truth_confidence", "truth_class"])
    raw = frame.groupby(["truth_confidence", "truth_class"], dropna=False)["member_count"].sum().reset_index(name="member_alerts")
    return {
        "meta_alerts": int(len(frame)),
        "member_alerts": int(frame["member_count"].sum()),
        "by_meta_alert": by_meta,
        "by_member_alert": raw.to_dict("records"),
    }


def _training_sampling_audit(label_frames: dict[str, pd.DataFrame]) -> dict:
    folds = []
    for held_out in AIT_SCENARIOS:
        development = tuple(s for s in AIT_SCENARIOS if s != held_out)
        selected_parts = []
        scenario_cells = []
        for scenario_index, scenario in enumerate(development):
            frame = label_frames[scenario]
            y = frame["target"].to_numpy(dtype=np.int8)
            indices = deterministic_indices(y, 50_000, RANDOM_SEED + 100 * scenario_index)
            selected = frame.iloc[indices].copy()
            selected["scenario"] = scenario
            weights = np.empty(len(selected), dtype=float)
            for target in (0, 1):
                mask = selected["target"].to_numpy(dtype=np.int8) == target
                weights[mask] = 1.0 / max(int(mask.sum()), 1)
                pool_count = int((y == target).sum())
                scenario_cells.append(
                    {
                        "scenario": scenario,
                        "target": target,
                        "pool": pool_count,
                        "selected": int(mask.sum()),
                        "inclusion_fraction": float(mask.sum() / pool_count) if pool_count else None,
                    }
                )
            selected["raw_weight"] = weights
            selected_parts.append(selected)
        combined = pd.concat(selected_parts, ignore_index=True)
        combined["weight"] = combined["raw_weight"] / combined["raw_weight"].mean()
        total_mass = float(combined["weight"].sum())
        mass = combined.groupby(["target", "label_confidence"], dropna=False)["weight"].sum().reset_index(name="weight_mass")
        mass["weight_fraction"] = mass["weight_mass"] / total_mass
        folds.append(
            {
                "held_out_scenario": held_out,
                "selected_rows": int(len(combined)),
                "selected_distribution": _nested_counts(combined, ["target", "label_confidence", "label_reason"]),
                "weight_mass": mass.to_dict("records"),
                "scenario_class_cells": scenario_cells,
                "strong_negative_selected": int(((combined["target"] == 0) & (combined["label_confidence"] == "high")).sum()),
                "weak_weight_fraction": float(combined.loc[combined["label_confidence"] == "weak", "weight"].sum() / total_mass),
                "strong_weight_fraction": float(combined.loc[combined["label_confidence"] == "high", "weight"].sum() / total_mass),
                "per_example_weight_min": float(combined["weight"].min()),
                "per_example_weight_max": float(combined["weight"].max()),
            }
        )
    return {
        "rule": "deterministic cap 50000 per scenario/class; equal mass per scenario/class; no confidence weighting",
        "folds": folds,
        "summary": {
            "strong_negative_selected": {
                "values": [x["strong_negative_selected"] for x in folds],
                "min": min(x["strong_negative_selected"] for x in folds),
                "max": max(x["strong_negative_selected"] for x in folds),
                "mean": float(np.mean([x["strong_negative_selected"] for x in folds])),
            },
            "weak_weight_fraction": {
                "min": min(x["weak_weight_fraction"] for x in folds),
                "max": max(x["weak_weight_fraction"] for x in folds),
                "mean": float(np.mean([x["weak_weight_fraction"] for x in folds])),
            },
        },
    }


def run_audit(cache_root: Path, ensemble_path: Path) -> dict:
    bundle = joblib.load(ensemble_path)
    folds = {str(x["held_out_scenario"]): x for x in bundle["folds"]}
    vocabulary = bundle["signature_vocabulary"]
    label_frames = {}
    meta_reports = {}
    pair_reports = {}
    scenario_errors = []
    confidence_confusions: dict[str, list[dict]] = defaultdict(list)
    reason_confusions: dict[str, list[dict]] = defaultdict(list)
    family_aggregate: dict[str, Counter] = defaultdict(Counter)

    for scenario in AIT_SCENARIOS:
        cache = cache_root / scenario
        meta_reports[scenario] = _meta_distribution(cache)
        fold = folds[scenario]
        columns = list(dict.fromkeys((*AUDIT_COLUMNS, *fold["feature_names"])))
        full = pq.read_table(cache / "pair_examples.parquet", columns=columns).to_pandas()
        pair_reports[scenario] = {
            "all_candidates": int(len(full)),
            "labeled_candidates": int(full["target"].notna().sum()),
            "excluded_candidates": int(full["target"].isna().sum()),
            "distribution": _nested_counts(full, ["target", "label_confidence", "label_reason"]),
        }
        frame = full[full["target"].notna()].reset_index(drop=True)
        label_frames[scenario] = frame[["target", "label_confidence", "label_reason"]].copy()
        meta = pq.read_table(cache / "meta_observable.parquet", columns=["meta_id", "signature"]).to_pandas()
        signatures = dict(zip(meta["meta_id"], meta["signature"].astype(str)))
        earlier_signatures = frame["earlier_meta_id"].map(signatures).to_numpy()
        later_signatures = frame["later_meta_id"].map(signatures).to_numpy()
        x = frame.loc[:, fold["feature_names"]].to_numpy(dtype=np.float32)
        if fold["idf"] is not None:
            x = np.column_stack(
                (
                    x,
                    _rarity(earlier_signatures, vocabulary, fold["idf"], fold["unseen_rarity"]),
                    _rarity(later_signatures, vocabulary, fold["idf"], fold["unseen_rarity"]),
                )
            ).astype(np.float32)
        y = frame["target"].to_numpy(dtype=np.int8)
        probability = fold["model"].predict_proba(x)[:, 1]
        threshold = float(fold["threshold"])
        prediction = probability >= threshold
        confidence = frame["label_confidence"].astype(str).to_numpy()
        per_confidence = {}
        for value in sorted(set(confidence)):
            mask = confidence == value
            report = _threshold_metrics(y[mask], probability[mask], threshold)
            per_confidence[value] = report
            confidence_confusions[value].append(report)
        per_reason = {}
        for reason in sorted(frame["label_reason"].astype(str).unique()):
            mask = frame["label_reason"].astype(str).to_numpy() == reason
            report = _confusion(y[mask], prediction[mask])
            per_reason[reason] = report
            reason_confusions[reason].append(report)
        families = _error_family_report(frame, y, prediction, signatures)
        for name, values in families.items():
            for key in ("support", "positive_support", "negative_support", "false_positive", "false_negative", "false_positive_weak", "false_positive_high", "false_negative_weak", "false_negative_high"):
                family_aggregate[name][key] += int(values[key])
        scenario_errors.append(
            {
                "scenario": scenario,
                "threshold": threshold,
                "overall": _threshold_metrics(y, probability, threshold),
                "by_confidence": per_confidence,
                "by_label_reason": per_reason,
                "error_families": families,
                "top_signature_error_families": _top_signature_errors(frame, y, prediction, signatures),
            }
        )
        print(json.dumps({"completed": scenario, "pairs": len(frame)}), flush=True)

    aggregate_families = {}
    for name, counts in family_aggregate.items():
        values = dict(counts)
        values["false_positive_rate"] = values["false_positive"] / values["negative_support"] if values["negative_support"] else None
        values["false_negative_rate"] = values["false_negative"] / values["positive_support"] if values["positive_support"] else None
        aggregate_families[name] = values
    return {
        "kind": "offline-ait-label-and-oof-error-audit",
        "scientific_status": "frozen strict out-of-fold predictions; no retraining",
        "inputs": {
            "cache_root": str(cache_root),
            "ensemble": str(ensemble_path),
            "ensemble_sha256": _sha256(ensemble_path),
        },
        "label_rules": {
            "strong_alert": "recognized event_label mapped to an attack phase",
            "weak_attack_alert": "recognized time window with absent event label",
            "weak_benign_alert": "time label starts with false_positive",
            "unknown_alert": "unknown event label or no recognized time/event label",
            "strong_pair": "both meta-alert truth confidences are high",
            "weak_pair": "labeled pair with at least one weak endpoint",
            "excluded_pair": "mixed meta-alert or at least one unknown endpoint",
        },
        "meta_distributions": meta_reports,
        "pair_distributions": pair_reports,
        "strict_oof_errors": {
            "scenarios": scenario_errors,
            "pooled_by_confidence": {key: _aggregate_confusions(values) for key, values in confidence_confusions.items()},
            "pooled_by_label_reason": {key: _aggregate_confusions(values) for key, values in reason_confusions.items()},
            "pooled_error_families": aggregate_families,
            "macro_scenario_metrics": {
                key: float(np.mean([item["overall"][key] for item in scenario_errors]))
                for key in ("average_precision", "precision_sklearn", "recall_sklearn", "f1_sklearn", "mcc", "balanced_accuracy")
            },
        },
        "training_sampling": _training_sampling_audit(label_frames),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=Path("data/processed/ait_pairs_v3"))
    parser.add_argument("--ensemble", type=Path, default=Path("output/final-ensemble.joblib"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"Le dossier existe déjà: {args.output_dir}")
    report = run_audit(args.cache_root, args.ensemble)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(args.output_dir / "report.json")}, indent=2))


if __name__ == "__main__":
    main()
