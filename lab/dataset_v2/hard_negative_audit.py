"""Audit descriptif des négatifs difficiles, sans entraînement ni mutation ML."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from statistics import mean, median, pstdev
from typing import Any

import pyarrow.parquet as pq

from lab.dataset_v2.io_utils import sha256_file, utc_now, write_new_json

IDENTITY_COLUMNS = {"run_id", "earlier_meta_id", "later_meta_id", "candidate_source"}


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _number(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def _quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low = int(math.floor(position)); high = int(math.ceil(position))
    if low == high:
        return ordered[low]
    return ordered[low] * (high - position) + ordered[high] * (position - low)


def _auc_smaller_positive(positive: list[float], negative: list[float]) -> float | None:
    if not positive or not negative:
        return None
    wins = sum(1.0 if p < n else 0.5 if p == n else 0.0 for p in positive for n in negative)
    return wins / (len(positive) * len(negative))


def _summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values), "mean": mean(values) if values else None,
        "median": median(values) if values else None,
        "q25": _quantile(values, .25), "q75": _quantile(values, .75),
        "std": pstdev(values) if len(values) > 1 else 0.0 if values else None,
    }


def audit_campaign(campaign_dir: Path) -> dict[str, Any]:
    cache = campaign_dir / "derived-cache" / "multiphase-fim-observable-normalized"
    parquet = cache / "pair_examples.parquet"
    truth_path = campaign_dir / "supervision-multiphase-fim-v2" / "pair-truth.jsonl"
    summary_path = campaign_dir / "supervision-multiphase-fim-v2" / "scientific-summary.json"
    table = pq.read_table(parquet)
    rows = table.to_pylist()
    features = [name for name in table.column_names if name not in IDENTITY_COLUMNS]
    if len(features) != 42:
        raise ValueError(f"42 caractéristiques attendues, {len(features)} trouvées")
    by_pair = {(str(row["earlier_meta_id"]), str(row["later_meta_id"])): row for row in rows}
    truth = _jsonl(truth_path)
    joined = []
    for label in truth:
        key = (str(label["earlier_meta_id"]), str(label["later_meta_id"]))
        if key not in by_pair:
            raise ValueError(f"label sans candidat observé: {key}")
        joined.append({**by_pair[key], "target": int(label["target"]), "relation_scope": label["relation_scope"]})
    positives = [row for row in joined if row["target"] == 1]
    negatives = [row for row in joined if row["target"] == 0]

    feature_stats: dict[str, Any] = {}
    for feature in features:
        pos = [value for row in positives if (value := _number(row.get(feature))) is not None]
        neg = [value for row in negatives if (value := _number(row.get(feature))) is not None]
        pos_summary = _summary(pos); neg_summary = _summary(neg)
        pooled = math.sqrt(((pos_summary["std"] or 0.0) ** 2 + (neg_summary["std"] or 0.0) ** 2) / 2)
        effect = ((pos_summary["mean"] or 0.0) - (neg_summary["mean"] or 0.0)) / pooled if pooled else 0.0
        auc = _auc_smaller_positive(pos, neg)
        feature_stats[feature] = {
            "positive": pos_summary, "negative": neg_summary,
            "standardized_mean_difference": effect,
            "univariate_separation_auc": max(auc, 1 - auc) if auc is not None else None,
            "univariate_direction": "smaller-positive" if auc is not None and auc >= .5 else "larger-positive",
        }

    delta_pos = [float(row["delta_seconds"]) for row in positives]
    delta_neg = [float(row["delta_seconds"]) for row in negatives]
    pos_q25 = _quantile(delta_pos, .25) or 0.0; pos_q75 = _quantile(delta_pos, .75) or 0.0
    entity_median = median(float(row.get("shared_entity_count") or 0) for row in positives)
    entity_jaccard_median = median(float(row.get("entity_jaccard") or 0) for row in positives)
    hard_rows = []
    for row in negatives:
        evidence = {
            "strong_description_similarity": bool(row.get("same_signature")) or float(row.get("signature_text_jaccard") or 0) >= .8,
            "shared_entities_at_least_positive_median": float(row.get("shared_entity_count") or 0) >= entity_median,
            "entity_jaccard_at_least_positive_median": float(row.get("entity_jaccard") or 0) >= entity_jaccard_median,
            "same_sensor": bool(row.get("same_sensor")),
            "shared_host": float(row.get("shared_host_count") or 0) > 0,
            "shared_ip": float(row.get("shared_ip_count") or 0) > 0,
            "delta_inside_positive_iqr": pos_q25 <= float(row["delta_seconds"]) <= pos_q75,
        }
        score = sum(evidence.values())
        if evidence["strong_description_similarity"] and score >= 4:
            hard_rows.append({
                "earlier_meta_id": row["earlier_meta_id"], "later_meta_id": row["later_meta_id"],
                "relation_scope": row["relation_scope"], "evidence_score": score,
                "delta_seconds": row["delta_seconds"], "evidence": evidence,
            })

    def vector(row: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(row.get(feature) for feature in features)
    positive_vectors = {vector(row) for row in positives}
    exact_cross_label = sum(vector(row) in positive_vectors for row in negatives)
    top_separation = sorted(
        ({"feature": name, **stats} for name, stats in feature_stats.items()),
        key=lambda item: abs(float(item["standardized_mean_difference"])), reverse=True,
    )[:10]
    scientific = json.loads(summary_path.read_text(encoding="utf-8"))
    possible = int(scientific["meta_alerts_total"]) * (int(scientific["meta_alerts_total"]) - 1) // 2
    return {
        "campaign_id": scientific["campaign_id"],
        "raw_sha256": scientific["files_sha256"]["raw_alerts"],
        "feature_count": len(features), "features": features,
        "meta_alerts_total": scientific["meta_alerts_total"],
        "verified_meta_alerts": scientific["verified_meta_alerts"],
        "candidate_pairs": len(rows), "all_possible_pairs": possible,
        "candidate_density": len(rows) / possible if possible else 0.0,
        "strict_positive_pairs": len(positives), "strict_negative_pairs": len(negatives),
        "positive_candidate_coverage": 1.0,
        "missing_verified_negative_pairs": sum(scientific["missing_eligible_pairs"].values()),
        "delta_seconds": {"positive": _summary(delta_pos), "negative": _summary(delta_neg)},
        "temporal_shortcut_auc": max(time_auc, 1 - time_auc) if (time_auc := _auc_smaller_positive(delta_pos, delta_neg)) is not None else None,
        "hard_negative_definition": "strong description/signature similarity is mandatory plus at least three of six entity/context conditions",
        "hard_negative_count": len(hard_rows),
        "hard_negative_by_scope": dict(Counter(row["relation_scope"] for row in hard_rows)),
        "hard_negative_examples": sorted(hard_rows, key=lambda row: (-row["evidence_score"], row["delta_seconds"]))[:20],
        "negative_same_signature_or_text_jaccard_ge_0_8": sum(
            bool(row.get("same_signature")) or float(row.get("signature_text_jaccard") or 0) >= .8 for row in negatives
        ),
        "negative_with_shared_entity": sum(float(row.get("shared_entity_count") or 0) > 0 for row in negatives),
        "negative_feature_vectors_identical_to_a_positive": exact_cross_label,
        "top_univariate_separations": top_separation,
        "feature_statistics": feature_stats,
        "labels_used_only_after_candidate_generation": True,
        "model_trained": False, "training_ready": False,
    }


def compare(campaigns: dict[str, Path]) -> dict[str, Any]:
    audited = {name: audit_campaign(path) for name, path in campaigns.items()}
    d2 = audited["d2"]
    comparisons = {}
    for name, other in audited.items():
        if name == "d2":
            continue
        shifts = []
        for feature in d2["features"]:
            d2_mean = d2["feature_statistics"][feature]["negative"]["mean"]
            other_mean = other["feature_statistics"][feature]["negative"]["mean"]
            if d2_mean is not None and other_mean is not None:
                shifts.append({"feature": feature, "absolute_negative_mean_shift": abs(d2_mean - other_mean)})
        comparisons[name] = {
            "candidate_delta": d2["candidate_pairs"] - other["candidate_pairs"],
            "hard_negative_delta": d2["hard_negative_count"] - other["hard_negative_count"],
            "temporal_shortcut_auc_delta": d2["temporal_shortcut_auc"] - other["temporal_shortcut_auc"],
            "largest_negative_distribution_shifts": sorted(shifts, key=lambda row: row["absolute_negative_mean_shift"], reverse=True)[:10],
        }
    return {
        "schema_version": "alertgraph-hard-negative-audit/2.0",
        "created_at_utc": utc_now(),
        "campaigns": audited, "d2_comparisons": comparisons,
        "interpretation_guard": "descriptive post-generation audit; no feature, threshold, candidate or model was changed",
        "training_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--d2", type=Path, required=True); parser.add_argument("--d1", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = compare({"d2": args.d2, "d1": args.d1, "previous": args.previous})
    write_new_json(args.output, report)
    print(json.dumps({name: {
        "candidates": value["candidate_pairs"], "density": value["candidate_density"],
        "hard_negatives": value["hard_negative_count"], "temporal_auc": value["temporal_shortcut_auc"],
    } for name, value in report["campaigns"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
