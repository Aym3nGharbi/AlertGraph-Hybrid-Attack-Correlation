#!/usr/bin/env python3
"""Évalue les graphes disponibles sur les seuls labels explicitement admissibles."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import matthews_corrcoef, precision_recall_fscore_support

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml"))
from graph_metrics import clustering_metrics  # noqa: E402


METHODS = (
    "ml_only", "ml_and_manual", "manual_core_ml_bridges_legacy_mean",
    "manual_core_ml_bridges",
    "episode_constrained_bridges",
)


def evaluate(cache: Path, inference: Path, annotations: Path, *, accept_proposals: bool) -> dict:
    annotation = json.loads(annotations.read_text(encoding="utf-8"))["proposals"]
    allowed = {
        alert_id: value for alert_id, value in annotation.items()
        if value.get("reviewed") or accept_proposals
    }
    meta = pq.read_table(cache / "meta_observable.parquet").to_pandas()
    pairs = pq.read_table(inference / "pair_predictions.parquet").to_pandas()
    methods = tuple(method for method in METHODS if method in pairs.columns)
    labels, phases, weights = {}, {}, {}
    for row in meta.itertuples(index=False):
        member_labels = [allowed[x] for x in row.member_alert_ids if x in allowed]
        if not member_labels:
            continue
        instances = {x["attack_instance_id"] for x in member_labels}
        if len(instances) != 1:
            continue
        labels[row.meta_id] = next(iter(instances))
        phases[row.meta_id] = {x["ground_truth_phase"] for x in member_labels}
        weights[row.meta_id] = len(row.member_alert_ids)

    pair_known = pairs["earlier_meta_id"].isin(labels) & pairs["later_meta_id"].isin(labels)
    known_pairs = pairs[pair_known].copy()
    target = np.asarray([
        labels[left] == labels[right]
        for left, right in zip(known_pairs["earlier_meta_id"], known_pairs["later_meta_id"])
    ], dtype=np.int8)
    reports = {}
    for method in methods:
        prediction = known_pairs[method].to_numpy(dtype=np.int8)
        has_both_classes = len(np.unique(target)) > 1
        if len(target):
            precision, recall, f1, _ = precision_recall_fscore_support(target, prediction, average="binary", zero_division=0)
            if not has_both_classes:
                precision = None
                f1 = None
            mcc = float(matthews_corrcoef(target, prediction)) if has_both_classes else None
        else:
            precision = recall = f1 = 0.0
            mcc = None

        component_column = f"{method}_component"
        attack_nodes = meta[meta["meta_id"].isin(labels)].copy()
        components = dict(zip(attack_nodes["meta_id"], attack_nodes[component_column])) if component_column in attack_nodes else {}
        # Les composantes sont stockées dans nodes.parquet, pas dans le cache observable.
        inferred_nodes = pq.read_table(inference / "nodes.parquet", columns=["meta_id", component_column]).to_pandas()
        components = dict(zip(inferred_nodes["meta_id"], inferred_nodes[component_column]))
        by_attack = {}
        for meta_id, attack_id in labels.items():
            by_attack.setdefault(attack_id, []).append(meta_id)
        fragments = []
        largest = []
        phase_coverages = []
        for attack_id, members in by_attack.items():
            member_components = [components[x] for x in members]
            unique, counts = np.unique(member_components, return_counts=True)
            dominant = unique[int(np.argmax(counts))]
            dominant_members = [x for x in members if components[x] == dominant]
            total_weight = sum(weights[x] for x in members)
            dominant_weight = sum(weights[x] for x in dominant_members)
            all_phases = set().union(*(phases[x] for x in members))
            dominant_phases = set().union(*(phases[x] for x in dominant_members))
            fragments.append(len(unique))
            largest.append(dominant_weight / total_weight if total_weight else 0.0)
            phase_coverages.append(len(dominant_phases & all_phases) / len(all_phases) if all_phases else 0.0)
        labeled_ids = list(labels)
        gold = np.asarray([labels[x] for x in labeled_ids], dtype=object)
        predicted = np.asarray([components[x] for x in labeled_ids], dtype=np.int32)
        member_weights = np.asarray([weights[x] for x in labeled_ids], dtype=np.int64)
        clusters_to_attacks = {}
        for meta_id in labeled_ids:
            clusters_to_attacks.setdefault(components[meta_id], set()).add(labels[meta_id])
        fused = [values for values in clusters_to_attacks.values() if len(values) > 1]
        reports[method] = {
            "known_pair_count": int(len(target)),
            "known_positive_pairs": int(target.sum()),
            "relation_precision": float(precision) if precision is not None else None,
            "relation_recall": float(recall),
            "relation_f1": float(f1) if f1 is not None else None,
            "relation_mcc": mcc,
            "mean_fragments_per_attack": float(np.mean(fragments)) if fragments else None,
            "mean_largest_fragment_coverage": float(np.mean(largest)) if largest else None,
            "mean_phase_coverage": float(np.mean(phase_coverages)) if phase_coverages else None,
            "fused_components": len(fused),
            "attack_instances_in_fused_components": len(set().union(*fused)) if fused else 0,
            "clustering_meta": clustering_metrics(gold, predicted),
            "clustering_raw_weighted": clustering_metrics(gold, predicted, member_weights),
        }
    limitations = ["unlisted alerts are unknown and excluded"]
    if len(set(labels.values())) < 2:
        limitations.append("one attack instance cannot measure cross-attack fusion")
    if len(target) and len(np.unique(target)) < 2:
        limitations.append("without known negative pairs, precision, F1 and MCC are not estimable")
    ground_truth = {
        meta_id: {
            "attack_instance_id": labels[meta_id],
            "ground_truth_phases": sorted(phases[meta_id]),
            "labeled_member_count": sum(
                member in allowed
                for member in meta.loc[meta["meta_id"] == meta_id, "member_alert_ids"].iloc[0]
            ),
        }
        for meta_id in labels
    }
    return {
        "kind": "lab-run-partial-ground-truth-evaluation",
        "accepted_unreviewed_proposals": accept_proposals,
        "labeled_raw_alerts": len(allowed),
        "labeled_meta_alerts": len(labels),
        "attack_instances": len(set(labels.values())),
        "limitations": limitations,
        "ground_truth": {
            "mode": "evaluation-only",
            "status": "provisional" if accept_proposals else "reviewed",
            "meta_labels": ground_truth,
        },
        "methods": reports,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path)
    parser.add_argument("inference", type=Path)
    parser.add_argument("annotations", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--accept-proposals", action="store_true")
    args = parser.parse_args()
    report = evaluate(args.cache, args.inference, args.annotations, accept_proposals=args.accept_proposals)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
