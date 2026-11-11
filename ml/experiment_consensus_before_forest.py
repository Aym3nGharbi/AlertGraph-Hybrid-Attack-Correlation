#!/usr/bin/env python3
"""Compare le vote après huit forêts au consensus avant une forêt unique.

Expérience hors ligne uniquement. Aucun modèle n'est réentraîné et le dossier
de sortie doit être nouveau. Les comparaisons à huit modèles sur AIT sont
explicitement exploratoires car sept modèles ont déjà vu le scénario évalué.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from evaluate_nested_baselines import load_scores
from experiment_old_causal_bridge_policies import _aggregate, _rarity, _scenario_metrics
from graph_reconstruction import (
    DisjointSet,
    MANUAL_ALPHA,
    MANUAL_THRESHOLD,
    bridge_prediction,
)
from optimize_graph_thresholds import component_membership, load_meta, prepare_fast_graph_truth


FOCUS_SCENARIOS = frozenset({"harrison", "santos", "wilson", "fox", "wheeler"})
QUORUM = 4


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fold_relation_masks(
    probability: np.ndarray,
    scores: dict[str, np.ndarray],
    pair_threshold: float,
    bridge_threshold: float,
) -> tuple[np.ndarray, np.ndarray]:
    """Retourne le cœur et toute relation admissible dans un modèle figé."""

    manual = MANUAL_ALPHA * scores["similarity"] + (1.0 - MANUAL_ALPHA) * scores["causality"]
    core = (probability >= pair_threshold) & (manual >= MANUAL_THRESHOLD)
    compatible = ~scores["stage_known"] | scores["same_stage"] | scores["compatible"]
    admissible = core | (compatible & (probability >= bridge_threshold))
    return core, admissible


def consensus_before_forest(
    meta: pd.DataFrame,
    pairs: pd.DataFrame,
    core_votes: np.ndarray,
    admissible_votes: np.ndarray,
    mean_probability: np.ndarray,
    quorum: int = QUORUM,
) -> np.ndarray:
    """Cœur voté, puis forêt unique sur les ponts admissibles consensuels.

    Ordre déterministe des ponts : votes décroissants, probabilité moyenne
    décroissante, puis position originale croissante. La probabilité n'ajoute
    pas de seuil; elle départage et ordonne les relations ayant déjà le quorum.
    """

    size = len(pairs)
    arrays = (core_votes, admissible_votes, mean_probability)
    if any(len(values) != size for values in arrays):
        raise ValueError("Désalignement des paires et des votes de consensus")
    if quorum < 1:
        raise ValueError("Le quorum doit être strictement positif")

    core = np.asarray(core_votes) >= quorum
    candidates = np.flatnonzero(~core & (np.asarray(admissible_votes) >= quorum))
    if len(candidates):
        order = np.lexsort(
            (
                candidates,
                -np.asarray(mean_probability)[candidates],
                -np.asarray(admissible_votes)[candidates],
            )
        )
        candidates = candidates[order]

    vertex = {meta_id: index for index, meta_id in enumerate(meta["meta_id"])}
    left = pairs["earlier_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    right = pairs["later_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    dsu = DisjointSet(len(meta))
    for index in np.flatnonzero(core):
        dsu.union(int(left[index]), int(right[index]))
    prediction = core.copy()
    for index in candidates:
        if dsu.union(int(left[index]), int(right[index])):
            prediction[index] = True
    return prediction


def _truth_breakdown(frame: pd.DataFrame, prediction: np.ndarray) -> dict:
    target = frame["target"].to_numpy(dtype=np.int8)
    confidence = frame["label_confidence"].astype(str).to_numpy()
    masks = {
        "strong_positive": (target == 1) & (confidence == "high"),
        "weak_positive": (target == 1) & (confidence != "high"),
        "strong_negative": (target == 0) & (confidence == "high"),
        "weak_negative": (target == 0) & (confidence != "high"),
    }
    return {
        name: {"available": int(mask.sum()), "selected": int((mask & prediction).sum())}
        for name, mask in masks.items()
    }


def _delta(new: dict, baseline: dict) -> dict:
    return {
        "selected_edges": new["relation"]["selected_edges"] - baseline["relation"]["selected_edges"],
        "strong_positive_selected": new["relation"]["selected_high_positive"] - baseline["relation"]["selected_high_positive"],
        "weak_positive_selected": new["relation"]["selected_weak_positive"] - baseline["relation"]["selected_weak_positive"],
        "weak_negative_selected": new["relation"]["selected_weak_negative"] - baseline["relation"]["selected_weak_negative"],
        "fused_attack_clusters": new["fused_attack_clusters"] - baseline["fused_attack_clusters"],
        "bcubed_meta_attacks": new["graph"]["bcubed_meta_attacks"] - baseline["graph"]["bcubed_meta_attacks"],
        "ari_meta_attacks": new["graph"]["ari_meta_attacks"] - baseline["graph"]["ari_meta_attacks"],
        "attack_fragments": new["graph"]["attack_fragments"] - baseline["graph"]["attack_fragments"],
        "largest_attack_fragment": new["graph"]["largest_attack_fragment"] - baseline["graph"]["largest_attack_fragment"],
        "phase_type_coverage": new["graph"]["phase_type_coverage"] - baseline["graph"]["phase_type_coverage"],
        "phase_alert_recall": new["graph"]["phase_alert_recall"] - baseline["graph"]["phase_alert_recall"],
    }


def _fusion_diagnostics(
    meta: pd.DataFrame, frame: pd.DataFrame, prediction: np.ndarray
) -> dict:
    pair_ids = frame[["earlier_meta_id", "later_meta_id", "target"]]
    membership, _, _ = component_membership(
        meta, pair_ids, prediction.astype(np.float32), 0.5
    )
    attack = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    instances = meta["attack_instance_id"].fillna("").astype(str).to_numpy()
    weights = meta["member_count"].to_numpy(dtype=np.int64)
    components = []
    for component in np.unique(membership[attack]):
        nodes = membership == component
        attack_nodes = nodes & attack
        instance_counts = {
            instance: int((attack_nodes & (instances == instance)).sum())
            for instance in sorted(set(instances[attack_nodes]))
        }
        if len(instance_counts) < 2:
            continue
        instance_raw_counts = {
            instance: int(weights[attack_nodes & (instances == instance)].sum())
            for instance in instance_counts
        }
        components.append(
            {
                "component": int(component),
                "total_meta_nodes": int(nodes.sum()),
                "attack_meta_nodes": int(attack_nodes.sum()),
                "nonattack_meta_nodes": int((nodes & ~attack).sum()),
                "attack_meta_nodes_by_instance": instance_counts,
                "attack_raw_alerts_by_instance": instance_raw_counts,
            }
        )
    return {
        "fused_component_count": len(components),
        "attack_meta_nodes_in_fused_components": int(
            sum(item["attack_meta_nodes"] for item in components)
        ),
        "nonattack_meta_nodes_in_fused_components": int(
            sum(item["nonattack_meta_nodes"] for item in components)
        ),
        "components": components,
    }


def _changed_edges(
    scenario: str,
    frame: pd.DataFrame,
    baseline: np.ndarray,
    consensus: np.ndarray,
    core_votes: np.ndarray,
    admissible_votes: np.ndarray,
    mean_probability: np.ndarray,
) -> list[dict]:
    changed = baseline ^ consensus
    rows = []
    for index in np.flatnonzero(changed):
        row = frame.iloc[int(index)]
        rows.append(
            {
                "scenario": scenario,
                "pair_index": int(index),
                "change": "added_by_consensus" if consensus[index] else "removed_by_consensus",
                "earlier_meta_id": str(row["earlier_meta_id"]),
                "later_meta_id": str(row["later_meta_id"]),
                "target": int(row["target"]),
                "label_confidence": str(row["label_confidence"]),
                "label_reason": str(row["label_reason"]),
                "candidate_source": str(row["candidate_source"]),
                "delta_seconds": float(row["delta_seconds"]),
                "core_votes": int(core_votes[index]),
                "admissible_votes": int(admissible_votes[index]),
                "mean_probability": float(mean_probability[index]),
            }
        )
    return rows


def run_experiment(cache_root: Path, ensemble_path: Path, graph_policy_path: Path) -> tuple[dict, list[dict]]:
    bundle = joblib.load(ensemble_path)
    policy = json.loads(graph_policy_path.read_text(encoding="utf-8"))
    graph_thresholds = {
        item["scenario"]: float(item["selected_bridge_threshold"]["threshold"])
        for item in policy["ait"]["scenarios"]
    }
    scenarios = [str(fold["held_out_scenario"]) for fold in bundle["folds"]]
    vocabulary = bundle["signature_vocabulary"]
    reports = []
    changed_edges = []

    for scenario in scenarios:
        cache = cache_root / scenario
        frame = pq.read_table(cache / "pair_examples.parquet").to_pandas()
        frame = frame[frame["target"].notna()].reset_index(drop=True)
        observable = pq.read_table(cache / "meta_observable.parquet").to_pandas()
        meta = load_meta(cache_root, scenario)
        scores = load_scores(cache_root, scenario)
        signature_by_id = dict(zip(observable["meta_id"], observable["signature"]))
        earlier_signatures = frame["earlier_meta_id"].map(signature_by_id).to_numpy()
        later_signatures = frame["later_meta_id"].map(signature_by_id).to_numpy()

        core_votes = np.zeros(len(frame), dtype=np.int8)
        admissible_votes = np.zeros(len(frame), dtype=np.int8)
        graph_votes = np.zeros(len(frame), dtype=np.int8)
        mean_probability = np.zeros(len(frame), dtype=np.float64)
        oof_prediction = None
        for fold in bundle["folds"]:
            x = frame.loc[:, fold["feature_names"]].to_numpy(dtype=np.float32)
            if fold["idf"] is not None:
                x = np.column_stack(
                    (
                        x,
                        _rarity(earlier_signatures, vocabulary, fold["idf"], fold["unseen_rarity"]),
                        _rarity(later_signatures, vocabulary, fold["idf"], fold["unseen_rarity"]),
                    )
                ).astype(np.float32)
            probability = fold["model"].predict_proba(x)[:, 1]
            pair_threshold = float(fold["threshold"])
            bridge_threshold = graph_thresholds[str(fold["held_out_scenario"])]
            core, admissible = fold_relation_masks(
                probability, scores, pair_threshold, bridge_threshold
            )
            fold_graph = bridge_prediction(
                meta, frame, probability, scores, pair_threshold, bridge_threshold
            )
            core_votes += core.astype(np.int8)
            admissible_votes += admissible.astype(np.int8)
            graph_votes += fold_graph.astype(np.int8)
            mean_probability += probability / len(bundle["folds"])
            if str(fold["held_out_scenario"]) == scenario:
                oof_prediction = fold_graph

        if oof_prediction is None:
            raise AssertionError(f"Aucun modèle hors-fold trouvé pour {scenario}")
        baseline = graph_votes >= QUORUM
        consensus = consensus_before_forest(
            meta, frame, core_votes, admissible_votes, mean_probability, QUORUM
        )
        prepared = prepare_fast_graph_truth(meta)
        oof_metrics = _scenario_metrics(meta, frame, oof_prediction, prepared)
        baseline_metrics = _scenario_metrics(meta, frame, baseline, prepared)
        consensus_metrics = _scenario_metrics(meta, frame, consensus, prepared)
        reports.append(
            {
                "scenario": scenario,
                "strict_out_of_fold_reference": {
                    "method": "single frozen model whose training excluded this scenario",
                    "metrics": oof_metrics,
                    "truth_breakdown": _truth_breakdown(frame, oof_prediction),
                    "fusion_diagnostics": _fusion_diagnostics(meta, frame, oof_prediction),
                },
                "exploratory_eight_model": {
                    "independent_generalization": False,
                    "baseline_vote_after_forests": {
                        "metrics": baseline_metrics,
                        "truth_breakdown": _truth_breakdown(frame, baseline),
                        "fusion_diagnostics": _fusion_diagnostics(meta, frame, baseline),
                    },
                    "consensus_before_forest": {
                        "metrics": consensus_metrics,
                        "truth_breakdown": _truth_breakdown(frame, consensus),
                        "fusion_diagnostics": _fusion_diagnostics(meta, frame, consensus),
                    },
                    "delta_consensus_minus_baseline": _delta(consensus_metrics, baseline_metrics),
                    "changed_edges": int((baseline ^ consensus).sum()),
                    "added_edges": int((consensus & ~baseline).sum()),
                    "removed_edges": int((baseline & ~consensus).sum()),
                },
            }
        )
        if scenario in FOCUS_SCENARIOS:
            changed_edges.extend(
                _changed_edges(
                    scenario, frame, baseline, consensus, core_votes,
                    admissible_votes, mean_probability,
                )
            )
        print(json.dumps({"completed": scenario, "baseline": int(baseline.sum()), "consensus": int(consensus.sum())}), flush=True)

    oof_items = [item["strict_out_of_fold_reference"]["metrics"] for item in reports]
    baseline_items = [item["exploratory_eight_model"]["baseline_vote_after_forests"]["metrics"] for item in reports]
    consensus_items = [item["exploratory_eight_model"]["consensus_before_forest"]["metrics"] for item in reports]
    focus = [item for item in reports if item["scenario"] in FOCUS_SCENARIOS]
    result = {
        "kind": "offline-consensus-before-forest-development-experiment",
        "scientific_status": {
            "strict_out_of_fold_reference": "descriptive frozen OOF baseline; no eight-model consensus is possible OOF with current artifacts",
            "eight_model_comparison": "exploratory only; seven of eight models may have seen the evaluated AIT scenario",
        },
        "no_retraining": True,
        "production_changed": False,
        "external_datasets_used": [],
        "quorum": QUORUM,
        "consensus_definition": {
            "core": "core in at least 4 of 8 frozen models",
            "bridge_candidate": "admissible as core or compatible bridge in at least 4 of 8 frozen models",
            "ordering": [
                "admissibility vote count descending",
                "mean frozen-model probability descending",
                "original pair position ascending for deterministic ties",
            ],
            "new_probability_threshold": None,
            "forest": "one DSU maximum-ranking forest seeded by all consensus-core edges",
        },
        "inputs": {
            "cache_root": str(cache_root),
            "ensemble": str(ensemble_path),
            "ensemble_sha256": _sha256(ensemble_path),
            "graph_policy": str(graph_policy_path),
            "graph_policy_sha256": _sha256(graph_policy_path),
        },
        "aggregate_all_eight_scenarios": {
            "strict_out_of_fold_reference": _aggregate(oof_items),
            "exploratory_baseline_vote_after_forests": _aggregate(baseline_items),
            "exploratory_consensus_before_forest": _aggregate(consensus_items),
        },
        "aggregate_focus_five_scenarios": {
            "exploratory_baseline_vote_after_forests": _aggregate([
                x["exploratory_eight_model"]["baseline_vote_after_forests"]["metrics"] for x in focus
            ]),
            "exploratory_consensus_before_forest": _aggregate([
                x["exploratory_eight_model"]["consensus_before_forest"]["metrics"] for x in focus
            ]),
        },
        "scenarios": reports,
    }
    return result, changed_edges


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=Path("data/processed/ait_pairs_v3"))
    parser.add_argument("--ensemble", type=Path, default=Path("output/final-ensemble.joblib"))
    parser.add_argument("--graph-policy", type=Path, default=Path("output/manual-core-ml-bridges.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"Le dossier existe déjà: {args.output_dir}")
    report, changed_edges = run_experiment(
        args.cache_root, args.ensemble, args.graph_policy
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    table = pa.Table.from_pylist(changed_edges) if changed_edges else pa.table({"scenario": []})
    pq.write_table(table, args.output_dir / "changed_edges_focus.parquet", compression="zstd")
    print(json.dumps({"output": str(args.output_dir), "changed_edges_focus": len(changed_edges)}, indent=2))


if __name__ == "__main__":
    main()
