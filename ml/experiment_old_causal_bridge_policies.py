#!/usr/bin/env python3
"""Compare hors ligne trois politiques pour les ponts causaux anciens.

Ce script ne réentraîne aucun modèle et n'écrit que dans un nouveau dossier.
Les scénarios AIT sont considérés comme données de développement consultées.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

import igraph as ig
import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.metrics import matthews_corrcoef, precision_recall_fscore_support

from evaluate_cascade_graphs import graph_report
from evaluate_nested_baselines import load_scores
from graph_reconstruction import DisjointSet, bridge_prediction
from optimize_graph_thresholds import (
    component_membership,
    fast_graph_validation_metrics,
    load_meta,
    prepare_fast_graph_truth,
)


GENERIC_SIGNATURES = frozenset({"A-All-Evt"})
K_VALUES = (2, 5, 10, 20, 30, 50)
K_LOW_VALUES = (2, 5, 10)
K_HIGH_VALUES = (20, 30, 50)
STRONG_POOLED_MIN = 0.95
STRONG_WORST_MIN = 0.90


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _rarity(values, vocabulary, idf, unseen) -> np.ndarray:
    return np.asarray(
        [idf[vocabulary[x]] if x in vocabulary else unseen for x in values],
        dtype=np.float32,
    )


def _configurations() -> dict[str, dict]:
    result = {
        "baseline": {"policy": "baseline"},
        "policy1": {"policy": "policy1"},
    }
    for k in K_VALUES:
        result[f"policy2:k={k}"] = {"policy": "policy2", "k": k}
    for low in K_LOW_VALUES:
        for high in K_HIGH_VALUES:
            if high > low:
                result[f"policy3:k_low={low},k_high={high}"] = {
                    "policy": "policy3",
                    "k_low": low,
                    "k_high": high,
                }
    return result


def eligibility_masks(frame: pd.DataFrame, meta: pd.DataFrame) -> dict[str, np.ndarray]:
    signatures = dict(zip(meta["meta_id"], meta["signature"]))
    left_generic = frame["earlier_meta_id"].map(signatures).isin(GENERIC_SIGNATURES)
    right_generic = frame["later_meta_id"].map(signatures).isin(GENERIC_SIGNATURES)
    generic = (left_generic | right_generic).to_numpy(dtype=bool)
    old = (
        frame["causal_bridge_evidence"].to_numpy(dtype=bool)
        & ~frame["local_window_evidence"].to_numpy(dtype=bool)
    )
    degree = np.expm1(
        frame["earlier_log1p_prior_candidate_degree"].to_numpy(dtype=float)
    )
    technical = (
        frame["protocol_overlap"].to_numpy(dtype=bool)
        | frame["service_overlap"].to_numpy(dtype=bool)
        | (frame["forward_network_handoff_count"].to_numpy(dtype=float) > 0)
        | (frame["reverse_network_handoff_count"].to_numpy(dtype=float) > 0)
    )
    masks = {}
    for name, config in _configurations().items():
        policy = config["policy"]
        if policy == "baseline":
            accepted_old = np.ones(len(frame), dtype=bool)
        elif policy == "policy1":
            accepted_old = ~generic
        elif policy == "policy2":
            accepted_old = technical | (degree >= config["k"])
        else:
            accepted_old = (
                technical
                | (~generic & (degree >= config["k_low"]))
                | (generic & (degree >= config["k_high"]))
            )
        masks[name] = ~old | accepted_old
    return masks


def _audit_prior_degree(frame: pd.DataFrame, meta: pd.DataFrame) -> dict:
    """Vérifie que le degré utilisé dépend seulement des prédécesseurs temporels."""

    predecessor_count = frame.groupby("later_meta_id", sort=False)[
        "earlier_meta_id"
    ].nunique()
    expected = np.log1p(
        frame["earlier_meta_id"].map(predecessor_count).fillna(0).to_numpy(dtype=np.float64)
    )
    stored = frame["earlier_log1p_prior_candidate_degree"].to_numpy(dtype=np.float64)
    timestamp = dict(zip(meta["meta_id"].astype(str), meta["first_timestamp"]))
    earlier_time = frame["earlier_meta_id"].astype(str).map(timestamp).to_numpy(dtype=float)
    later_time = frame["later_meta_id"].astype(str).map(timestamp).to_numpy(dtype=float)
    temporal_violations = int((earlier_time > later_time).sum())
    return {
        "exact_match_with_pair_id_predecessor_count": bool(
            np.allclose(expected, stored, rtol=0.0, atol=1e-6)
        ),
        "maximum_absolute_difference": float(np.max(np.abs(expected - stored))),
        "future_predecessor_violations": int(temporal_violations),
        "inputs_used": ["earlier_meta_id", "later_meta_id", "first_timestamp"],
        "ground_truth_used": False,
    }


def _masked_bridge_prediction(
    meta: pd.DataFrame,
    pairs: pd.DataFrame,
    probability: np.ndarray,
    scores: dict[str, np.ndarray],
    pair_threshold: float,
    bridge_threshold: float,
    eligibility: np.ndarray,
    manual_alpha: float,
    manual_threshold: float,
) -> np.ndarray:
    """Même règle scientifique, avec un masque avant le cœur et les ponts."""

    manual = manual_alpha * scores["similarity"] + (1.0 - manual_alpha) * scores["causality"]
    core = (
        (probability >= pair_threshold)
        & (manual >= manual_threshold)
        & eligibility
    )
    allowed = ~scores["stage_known"] | scores["same_stage"] | scores["compatible"]
    candidates = np.flatnonzero(
        ~core & allowed & (probability >= bridge_threshold) & eligibility
    )
    candidates = candidates[np.argsort(-probability[candidates], kind="stable")]

    vertex = {value: index for index, value in enumerate(meta["meta_id"])}
    left = pairs["earlier_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    right = pairs["later_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    core_indices = np.flatnonzero(core)
    if len(core_indices):
        graph = ig.Graph(
            n=len(meta),
            edges=np.column_stack((left[core_indices], right[core_indices])),
            directed=False,
        )
        membership = np.asarray(graph.connected_components().membership, dtype=np.int32)
    else:
        membership = np.arange(len(meta), dtype=np.int32)
    prediction = core.copy()
    # Après contraction du cœur, la boucle DSU scientifique est exactement une
    # forêt couvrante minimale sur le rang stable des probabilités. igraph
    # exécute cette étape en C; les rangs uniques préservent l'ordre scientifique.
    candidate_left = membership[left[candidates]]
    candidate_right = membership[right[candidates]]
    useful = candidate_left != candidate_right
    useful_candidates = candidates[useful]
    if len(useful_candidates):
        contracted_edges = np.column_stack(
            (candidate_left[useful], candidate_right[useful])
        )
        contracted = ig.Graph(
            n=int(membership.max()) + 1,
            edges=contracted_edges,
            directed=False,
        )
        # Le rang dans `candidates` est unique, même si deux probabilités sont égales.
        ranks = np.flatnonzero(useful).astype(float)
        selected = contracted.spanning_tree(weights=ranks, return_tree=False)
        prediction[useful_candidates[np.asarray(selected, dtype=np.int64)]] = True
    return prediction


def _verify_kernel() -> None:
    meta = pd.DataFrame({"meta_id": ["a", "b", "c", "d"]})
    pairs = pd.DataFrame(
        {
            "earlier_meta_id": ["a", "b", "a", "c"],
            "later_meta_id": ["b", "c", "c", "d"],
        }
    )
    probability = np.asarray([0.9, 0.8, 0.7, 0.6])
    scores = {
        "similarity": np.ones(4),
        "causality": np.ones(4),
        "stage_known": np.zeros(4, dtype=bool),
        "same_stage": np.zeros(4, dtype=bool),
        "compatible": np.zeros(4, dtype=bool),
    }
    expected = bridge_prediction(meta, pairs, probability, scores, 0.85, 0.50)
    actual = _masked_bridge_prediction(
        meta, pairs, probability, scores, 0.85, 0.50,
        np.ones(4, dtype=bool), 0.25, 0.50,
    )
    if not np.array_equal(expected, actual):
        raise AssertionError("Le noyau expérimental ne reproduit pas la stratégie scientifique")
    # Vérifie également les masques et les égalités de probabilité, qui rendent
    # indispensable l'ordre stable des candidats.
    rng = np.random.default_rng(42)
    for _ in range(20):
        size = 8
        all_pairs = [(a, b) for a in range(size) for b in range(a + 1, size)]
        rng.shuffle(all_pairs)
        all_pairs = all_pairs[:18]
        test_pairs = pd.DataFrame(
            {
                "earlier_meta_id": [f"m{a}" for a, _ in all_pairs],
                "later_meta_id": [f"m{b}" for _, b in all_pairs],
            }
        )
        test_meta = pd.DataFrame({"meta_id": [f"m{x}" for x in range(size)]})
        test_probability = rng.choice([0.4, 0.6, 0.8, 0.9], len(test_pairs))
        test_scores = {
            "similarity": rng.random(len(test_pairs)),
            "causality": rng.random(len(test_pairs)),
            "stage_known": rng.random(len(test_pairs)) > 0.5,
            "same_stage": rng.random(len(test_pairs)) > 0.5,
            "compatible": rng.random(len(test_pairs)) > 0.5,
        }
        eligible = rng.random(len(test_pairs)) > 0.25
        manual = 0.25 * test_scores["similarity"] + 0.75 * test_scores["causality"]
        core = (test_probability >= 0.75) & (manual >= 0.50) & eligible
        allowed = (
            ~test_scores["stage_known"]
            | test_scores["same_stage"]
            | test_scores["compatible"]
        )
        ordered = np.flatnonzero(
            ~core & allowed & (test_probability >= 0.50) & eligible
        )
        ordered = ordered[np.argsort(-test_probability[ordered], kind="stable")]
        dsu = DisjointSet(size)
        for index in np.flatnonzero(core):
            dsu.union(*all_pairs[index])
        reference = core.copy()
        for index in ordered:
            if dsu.union(*all_pairs[index]):
                reference[index] = True
        actual = _masked_bridge_prediction(
            test_meta, test_pairs, test_probability, test_scores,
            0.75, 0.50, eligible, 0.25, 0.50,
        )
        if not np.array_equal(reference, actual):
            raise AssertionError("La forêt igraph diverge de la boucle DSU scientifique")


def _relation_report(frame: pd.DataFrame, prediction: np.ndarray) -> dict:
    y = frame["target"].to_numpy(dtype=np.int8)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, prediction.astype(np.int8), average="binary", zero_division=0
    )
    confidence = frame["label_confidence"].astype(str).to_numpy()
    high_positive = (confidence == "high") & (y == 1)
    weak_positive = (confidence == "weak") & (y == 1)
    weak_negative = (confidence == "weak") & (y == 0)
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "mcc": float(matthews_corrcoef(y, prediction)),
        "selected_edges": int(prediction.sum()),
        "selected_high_positive": int((prediction & high_positive).sum()),
        "available_high_positive": int(high_positive.sum()),
        "selected_weak_positive": int((prediction & weak_positive).sum()),
        "available_weak_positive": int(weak_positive.sum()),
        "selected_weak_negative": int((prediction & weak_negative).sum()),
        "available_weak_negative": int(weak_negative.sum()),
    }


def _scenario_metrics(
    meta: pd.DataFrame,
    frame: pd.DataFrame,
    prediction: np.ndarray,
    prepared: dict,
) -> dict:
    pair_ids = frame[["earlier_meta_id", "later_meta_id", "target"]]
    membership, edges, _ = component_membership(
        meta, pair_ids, prediction.astype(np.float32), 0.5
    )
    fast = fast_graph_validation_metrics(
        prepared, membership, edges["target"].to_numpy(dtype=np.int8)
    )
    graph = graph_report(meta, pair_ids, prediction)
    return {
        "relation": _relation_report(frame, prediction),
        "graph": graph,
        "fused_attack_clusters": int(fast["fused_attack_clusters"]),
    }


def _aggregate(items: list[dict]) -> dict:
    relation = [x["relation"] for x in items]
    graph = [x["graph"] for x in items]
    selected = sum(x["selected_edges"] for x in relation)
    high_selected = sum(x["selected_high_positive"] for x in relation)
    high_available = sum(x["available_high_positive"] for x in relation)
    weak_positive_selected = sum(x["selected_weak_positive"] for x in relation)
    weak_positive_available = sum(x["available_weak_positive"] for x in relation)
    weak_negative_selected = sum(x["selected_weak_negative"] for x in relation)
    return {
        "scenarios": len(items),
        "selected_edges": selected,
        "incorrect_edges": sum(x["incorrect_edges"] for x in graph),
        "fused_scenarios": sum(x["fused_attack_clusters"] > 0 for x in items),
        "fused_attack_clusters": sum(x["fused_attack_clusters"] for x in items),
        "bcubed_meta_all_macro": float(np.mean([x["bcubed_meta_all"] for x in graph])),
        "bcubed_meta_attacks_macro": float(np.mean([x["bcubed_meta_attacks"] for x in graph])),
        "ari_meta_all_macro": float(np.mean([x["ari_meta_all"] for x in graph])),
        "ari_meta_attacks_macro": float(np.mean([x["ari_meta_attacks"] for x in graph])),
        "attack_fragments_macro": float(np.mean([x["attack_fragments"] for x in graph])),
        "largest_attack_fragment_macro": float(np.mean([x["largest_attack_fragment"] for x in graph])),
        "phase_type_coverage_macro": float(np.mean([x["phase_type_coverage"] for x in graph])),
        "phase_alert_recall_macro": float(np.mean([x["phase_alert_recall"] for x in graph])),
        "high_positive_selected": high_selected,
        "high_positive_available": high_available,
        "high_positive_candidate_recall": high_selected / high_available if high_available else None,
        "weak_positive_selected": weak_positive_selected,
        "weak_positive_available": weak_positive_available,
        "weak_positive_candidate_recall": (
            weak_positive_selected / weak_positive_available
            if weak_positive_available else None
        ),
        "weak_negative_selected": weak_negative_selected,
    }


def _selection_key(
    aggregate: dict,
    pooled_retention: float,
    worst_retention: float,
    config_name: str,
) -> tuple:
    constraint = pooled_retention >= STRONG_POOLED_MIN and worst_retention >= STRONG_WORST_MIN
    return (
        int(constraint),
        -aggregate["fused_scenarios"],
        -aggregate["fused_attack_clusters"],
        aggregate["bcubed_meta_attacks_macro"],
        aggregate["phase_alert_recall_macro"],
        aggregate["ari_meta_attacks_macro"],
        -aggregate["attack_fragments_macro"],
        pooled_retention,
        config_name,
    )


def _select_for_holdout(
    results: dict[str, dict[str, dict]],
    scenarios: list[str],
    held_out: str,
    policy: str,
) -> dict:
    development = [x for x in scenarios if x != held_out]
    names = [
        name for name, config in _configurations().items()
        if config["policy"] == policy
    ]
    baseline_items = [results[x]["baseline"] for x in development]
    baseline_selected = {
        x: results[x]["baseline"]["relation"]["selected_high_positive"]
        for x in development
    }
    candidates = []
    for name in names:
        items = [results[x][name] for x in development]
        aggregate = _aggregate(items)
        numerator = sum(x["relation"]["selected_high_positive"] for x in items)
        denominator = sum(x["relation"]["selected_high_positive"] for x in baseline_items)
        pooled = numerator / denominator if denominator else 1.0
        per_scenario = []
        for scenario, item in zip(development, items):
            base = baseline_selected[scenario]
            per_scenario.append(
                item["relation"]["selected_high_positive"] / base if base else 1.0
            )
        worst = min(per_scenario) if per_scenario else 1.0
        constraint = pooled >= STRONG_POOLED_MIN and worst >= STRONG_WORST_MIN
        candidates.append(
            {
                "configuration": name,
                "development": aggregate,
                "strong_retention_vs_baseline": pooled,
                "worst_scenario_strong_retention": worst,
                "constraint_satisfied": constraint,
                "key": _selection_key(aggregate, pooled, worst, name),
            }
        )
    selected = max(candidates, key=lambda x: x["key"])
    selected = {k: v for k, v in selected.items() if k != "key"}
    selected["held_out_scenario"] = held_out
    selected["held_out_result"] = results[held_out][selected["configuration"]]
    return selected


def run_experiment(
    cache_root: Path,
    ensemble_path: Path,
    graph_policy_path: Path,
) -> dict:
    _verify_kernel()
    bundle = joblib.load(ensemble_path)
    graph_policy = json.loads(graph_policy_path.read_text(encoding="utf-8"))
    graph_thresholds = {
        x["scenario"]: float(x["selected_bridge_threshold"]["threshold"])
        for x in graph_policy["ait"]["scenarios"]
    }
    manual_alpha = float(graph_policy["manual_alpha"])
    manual_threshold = float(graph_policy["manual_threshold"])
    vocabulary = bundle["signature_vocabulary"]
    scenarios = [str(x["held_out_scenario"]) for x in bundle["folds"]]
    configurations = _configurations()
    results: dict[str, dict[str, dict]] = {}
    diagnostics = {}

    for scenario in scenarios:
        cache = cache_root / scenario
        full_frame = pq.read_table(cache / "pair_examples.parquet").to_pandas()
        frame = full_frame[full_frame["target"].notna()].reset_index(drop=True)
        observable = pq.read_table(cache / "meta_observable.parquet").to_pandas()
        meta = load_meta(cache_root, scenario)
        scores = load_scores(cache_root, scenario)
        masks = eligibility_masks(frame, observable)
        mask_groups: dict[bytes, list[str]] = {}
        for name, mask in masks.items():
            key = np.packbits(mask).tobytes()
            mask_groups.setdefault(key, []).append(name)
        signature_by_id = dict(zip(observable["meta_id"], observable["signature"]))
        earlier_signatures = frame["earlier_meta_id"].map(signature_by_id).to_numpy()
        later_signatures = frame["later_meta_id"].map(signature_by_id).to_numpy()
        vote_counts = {
            name: np.zeros(len(frame), dtype=np.int8) for name in configurations
        }
        mean_probability = np.zeros(len(frame), dtype=np.float64)
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
            mean_probability += probability / len(bundle["folds"])
            for names in mask_groups.values():
                name = names[0]
                prediction = _masked_bridge_prediction(
                    meta,
                    frame,
                    probability,
                    scores,
                    float(fold["threshold"]),
                    graph_thresholds[str(fold["held_out_scenario"])],
                    masks[name],
                    manual_alpha,
                    manual_threshold,
                )
                for equivalent_name in names:
                    vote_counts[equivalent_name] += prediction.astype(np.int8)

        prepared = prepare_fast_graph_truth(meta)
        scenario_results = {}
        for name in configurations:
            prediction = vote_counts[name] >= 4
            scenario_results[name] = _scenario_metrics(meta, frame, prediction, prepared)
        results[scenario] = scenario_results

        old = (
            frame["causal_bridge_evidence"].to_numpy(dtype=bool)
            & ~frame["local_window_evidence"].to_numpy(dtype=bool)
        )
        degree = np.expm1(
            frame.loc[old, "earlier_log1p_prior_candidate_degree"].to_numpy(dtype=float)
        )
        diagnostics[scenario] = {
            "pair_count": len(frame),
            "old_causal_candidates": int(old.sum()),
            "degree_quantiles": {
                str(q): float(np.quantile(degree, q)) if len(degree) else None
                for q in (0.5, 0.75, 0.9, 0.95, 0.99)
            },
            "degree_at_cap_50": int((degree >= 49.5).sum()),
            "distinct_eligibility_masks": len(mask_groups),
            "mean_ml_probability_old": float(mean_probability[old].mean()) if old.any() else None,
            "prior_degree_audit": _audit_prior_degree(full_frame, observable),
        }
        print(json.dumps({"completed_scenario": scenario}), flush=True)

    selections = {policy: [] for policy in ("baseline", "policy1", "policy2", "policy3")}
    for held_out in scenarios:
        for policy in selections:
            selections[policy].append(
                _select_for_holdout(results, scenarios, held_out, policy)
            )

    comparison = {}
    stability = {}
    counterexamples = {}
    for policy, folds in selections.items():
        held_out_items = [x["held_out_result"] for x in folds]
        comparison[policy] = _aggregate(held_out_items)
        chosen = Counter(x["configuration"] for x in folds)
        stability[policy] = dict(sorted(chosen.items()))
        examples = []
        for fold in folds:
            scenario = fold["held_out_scenario"]
            current = fold["held_out_result"]
            baseline = results[scenario]["baseline"]
            examples.append(
                {
                    "scenario": scenario,
                    "configuration": fold["configuration"],
                    "constraint_satisfied_on_development": fold["constraint_satisfied"],
                    "delta_high_positive_selected": (
                        current["relation"]["selected_high_positive"]
                        - baseline["relation"]["selected_high_positive"]
                    ),
                    "delta_fused_attack_clusters": (
                        current["fused_attack_clusters"] - baseline["fused_attack_clusters"]
                    ),
                    "delta_bcubed_meta_attacks": (
                        current["graph"]["bcubed_meta_attacks"]
                        - baseline["graph"]["bcubed_meta_attacks"]
                    ),
                    "delta_attack_fragments": (
                        current["graph"]["attack_fragments"]
                        - baseline["graph"]["attack_fragments"]
                    ),
                    "delta_phase_alert_recall": (
                        current["graph"]["phase_alert_recall"]
                        - baseline["graph"]["phase_alert_recall"]
                    ),
                }
            )
        counterexamples[policy] = examples

    return {
        "kind": "offline-old-causal-bridge-policy-development-experiment",
        "scientific_status": "development only; scenarios were previously inspected",
        "no_retraining": True,
        "external_datasets_used_for_selection": [],
        "generic_signatures": sorted(GENERIC_SIGNATURES),
        "old_bridge_definition": "causal_bridge_evidence=1 and local_window_evidence=0",
        "eligibility_application": "before both manual core and ML bridge candidates in every fold",
        "ensemble_rule": "at least 4 of 8 frozen graph decisions; no post-vote cycle rule",
        "selection_rule": {
            "development_scenarios": 7,
            "reserved_scenarios": 1,
            "strong_pooled_min": STRONG_POOLED_MIN,
            "strong_worst_scenario_min": STRONG_WORST_MIN,
            "priority": [
                "satisfy strong-positive retention constraints",
                "minimize fused scenarios",
                "minimize fused attack clusters",
                "maximize attack B-cubed",
                "maximize phase alert recall",
                "maximize attack ARI",
                "minimize fragmentation",
            ],
        },
        "inputs": {
            "cache_root": str(cache_root),
            "ensemble": str(ensemble_path),
            "ensemble_sha256": _sha256(ensemble_path),
            "graph_policy": str(graph_policy_path),
            "graph_policy_sha256": _sha256(graph_policy_path),
        },
        "configurations": configurations,
        "comparison_leave_one_scenario_out": comparison,
        "parameter_stability": stability,
        "selections": selections,
        "scenario_results_all_configurations": results,
        "degree_diagnostics": diagnostics,
        "counterexamples_vs_baseline": counterexamples,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=Path("data/processed/ait_pairs_v3"))
    parser.add_argument("--ensemble", type=Path, default=Path("output/final-ensemble.joblib"))
    parser.add_argument("--graph-policy", type=Path, default=Path("output/manual-core-ml-bridges.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"Le dossier existe déjà: {args.output_dir}")
    report = run_experiment(args.cache_root, args.ensemble, args.graph_policy)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "output": str(args.output_dir / "report.json"),
        "comparison": report["comparison_leave_one_scenario_out"],
        "stability": report["parameter_stability"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
