#!/usr/bin/env python3
"""Expérience hors ligne : consensus puis unions validées par multi-preuves.

La baseline, les modèles et leurs seuils restent figés. Les résultats AIT à
huit modèles sont exploratoires : sept modèles peuvent avoir vu le scénario.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import tracemalloc
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.metrics import adjusted_rand_score

from evaluate_nested_baselines import load_scores
from experiment_consensus_before_forest import (
    QUORUM,
    _fusion_diagnostics,
    _truth_breakdown,
    consensus_before_forest,
    fold_relation_masks,
)
from experiment_old_causal_bridge_policies import _aggregate, _rarity, _scenario_metrics
from graph_reconstruction import DisjointSet, bridge_prediction
from optimize_graph_thresholds import load_meta, prepare_fast_graph_truth


GENERIC_SIGNATURES = frozenset({"A-All-Evt"})
FOCUS_SCENARIOS = frozenset({"harrison", "santos", "wilson", "fox", "wheeler"})
IPV4_ENTITY = re.compile(r"^ip:(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_entity(value: str) -> str:
    """Normalise seulement les ports IPv4; ne tente aucune résolution externe."""

    text = str(value)
    match = IPV4_ENTITY.match(text)
    return f"ip:{match.group(1)}" if match else text


def _edge_order(
    selected: np.ndarray,
    core_votes: np.ndarray,
    admissible_votes: np.ndarray,
    mean_probability: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    indices = np.flatnonzero(selected)
    order = np.lexsort(
        (
            indices,
            -mean_probability[indices],
            -admissible_votes[indices],
            -(core_votes[indices] >= QUORUM).astype(np.int8),
        )
    )
    ordered = indices[order]
    rank = np.full(len(selected), np.iinfo(np.int32).max, dtype=np.int32)
    rank[ordered] = np.arange(len(ordered), dtype=np.int32)
    return ordered, rank


def safe_seed_mask(
    frame: pd.DataFrame,
    meta: pd.DataFrame,
    consensus_prediction: np.ndarray,
    admissible_votes: np.ndarray,
) -> np.ndarray:
    """Exception de bootstrap locale combinant trois familles observables."""

    signatures = dict(zip(meta["meta_id"], meta["signature"].astype(str)))
    left_signature = frame["earlier_meta_id"].map(signatures).astype(str)
    right_signature = frame["later_meta_id"].map(signatures).astype(str)
    non_generic = ~left_signature.isin(GENERIC_SIGNATURES) & ~right_signature.isin(GENERIC_SIGNATURES)
    behavior = non_generic.to_numpy(dtype=bool) & (
        frame["same_signature"].to_numpy(dtype=bool)
        | (
            frame["stage_known_both"].to_numpy(dtype=bool)
            & (
                frame["same_stage"].to_numpy(dtype=bool)
                | frame["forward_progression_compatible"].to_numpy(dtype=bool)
            )
        )
    )
    return (
        consensus_prediction
        & (admissible_votes >= QUORUM)
        & frame["local_window_evidence"].to_numpy(dtype=bool)
        & (frame["shared_entity_count"].to_numpy(dtype=np.int64) > 0)
        & ~frame["non_malicious_stage_present"].to_numpy(dtype=bool)
        & behavior
    )


def _meta_evidence(meta: pd.DataFrame) -> tuple[list[frozenset[str]], np.ndarray, np.ndarray]:
    entities = [frozenset(normalize_entity(x) for x in values) for values in meta["entities"]]
    signatures = meta["signature"].astype(str).to_numpy()
    meta_ids = meta["meta_id"].astype(str).to_numpy()
    return entities, signatures, meta_ids


def _edge_tokens(
    index: int,
    left: np.ndarray,
    right: np.ndarray,
    entities: list[frozenset[str]],
    signatures: np.ndarray,
    meta_ids: np.ndarray,
) -> tuple[str, ...]:
    a, b = int(left[index]), int(right[index])
    tokens = [f"pivot:{meta_ids[a]}", f"pivot:{meta_ids[b]}"]
    tokens.extend(f"entity:{x}" for x in sorted(entities[a] & entities[b]))
    for signature in (signatures[a], signatures[b]):
        if signature not in GENERIC_SIGNATURES:
            tokens.append(f"signature:{signature}")
    return tuple(tokens)


def independent_packages(
    indices: np.ndarray,
    consumed: np.ndarray,
    rank: np.ndarray,
    left: np.ndarray,
    right: np.ndarray,
    entities: list[frozenset[str]],
    signatures: np.ndarray,
    meta_ids: np.ndarray,
) -> list[np.ndarray]:
    """Paquets corrélés par pivot, entité ou signature non générique."""

    active = np.asarray([int(x) for x in indices if not consumed[int(x)]], dtype=np.int64)
    if not len(active):
        return []
    parent = np.arange(len(active), dtype=np.int32)

    def find(item: int) -> int:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = int(parent[item])
        return item

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    first_for_token: dict[str, int] = {}
    for position, edge_index in enumerate(active):
        for token in _edge_tokens(
            int(edge_index), left, right, entities, signatures, meta_ids
        ):
            previous = first_for_token.setdefault(token, position)
            if previous != position:
                union(position, previous)
    groups: dict[int, list[int]] = {}
    for position, edge_index in enumerate(active):
        groups.setdefault(find(position), []).append(int(edge_index))
    packages = [np.asarray(values, dtype=np.int64) for values in groups.values()]
    packages.sort(key=lambda values: int(rank[values].min()))
    return packages


def _component_roots(dsu: DisjointSet, size: int) -> np.ndarray:
    return np.fromiter((dsu.find(x) for x in range(size)), dtype=np.int32, count=size)


def _pair_keys(root_left: np.ndarray, root_right: np.ndarray, size: int) -> np.ndarray:
    low = np.minimum(root_left, root_right).astype(np.int64)
    high = np.maximum(root_left, root_right).astype(np.int64)
    return low * np.int64(size + 1) + high


def _relation_counts(frame: pd.DataFrame, mask: np.ndarray) -> dict:
    return _truth_breakdown(frame, mask)


def multi_proof_reconstruction(
    meta: pd.DataFrame,
    frame: pd.DataFrame,
    consensus_prediction: np.ndarray,
    core_votes: np.ndarray,
    admissible_votes: np.ndarray,
    mean_probability: np.ndarray,
    application_order: str = "primary",
) -> dict:
    """Construit les composantes dures et conserve les refus en liens souples."""

    if application_order not in {"primary", "reverse"}:
        raise ValueError("Ordre d'application inconnu")
    started_wall = time.perf_counter()
    started_cpu = time.process_time()
    tracemalloc.start()

    vertex = pd.Series(np.arange(len(meta), dtype=np.int32), index=meta["meta_id"])
    left = frame["earlier_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    right = frame["later_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    entities, signatures, meta_ids = _meta_evidence(meta)
    ordered, rank = _edge_order(
        consensus_prediction, core_votes, admissible_votes, mean_probability
    )
    seeds = safe_seed_mask(frame, meta, consensus_prediction, admissible_votes)
    dsu = DisjointSet(len(meta))
    union_edges = np.zeros(len(frame), dtype=bool)
    consumed = np.zeros(len(frame), dtype=bool)
    logs: list[dict] = []
    successful_seed_unions = 0
    for index in ordered[seeds[ordered]]:
        if dsu.union(int(left[index]), int(right[index])):
            union_edges[index] = True
            successful_seed_unions += 1
            logs.append(
                {
                    "pair_index": int(index),
                    "decision": "accepted_seed_union",
                    "reason": "local+shared_identity+non_generic_behavior+no_non_malicious_stage",
                    "round": 0,
                    "proof_packet_count": 1,
                    "witness_pair_indices": [int(index)],
                }
            )

    evidence_mask = admissible_votes >= QUORUM
    rounds = 0
    examined_boundary_groups = 0
    examined_evidence_edges = 0
    accepted_multi_unions = 0
    final_package_counts: dict[int, int] = {}
    while True:
        roots = _component_roots(dsu, len(meta))
        root_left, root_right = roots[left], roots[right]
        boundary = root_left != root_right
        pending = np.flatnonzero(consensus_prediction & boundary)
        if not len(pending):
            break
        evidence = np.flatnonzero(evidence_mask & boundary & ~consumed)
        pending_keys = _pair_keys(root_left[pending], root_right[pending], len(meta))
        evidence_keys = _pair_keys(root_left[evidence], root_right[evidence], len(meta))
        pending_order = np.argsort(pending_keys, kind="stable")
        evidence_order = np.argsort(evidence_keys, kind="stable")
        pending_sorted, pending_keys_sorted = pending[pending_order], pending_keys[pending_order]
        evidence_sorted, evidence_keys_sorted = evidence[evidence_order], evidence_keys[evidence_order]
        unique_pending, pending_starts = np.unique(pending_keys_sorted, return_index=True)
        pending_ends = np.r_[pending_starts[1:], len(pending_sorted)]
        accepted = []
        final_package_counts = {}
        for key, p_start, p_end in zip(unique_pending, pending_starts, pending_ends):
            e_start = int(np.searchsorted(evidence_keys_sorted, key, side="left"))
            e_end = int(np.searchsorted(evidence_keys_sorted, key, side="right"))
            boundary_evidence = evidence_sorted[e_start:e_end]
            examined_boundary_groups += 1
            examined_evidence_edges += len(boundary_evidence)
            packages = independent_packages(
                boundary_evidence, consumed, rank, left, right,
                entities, signatures, meta_ids,
            )
            final_package_counts[int(key)] = len(packages)
            if len(packages) < 2:
                continue
            carriers = pending_sorted[p_start:p_end]
            carrier = int(carriers[np.argmin(rank[carriers])])
            accepted.append((carrier, packages[0], packages[1], int(key), len(packages)))
        if not accepted:
            break
        accepted.sort(key=lambda item: int(rank[item[0]]), reverse=application_order == "reverse")
        successful = 0
        rounds += 1
        for carrier, first_package, second_package, key, package_count in accepted:
            if not dsu.union(int(left[carrier]), int(right[carrier])):
                continue
            union_edges[carrier] = True
            consumed[first_package] = True
            consumed[second_package] = True
            successful += 1
            accepted_multi_unions += 1
            logs.append(
                {
                    "pair_index": carrier,
                    "decision": "accepted_multi_proof_union",
                    "reason": "two_independent_boundary_packages",
                    "round": rounds,
                    "proof_packet_count": package_count,
                    "witness_pair_indices": [
                        int(first_package[np.argmin(rank[first_package])]),
                        int(second_package[np.argmin(rank[second_package])]),
                    ],
                }
            )
        if not successful:
            break

    roots = _component_roots(dsu, len(meta))
    _, membership = np.unique(roots, return_inverse=True)
    same_final_component = membership[left] == membership[right]
    hard_relations = consensus_prediction & same_final_component
    soft_relations = consensus_prediction & ~same_final_component

    # Journal final de chaque union refusée. Le nombre de paquets est recalculé
    # par frontière finale afin de ne pas réutiliser un état obsolète.
    soft_indices = np.flatnonzero(soft_relations)
    if len(soft_indices):
        soft_keys = _pair_keys(roots[left[soft_indices]], roots[right[soft_indices]], len(meta))
        evidence = np.flatnonzero(evidence_mask & (roots[left] != roots[right]) & ~consumed)
        evidence_keys = _pair_keys(roots[left[evidence]], roots[right[evidence]], len(meta))
        evidence_order = np.argsort(evidence_keys, kind="stable")
        evidence_sorted, evidence_keys_sorted = evidence[evidence_order], evidence_keys[evidence_order]
        package_count_by_key = {}
        for key in np.unique(soft_keys):
            start = int(np.searchsorted(evidence_keys_sorted, key, side="left"))
            end = int(np.searchsorted(evidence_keys_sorted, key, side="right"))
            packages = independent_packages(
                evidence_sorted[start:end], consumed, rank, left, right,
                entities, signatures, meta_ids,
            )
            package_count_by_key[int(key)] = len(packages)
        for index, key in zip(soft_indices, soft_keys):
            logs.append(
                {
                    "pair_index": int(index),
                    "decision": "refused_soft_link",
                    "reason": "fewer_than_two_independent_boundary_packages",
                    "round": rounds + 1,
                    "proof_packet_count": int(package_count_by_key[int(key)]),
                    "witness_pair_indices": [],
                }
            )

    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "membership": membership.astype(np.int32),
        "union_edges": union_edges,
        "hard_relations": hard_relations,
        "soft_relations": soft_relations,
        "seed_mask": seeds,
        "logs": logs,
        "performance": {
            "wall_seconds": time.perf_counter() - started_wall,
            "cpu_seconds": time.process_time() - started_cpu,
            "python_peak_tracemalloc_bytes": int(peak_memory),
            "rounds": rounds,
            "successful_seed_unions": successful_seed_unions,
            "accepted_multi_proof_unions": accepted_multi_unions,
            "examined_boundary_groups_with_repetition": examined_boundary_groups,
            "examined_evidence_edges_with_repetition": examined_evidence_edges,
            "complexity_claim": "measured only; no asymptotic O(E log V) claim",
        },
    }


def _annotate_logs(
    scenario: str,
    logs: list[dict],
    frame: pd.DataFrame,
    core_votes: np.ndarray,
    admissible_votes: np.ndarray,
    mean_probability: np.ndarray,
) -> list[dict]:
    result = []
    for item in logs:
        index = int(item["pair_index"])
        row = frame.iloc[index]
        result.append(
            {
                "scenario": scenario,
                **item,
                "earlier_meta_id": str(row["earlier_meta_id"]),
                "later_meta_id": str(row["later_meta_id"]),
                "target_evaluation_only": int(row["target"]),
                "label_confidence_evaluation_only": str(row["label_confidence"]),
                "candidate_source": str(row["candidate_source"]),
                "delta_seconds": float(row["delta_seconds"]),
                "core_votes": int(core_votes[index]),
                "admissible_votes": int(admissible_votes[index]),
                "mean_probability": float(mean_probability[index]),
            }
        )
    return result


def run_experiment(
    cache_root: Path,
    ensemble_path: Path,
    graph_policy_path: Path,
    scenarios_requested: list[str] | None = None,
) -> tuple[dict, list[dict]]:
    bundle = joblib.load(ensemble_path)
    policy = json.loads(graph_policy_path.read_text(encoding="utf-8"))
    graph_thresholds = {
        item["scenario"]: float(item["selected_bridge_threshold"]["threshold"])
        for item in policy["ait"]["scenarios"]
    }
    scenarios = [str(fold["held_out_scenario"]) for fold in bundle["folds"]]
    if scenarios_requested is not None:
        unknown = sorted(set(scenarios_requested) - set(scenarios))
        if unknown:
            raise ValueError(f"Scénarios inconnus: {unknown}")
        scenarios = [scenario for scenario in scenarios if scenario in scenarios_requested]
    vocabulary = bundle["signature_vocabulary"]
    reports = []
    decision_logs = []

    for scenario in scenarios:
        cache = cache_root / scenario
        frame = pq.read_table(cache / "pair_examples.parquet").to_pandas()
        frame = frame[frame["target"].notna()].reset_index(drop=True)
        observable = pq.read_table(cache / "meta_observable.parquet").to_pandas()
        meta = load_meta(cache_root, scenario)
        scores = load_scores(cache_root, scenario)
        signatures = dict(zip(observable["meta_id"], observable["signature"]))
        earlier_signatures = frame["earlier_meta_id"].map(signatures).to_numpy()
        later_signatures = frame["later_meta_id"].map(signatures).to_numpy()
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
            raise AssertionError(f"Référence hors-fold absente pour {scenario}")

        baseline = graph_votes >= QUORUM
        consensus = consensus_before_forest(
            meta, frame, core_votes, admissible_votes, mean_probability, QUORUM
        )
        multi = multi_proof_reconstruction(
            meta, frame, consensus, core_votes, admissible_votes, mean_probability,
            application_order="primary",
        )
        reverse = multi_proof_reconstruction(
            meta, frame, consensus, core_votes, admissible_votes, mean_probability,
            application_order="reverse",
        )
        prepared = prepare_fast_graph_truth(meta)
        oof_metrics = _scenario_metrics(meta, frame, oof_prediction, prepared)
        baseline_metrics = _scenario_metrics(meta, frame, baseline, prepared)
        consensus_metrics = _scenario_metrics(meta, frame, consensus, prepared)
        hard_metrics = _scenario_metrics(meta, frame, multi["hard_relations"], prepared)
        order_ari = float(adjusted_rand_score(multi["membership"], reverse["membership"]))
        same_partition = bool(order_ari == 1.0)
        report = {
            "scenario": scenario,
            "strict_out_of_fold_reference": oof_metrics,
            "exploratory": {
                "baseline_vote_after_forests": baseline_metrics,
                "consensus_before_forest": consensus_metrics,
                "multi_proof_hard_components": {
                    "metrics": hard_metrics,
                    "fusion_diagnostics": _fusion_diagnostics(meta, frame, multi["hard_relations"]),
                    "union_edges": _relation_counts(frame, multi["union_edges"]),
                    "hard_relations": _relation_counts(frame, multi["hard_relations"]),
                    "soft_relations": _relation_counts(frame, multi["soft_relations"]),
                    "soft_link_count": int(multi["soft_relations"].sum()),
                    "soft_link_proportion_of_consensus": float(
                        multi["soft_relations"].sum() / consensus.sum()
                    ) if consensus.sum() else 0.0,
                    "performance": multi["performance"],
                },
                "drop_soft_ablation": {
                    "component_metrics_identical_by_design": True,
                    "retained_relations": _relation_counts(frame, multi["hard_relations"]),
                    "discarded_soft_relations": _relation_counts(frame, multi["soft_relations"]),
                },
                "order_sensitivity": {
                    "primary_vs_reverse_partition_ari": order_ari,
                    "identical_partition": same_partition,
                    "primary_soft_links": int(multi["soft_relations"].sum()),
                    "reverse_soft_links": int(reverse["soft_relations"].sum()),
                    "reverse_performance": reverse["performance"],
                },
            },
        }
        reports.append(report)
        decision_logs.extend(
            _annotate_logs(
                scenario, multi["logs"], frame, core_votes,
                admissible_votes, mean_probability,
            )
        )
        print(json.dumps({
            "completed": scenario,
            "baseline_edges": int(baseline.sum()),
            "consensus_edges": int(consensus.sum()),
            "hard_edges": int(multi["hard_relations"].sum()),
            "soft_edges": int(multi["soft_relations"].sum()),
            "rounds": multi["performance"]["rounds"],
        }), flush=True)

    def metrics(method: str) -> list[dict]:
        if method == "oof":
            return [x["strict_out_of_fold_reference"] for x in reports]
        if method == "baseline":
            return [x["exploratory"]["baseline_vote_after_forests"] for x in reports]
        if method == "consensus":
            return [x["exploratory"]["consensus_before_forest"] for x in reports]
        return [x["exploratory"]["multi_proof_hard_components"]["metrics"] for x in reports]

    result = {
        "kind": "offline-consensus-multi-proof-component-union-experiment",
        "scientific_status": {
            "strict_out_of_fold_reference": "descriptive frozen OOF baseline",
            "eight_model_methods": "exploratory only; seven models may have seen each AIT scenario",
        },
        "no_retraining": True,
        "production_changed": False,
        "external_datasets_used": [],
        "policy": {
            "quorum": QUORUM,
            "safe_seed": "consensus-selected local relation with shared identity, non-generic coherent behavior, and no non-malicious stage",
            "independent_packages": "boundary evidence clustered transitively by shared pivot, normalized entity, or non-generic signature",
            "union_requirement": 2,
            "soft_link": "consensus-selected relation whose final endpoints remain in different hard components",
            "core_and_bridges_both_validated": True,
            "consumed_packages_not_reused": True,
        },
        "inputs": {
            "cache_root": str(cache_root),
            "ensemble": str(ensemble_path),
            "ensemble_sha256": _sha256(ensemble_path),
            "graph_policy": str(graph_policy_path),
            "graph_policy_sha256": _sha256(graph_policy_path),
        },
        "aggregate_all_eight_scenarios": {
            "strict_out_of_fold_reference": _aggregate(metrics("oof")),
            "exploratory_baseline": _aggregate(metrics("baseline")),
            "exploratory_consensus": _aggregate(metrics("consensus")),
            "exploratory_multi_proof": _aggregate(metrics("multi")),
        },
        "scenarios": reports,
    }
    return result, decision_logs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=Path("data/processed/ait_pairs_v3"))
    parser.add_argument("--ensemble", type=Path, default=Path("output/final-ensemble.joblib"))
    parser.add_argument("--graph-policy", type=Path, default=Path("output/manual-core-ml-bridges.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scenarios", nargs="+")
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"Le dossier existe déjà: {args.output_dir}")
    report, logs = run_experiment(
        args.cache_root, args.ensemble, args.graph_policy, args.scenarios
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    table = pa.Table.from_pylist(logs) if logs else pa.table({"scenario": []})
    pq.write_table(table, args.output_dir / "union_decisions.parquet", compression="zstd")
    print(json.dumps({"output": str(args.output_dir), "decision_log_rows": len(logs)}, indent=2))


if __name__ == "__main__":
    main()
