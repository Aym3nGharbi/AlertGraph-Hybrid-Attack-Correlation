#!/usr/bin/env python3
"""Diagnostic hors ligne des fusions et fragmentations de la baseline scientifique.

Le script ne réentraîne rien et ne modifie aucun artefact de production. Il
rejoue les huit décisions graphiques figées, applique le vote scientifique et
écrit des résultats nouveaux dans un dossier qui doit être absent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, deque
from pathlib import Path

import igraph as ig
import joblib
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from evaluate_nested_baselines import load_scores
from experiment_old_causal_bridge_policies import _rarity
from graph_reconstruction import MANUAL_ALPHA, MANUAL_THRESHOLD
from optimize_graph_thresholds import component_membership, load_meta


SCENARIOS = ("harrison", "santos", "wilson", "fox", "wheeler")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fold_decision(
    meta: pd.DataFrame,
    pairs: pd.DataFrame,
    probability: np.ndarray,
    scores: dict[str, np.ndarray],
    pair_threshold: float,
    bridge_threshold: float,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Reproduit un fold et expose cœur, pont retenu et admissibilité ML."""

    manual = MANUAL_ALPHA * scores["similarity"] + (1.0 - MANUAL_ALPHA) * scores["causality"]
    pair_pass = probability >= pair_threshold
    core = pair_pass & (manual >= MANUAL_THRESHOLD)
    allowed = ~scores["stage_known"] | scores["same_stage"] | scores["compatible"]
    bridge_eligible = ~core & allowed & (probability >= bridge_threshold)
    candidates = np.flatnonzero(bridge_eligible)
    candidates = candidates[np.argsort(-probability[candidates], kind="stable")]

    vertex = pd.Series(np.arange(len(meta), dtype=np.int32), index=meta["meta_id"])
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

    bridge = np.zeros(len(pairs), dtype=bool)
    candidate_left = membership[left[candidates]]
    candidate_right = membership[right[candidates]]
    useful = candidate_left != candidate_right
    useful_candidates = candidates[useful]
    if len(useful_candidates):
        contracted = ig.Graph(
            n=int(membership.max()) + 1,
            edges=np.column_stack((candidate_left[useful], candidate_right[useful])),
            directed=False,
        )
        ranks = np.flatnonzero(useful).astype(float)
        selected = contracted.spanning_tree(weights=ranks, return_tree=False)
        bridge[useful_candidates[np.asarray(selected, dtype=np.int64)]] = True
    return core | bridge, core, bridge, bridge_eligible | core


def _component_count(n: int, edges: np.ndarray) -> tuple[int, int]:
    if n == 0:
        return 0, 0
    graph = ig.Graph(n=n, edges=edges, directed=False) if len(edges) else ig.Graph(n=n)
    components = graph.connected_components()
    return len(components), sum(1 for degree in graph.degree() if degree == 0)


def _attack_fragmentation_stages(
    meta: pd.DataFrame,
    pairs: pd.DataFrame,
    left: np.ndarray,
    right: np.ndarray,
    pair_pass_votes: np.ndarray,
    core_votes: np.ndarray,
    bridge_eligible_votes: np.ndarray,
    decision_votes: np.ndarray,
    selected: np.ndarray,
    global_membership: np.ndarray,
) -> list[dict]:
    attack_ids = meta["attack_instance_id"].fillna("").astype(str).to_numpy()
    attack_mask = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    target = pairs["target"].to_numpy(dtype=np.int8)
    confidence = pairs["label_confidence"].astype(str).to_numpy()
    reports = []
    for attack_id in sorted(set(attack_ids[attack_mask])):
        nodes = np.flatnonzero(attack_mask & (attack_ids == attack_id))
        local_index = np.full(len(meta), -1, dtype=np.int32)
        local_index[nodes] = np.arange(len(nodes), dtype=np.int32)
        within = (local_index[left] >= 0) & (local_index[right] >= 0)

        def stage(mask: np.ndarray) -> dict:
            indices = np.flatnonzero(within & mask)
            edges = (
                np.column_stack((local_index[left[indices]], local_index[right[indices]]))
                if len(indices) else np.empty((0, 2), dtype=np.int32)
            )
            components, isolated = _component_count(len(nodes), edges)
            return {"components": components, "isolated_nodes": isolated, "edges": int(len(indices))}

        labels = global_membership[nodes]
        counts = Counter(labels.tolist())
        reports.append(
            {
                "attack_instance_id": attack_id,
                "nodes": int(len(nodes)),
                "candidate_topology": stage(np.ones(len(pairs), dtype=bool)),
                "strong_positive_topology": stage((target == 1) & (confidence == "high")),
                "all_positive_topology": stage(target == 1),
                "ml_pair_pass_vote_topology": stage(pair_pass_votes >= 4),
                "manual_core_vote_topology": stage(core_votes >= 4),
                "bridge_eligible_vote_topology": stage(bridge_eligible_votes >= 4),
                "selected_edges_restricted_topology": stage(selected),
                "decision_vote_quorum_topology": {
                    str(quorum): stage(decision_votes >= quorum)
                    for quorum in range(1, 9)
                },
                "final_global_components": int(len(counts)),
                "largest_final_component_nodes": int(max(counts.values(), default=0)),
                "largest_final_component_fraction": float(max(counts.values(), default=0) / len(nodes)),
            }
        )
    return reports


def _shortest_cross_path(
    graph: ig.Graph,
    membership: np.ndarray,
    component: int,
    attack_ids: np.ndarray,
    left: np.ndarray,
    right: np.ndarray,
    selected_indices: np.ndarray,
    forbid_direct: bool = False,
) -> list[int]:
    vertices = np.flatnonzero(membership == component)
    instances = sorted(set(attack_ids[vertices]) - {""})
    if len(instances) < 2:
        return []
    source_instance, target_instance = instances[:2]
    sources = set(vertices[attack_ids[vertices] == source_instance].tolist())
    targets = set(vertices[attack_ids[vertices] == target_instance].tolist())
    adjacency: dict[int, list[tuple[int, int]]] = {int(v): [] for v in vertices}
    for edge_id, pair_index in enumerate(selected_indices):
        a, b = int(left[pair_index]), int(right[pair_index])
        if membership[a] != component:
            continue
        if forbid_direct and attack_ids[a] and attack_ids[b] and attack_ids[a] != attack_ids[b]:
            continue
        adjacency[a].append((b, int(pair_index)))
        adjacency[b].append((a, int(pair_index)))
    queue = deque(sources)
    parent: dict[int, tuple[int, int] | None] = {x: None for x in sources}
    found = None
    while queue and found is None:
        node = queue.popleft()
        for neighbor, pair_index in adjacency.get(node, []):
            if neighbor in parent:
                continue
            parent[neighbor] = (node, pair_index)
            if neighbor in targets:
                found = neighbor
                break
            queue.append(neighbor)
    if found is None:
        return []
    path = []
    cursor = found
    while parent[cursor] is not None:
        previous, pair_index = parent[cursor]
        path.append(pair_index)
        cursor = previous
    return list(reversed(path))


def _truth_class(meta: pd.DataFrame) -> np.ndarray:
    attack = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    instance = meta["attack_instance_id"].fillna("").astype(str).to_numpy()
    confidence = meta["truth_confidence"].fillna("unknown").astype(str).to_numpy()
    return np.where(attack, instance, np.char.add("nonattack:", confidence))


def _edge_records(
    scenario: str,
    indices: np.ndarray,
    pairs: pd.DataFrame,
    meta: pd.DataFrame,
    left: np.ndarray,
    right: np.ndarray,
    probabilities: np.ndarray,
    decision_votes: np.ndarray,
    core_votes: np.ndarray,
    bridge_votes: np.ndarray,
    pair_pass_votes: np.ndarray,
    bridge_eligible_votes: np.ndarray,
    scores: dict[str, np.ndarray],
    is_graph_bridge: np.ndarray,
    reason: str,
) -> list[dict]:
    signatures = meta["signature"].astype(str).to_numpy()
    entities = meta["entities"].to_list()
    classes = _truth_class(meta)
    result = []
    for index in indices:
        index = int(index)
        a, b = int(left[index]), int(right[index])
        result.append(
            {
                "scenario": scenario,
                "pair_index": index,
                "reason": reason,
                "earlier_meta_id": str(pairs.iloc[index]["earlier_meta_id"]),
                "later_meta_id": str(pairs.iloc[index]["later_meta_id"]),
                "earlier_truth_class": str(classes[a]),
                "later_truth_class": str(classes[b]),
                "target": int(pairs.iloc[index]["target"]),
                "label_confidence": str(pairs.iloc[index]["label_confidence"]),
                "label_reason": str(pairs.iloc[index]["label_reason"]),
                "candidate_source": str(pairs.iloc[index]["candidate_source"]),
                "delta_seconds": float(pairs.iloc[index]["delta_seconds"]),
                "earlier_signature": signatures[a],
                "later_signature": signatures[b],
                "earlier_entities": [str(x) for x in entities[a]],
                "later_entities": [str(x) for x in entities[b]],
                "shared_entity_count": int(pairs.iloc[index]["shared_entity_count"]),
                "manual_similarity": float(scores["similarity"][index]),
                "manual_causality": float(scores["causality"][index]),
                "manual_score": float(MANUAL_ALPHA * scores["similarity"][index] + (1-MANUAL_ALPHA) * scores["causality"][index]),
                "stage_known": bool(scores["stage_known"][index]),
                "same_stage": bool(scores["same_stage"][index]),
                "compatible": bool(scores["compatible"][index]),
                "decision_votes": int(decision_votes[index]),
                "core_votes": int(core_votes[index]),
                "bridge_votes": int(bridge_votes[index]),
                "pair_pass_votes": int(pair_pass_votes[index]),
                "bridge_eligible_votes": int(bridge_eligible_votes[index]),
                "probability_min": float(probabilities[:, index].min()),
                "probability_mean": float(probabilities[:, index].mean()),
                "probability_max": float(probabilities[:, index].max()),
                "probabilities_by_fold": [float(x) for x in probabilities[:, index]],
                "is_undirected_graph_bridge": bool(is_graph_bridge[index]),
            }
        )
    return result


def _positive_stage_counts(
    pairs: pd.DataFrame,
    pair_pass_votes: np.ndarray,
    core_votes: np.ndarray,
    bridge_eligible_votes: np.ndarray,
    selected: np.ndarray,
    manual_score: np.ndarray,
) -> dict:
    target = pairs["target"].to_numpy(dtype=np.int8)
    confidence = pairs["label_confidence"].astype(str).to_numpy()
    result = {}
    for name, mask in {
        "strong_positive": (target == 1) & (confidence == "high"),
        "weak_positive": (target == 1) & (confidence != "high"),
    }.items():
        result[name] = {
            "available": int(mask.sum()),
            "ml_pair_pass_vote_ge_4": int((mask & (pair_pass_votes >= 4)).sum()),
            "manual_score_ge_0_5": int((mask & (manual_score >= MANUAL_THRESHOLD)).sum()),
            "manual_core_vote_ge_4": int((mask & (core_votes >= 4)).sum()),
            "bridge_eligible_vote_ge_4": int((mask & (bridge_eligible_votes >= 4)).sum()),
            "selected_vote_ge_4": int((mask & selected).sum()),
            "not_selected_ml_and_bridge_support_lt_4": int((mask & ~selected & (pair_pass_votes < 4) & (bridge_eligible_votes < 4)).sum()),
            "not_selected_manual_gate": int((mask & ~selected & (pair_pass_votes >= 4) & (manual_score < MANUAL_THRESHOLD)).sum()),
            "not_selected_after_bridge_eligibility": int((mask & ~selected & (bridge_eligible_votes >= 4)).sum()),
        }
    return result


def diagnose_scenario(
    scenario: str,
    cache_root: Path,
    bundle: dict,
    graph_thresholds: dict[str, float],
) -> tuple[dict, list[dict]]:
    cache = cache_root / scenario
    all_pairs = pq.read_table(cache / "pair_examples.parquet").to_pandas()
    pairs = all_pairs[all_pairs["target"].notna()].reset_index(drop=True)
    observable = pq.read_table(cache / "meta_observable.parquet").to_pandas()
    meta = load_meta(cache_root, scenario)
    scores = load_scores(cache_root, scenario)
    signature_by_id = dict(zip(observable["meta_id"], observable["signature"]))
    earlier_signatures = pairs["earlier_meta_id"].map(signature_by_id).to_numpy()
    later_signatures = pairs["later_meta_id"].map(signature_by_id).to_numpy()

    fold_count = len(bundle["folds"])
    probabilities = np.empty((fold_count, len(pairs)), dtype=np.float32)
    decision_votes = np.zeros(len(pairs), dtype=np.int8)
    core_votes = np.zeros(len(pairs), dtype=np.int8)
    bridge_votes = np.zeros(len(pairs), dtype=np.int8)
    pair_pass_votes = np.zeros(len(pairs), dtype=np.int8)
    bridge_eligible_votes = np.zeros(len(pairs), dtype=np.int8)
    for fold_index, fold in enumerate(bundle["folds"]):
        x = pairs.loc[:, fold["feature_names"]].to_numpy(dtype=np.float32)
        if fold["idf"] is not None:
            x = np.column_stack(
                (
                    x,
                    _rarity(earlier_signatures, bundle["signature_vocabulary"], fold["idf"], fold["unseen_rarity"]),
                    _rarity(later_signatures, bundle["signature_vocabulary"], fold["idf"], fold["unseen_rarity"]),
                )
            ).astype(np.float32)
        probability = fold["model"].predict_proba(x)[:, 1].astype(np.float32)
        prediction, core, bridge, bridge_eligible = _fold_decision(
            meta,
            pairs,
            probability,
            scores,
            float(fold["threshold"]),
            graph_thresholds[str(fold["held_out_scenario"])],
        )
        probabilities[fold_index] = probability
        decision_votes += prediction.astype(np.int8)
        core_votes += core.astype(np.int8)
        bridge_votes += bridge.astype(np.int8)
        pair_pass_votes += (probability >= float(fold["threshold"])).astype(np.int8)
        bridge_eligible_votes += bridge_eligible.astype(np.int8)

    selected = decision_votes >= 4
    membership, selected_edges, _ = component_membership(meta, pairs, selected.astype(float), 0.5)
    selected_indices = np.flatnonzero(selected)
    vertex = pd.Series(np.arange(len(meta), dtype=np.int32), index=meta["meta_id"])
    left = pairs["earlier_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    right = pairs["later_meta_id"].map(vertex).to_numpy(dtype=np.int32)
    graph = ig.Graph(n=len(meta), edges=np.column_stack((left[selected], right[selected])), directed=False)
    graph_bridge_pairs = np.zeros(len(pairs), dtype=bool)
    bridge_edge_ids = graph.bridges()
    if bridge_edge_ids:
        graph_bridge_pairs[selected_indices[np.asarray(bridge_edge_ids, dtype=np.int64)]] = True

    attack = meta["is_attack"].fillna(False).to_numpy(dtype=bool)
    attack_ids = np.where(attack, meta["attack_instance_id"].fillna("").astype(str), "")
    fused_components = []
    fusion_edge_records: list[dict] = []
    for component in np.unique(membership[attack]):
        nodes = np.flatnonzero(membership == component)
        instances = sorted(set(attack_ids[nodes]) - {""})
        if len(instances) < 2:
            continue
        in_component_edge = selected & (membership[left] == component)
        direct = in_component_edge & (attack_ids[left] != "") & (attack_ids[right] != "") & (attack_ids[left] != attack_ids[right])
        attack_nonattack = in_component_edge & ((attack_ids[left] == "") ^ (attack_ids[right] == ""))
        direct_indices = np.flatnonzero(direct)
        shortest = _shortest_cross_path(graph, membership, int(component), attack_ids, left, right, selected_indices)
        mediated = _shortest_cross_path(graph, membership, int(component), attack_ids, left, right, selected_indices, forbid_direct=True)
        record_indices = np.unique(np.concatenate((direct_indices, np.asarray(shortest), np.asarray(mediated))).astype(np.int64))
        fusion_edge_records.extend(
            _edge_records(
                scenario, record_indices, pairs, meta, left, right, probabilities,
                decision_votes, core_votes, bridge_votes, pair_pass_votes,
                bridge_eligible_votes, scores, graph_bridge_pairs, "fusion_evidence",
            )
        )
        fused_components.append(
            {
                "component": int(component),
                "nodes": int(len(nodes)),
                "attack_nodes": int(attack[nodes].sum()),
                "nonattack_nodes": int((~attack[nodes]).sum()),
                "attack_instances": instances,
                "selected_edges": int(in_component_edge.sum()),
                "direct_cross_attack_edges": int(direct.sum()),
                "direct_cross_strong_negative": int((direct & (pairs["target"].to_numpy() == 0) & (pairs["label_confidence"].to_numpy() == "high")).sum()),
                "direct_cross_weak_negative": int((direct & (pairs["target"].to_numpy() == 0) & (pairs["label_confidence"].to_numpy() != "high")).sum()),
                "attack_nonattack_edges": int(attack_nonattack.sum()),
                "shortest_cross_path_pair_indices": [int(x) for x in shortest],
                "shortest_cross_path_length": len(shortest),
                "mediated_path_without_direct_cross_edge": [int(x) for x in mediated],
                "mediated_path_length": len(mediated) if mediated else None,
                "has_attack_to_attack_connection_via_nonattack_without_direct_edge": bool(mediated),
            }
        )

    target = pairs["target"].to_numpy(dtype=np.int8)
    confidence = pairs["label_confidence"].astype(str).to_numpy()
    manual_score = MANUAL_ALPHA * scores["similarity"] + (1.0 - MANUAL_ALPHA) * scores["causality"]
    selected_origin = {
        "core_supported": int((selected & (core_votes >= 4)).sum()),
        "bridge_or_mixed_supported": int((selected & (core_votes < 4) & (bridge_votes > 0)).sum()),
        "selected_without_core_or_bridge_impossible": int((selected & (core_votes == 0) & (bridge_votes == 0)).sum()),
        "strong_positive": int((selected & (target == 1) & (confidence == "high")).sum()),
        "weak_positive": int((selected & (target == 1) & (confidence != "high")).sum()),
        "strong_negative": int((selected & (target == 0) & (confidence == "high")).sum()),
        "weak_negative": int((selected & (target == 0) & (confidence != "high")).sum()),
    }
    endpoint_left = attack_ids[left]
    endpoint_right = attack_ids[right]
    direct_cross = (
        (endpoint_left != "")
        & (endpoint_right != "")
        & (endpoint_left != endpoint_right)
    )
    same_attack = (endpoint_left != "") & (endpoint_left == endpoint_right)
    attack_nonattack = (endpoint_left == "") ^ (endpoint_right == "")
    nonattack_nonattack = (endpoint_left == "") & (endpoint_right == "")
    selected_endpoint_classes = {
        "same_attack": int((selected & same_attack).sum()),
        "direct_different_attacks": int((selected & direct_cross).sum()),
        "attack_nonattack": int((selected & attack_nonattack).sum()),
        "nonattack_nonattack": int((selected & nonattack_nonattack).sum()),
        "attack_nonattack_core_supported": int((selected & attack_nonattack & (core_votes >= 4)).sum()),
        "attack_nonattack_bridge_or_mixed": int((selected & attack_nonattack & (core_votes < 4)).sum()),
    }
    fragmentation = _attack_fragmentation_stages(
        meta, pairs, left, right, pair_pass_votes, core_votes,
        bridge_eligible_votes, decision_votes, selected, membership,
    )
    report = {
        "scenario": scenario,
        "meta_alerts": int(len(meta)),
        "attack_meta_alerts": int(attack.sum()),
        "labeled_candidates": int(len(pairs)),
        "selected_edges": int(selected.sum()),
        "selected_origin_and_truth": selected_origin,
        "selected_endpoint_classes": selected_endpoint_classes,
        "positive_relation_pipeline": _positive_stage_counts(
            pairs, pair_pass_votes, core_votes, bridge_eligible_votes, selected, manual_score
        ),
        "fused_component_count": len(fused_components),
        "fused_components": fused_components,
        "fragmentation_stages": fragmentation,
        "candidate_source_selected": dict(Counter(pairs.loc[selected, "candidate_source"].astype(str))),
        "vote_cycle_note": {
            "selected_graph_cycle_rank": int(selected.sum() - len(meta) + len(np.unique(membership))),
            "selected_edges_that_are_graph_bridges": int(graph_bridge_pairs.sum()),
        },
    }
    return report, fusion_edge_records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=Path("data/processed/ait_pairs_v3"))
    parser.add_argument("--ensemble", type=Path, default=Path("output/final-ensemble.joblib"))
    parser.add_argument("--graph-policy", type=Path, default=Path("output/manual-core-ml-bridges.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scenarios", nargs="+", default=list(SCENARIOS))
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"Le dossier existe déjà: {args.output_dir}")

    bundle = joblib.load(args.ensemble)
    policy = json.loads(args.graph_policy.read_text(encoding="utf-8"))
    graph_thresholds = {
        item["scenario"]: float(item["selected_bridge_threshold"]["threshold"])
        for item in policy["ait"]["scenarios"]
    }
    reports = []
    fusion_edges = []
    for scenario in args.scenarios:
        report, records = diagnose_scenario(
            scenario, args.cache_root, bundle, graph_thresholds
        )
        reports.append(report)
        fusion_edges.extend(records)
        print(json.dumps({"completed": scenario, "selected_edges": report["selected_edges"]}), flush=True)

    result = {
        "kind": "offline-graph-fusion-fragmentation-diagnostic",
        "scientific_status": "development diagnostic; AIT scenarios were previously inspected",
        "no_retraining": True,
        "truth_used_for_decision": False,
        "truth_used_for_diagnostic_only": True,
        "ensemble_rule": "eight frozen graph decisions, vote >= 4, no post-vote cycle removal",
        "inputs": {
            "cache_root": str(args.cache_root),
            "ensemble": str(args.ensemble),
            "ensemble_sha256": _sha256(args.ensemble),
            "graph_policy": str(args.graph_policy),
            "graph_policy_sha256": _sha256(args.graph_policy),
        },
        "scenarios": reports,
    }
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "report.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    table = pa.Table.from_pylist(fusion_edges) if fusion_edges else pa.table({"scenario": []})
    pq.write_table(table, args.output_dir / "fusion_edges.parquet", compression="zstd")
    print(json.dumps({"output": str(args.output_dir), "fusion_edge_records": len(fusion_edges)}, indent=2))


if __name__ == "__main__":
    main()
