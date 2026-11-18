"""Audit hors ML du rappel des candidats sur les transitions longues V2."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict, deque
from itertools import combinations
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterable

import pyarrow.parquet as pq

from .io_utils import load_json, utc_now, write_new_json


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _summary(values: Iterable[float]) -> dict[str, float | int | None]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"count": 0, "min": None, "median": None, "mean": None, "max": None}
    return {
        "count": len(ordered), "min": ordered[0], "median": median(ordered),
        "mean": mean(ordered), "max": ordered[-1],
    }


def _identity(row: dict[str, Any]) -> str:
    attack = row.get("attack_instance_id")
    if attack:
        return str(attack).rsplit(":", 1)[-1].upper()
    benign = row.get("benign_activity_id")
    return str(benign).rsplit(":", 1)[-1].upper() if benign else "UNKNOWN"


def relation_scope(left: dict[str, Any], right: dict[str, Any]) -> str | None:
    left_identity, right_identity = _identity(left), _identity(right)
    if left["class"] == "benign" and right["class"] == "benign":
        return None
    if left["class"] == "attack" and right["class"] == "attack":
        if left_identity == right_identity:
            return f"positive-{left_identity.lower()}-{right_identity.lower()}"
        return "negative-a1-a2"
    attack_identity = left_identity if left["class"] == "attack" else right_identity
    return f"negative-{attack_identity.lower()}-b1"


def connected_components(nodes: Iterable[str], edges: Iterable[tuple[str, str]]) -> list[list[str]]:
    adjacency = {node: set() for node in nodes}
    for left, right in edges:
        if left in adjacency and right in adjacency:
            adjacency[left].add(right); adjacency[right].add(left)
    components = []
    unseen = set(adjacency)
    while unseen:
        start = min(unseen); unseen.remove(start); component = []
        queue = deque([start])
        while queue:
            node = queue.popleft(); component.append(node)
            for neighbor in sorted(adjacency[node]):
                if neighbor in unseen:
                    unseen.remove(neighbor); queue.append(neighbor)
        components.append(sorted(component))
    return sorted(components, key=lambda value: (value[0], len(value)))


def audit_campaign(campaign_dir: str | Path) -> dict[str, Any]:
    campaign = Path(campaign_dir)
    cache = campaign / "derived-cache" / "multiphase-fim-observable-normalized"
    manifest = load_json(cache / "manifest.json")
    metas = {row["meta_id"]: row for row in pq.read_table(cache / "meta_observable.parquet").to_pylist()}
    candidates = pq.read_table(cache / "pair_examples.parquet").to_pylist()
    truth = {row["meta_id"]: row for row in _jsonl(campaign / "supervision-multiphase-fim-v2" / "meta-truth.jsonl")}
    verified = {key: value for key, value in truth.items() if value.get("confidence") == "verified"}
    candidate_by_pair = {(row["earlier_meta_id"], row["later_meta_id"]): row for row in candidates}
    predecessor_counts = Counter(row["later_meta_id"] for row in candidates)
    window = float(manifest["parameters"]["window_seconds"])
    cap = int(manifest["parameters"]["cap"])

    references: list[dict[str, Any]] = []
    for left_id, right_id in combinations(sorted(verified, key=lambda key: (metas[key]["first_timestamp"], key)), 2):
        if metas[left_id]["first_timestamp"] > metas[right_id]["first_timestamp"]:
            left_id, right_id = right_id, left_id
        left_truth, right_truth = verified[left_id], verified[right_id]
        scope = relation_scope(left_truth, right_truth)
        if scope is None:
            continue
        delta = float(metas[right_id]["first_timestamp"] - metas[left_id]["first_timestamp"])
        candidate = candidate_by_pair.get((left_id, right_id))
        if candidate is None:
            if delta > window:
                cause = "outside-window-without-qualifying-causal-bridge"
            elif predecessor_counts[right_id] >= cap:
                cause = "predecessor-cap"
            else:
                cause = "within-window-not-returned"
        else:
            cause = None
        references.append({
            "earlier_meta_id": left_id, "later_meta_id": right_id,
            "scope": scope, "target": 1 if scope.startswith("positive-") else 0,
            "delta_seconds": delta, "candidate": candidate is not None,
            "candidate_source": candidate.get("candidate_source") if candidate else None,
            "missing_cause": cause,
            "earlier_activity_ids": left_truth.get("activity_ids", []),
            "later_activity_ids": right_truth.get("activity_ids", []),
        })

    expected = Counter(row["scope"] for row in references)
    observed = Counter(row["scope"] for row in references if row["candidate"])
    missing = Counter(row["scope"] for row in references if not row["candidate"])
    missing_causes = Counter(row["missing_cause"] for row in references if not row["candidate"])
    positives = [row for row in references if row["target"] == 1]
    negatives = [row for row in references if row["target"] == 0]
    causal = [row for row in references if row["candidate"] and "causal-bridge" in str(row["candidate_source"])]
    causal_only = [row for row in causal if row["candidate_source"] == "causal-bridge"]

    graph = {}
    for identity in ("A1", "A2"):
        nodes = sorted(meta_id for meta_id, row in verified.items() if _identity(row) == identity)
        edges = [
            (row["earlier_meta_id"], row["later_meta_id"])
            for row in positives if row["candidate"] and row["scope"] == f"positive-{identity.lower()}-{identity.lower()}"
        ]
        components = connected_components(nodes, edges)
        graph[identity] = {
            "verified_nodes": len(nodes), "candidate_positive_edges": len(edges),
            "component_count": len(components), "components": components,
            "isolated_nodes": [component[0] for component in components if len(component) == 1],
            "connected": len(components) == 1,
        }

    present_positive = [row["delta_seconds"] for row in positives if row["candidate"]]
    absent_positive = [row["delta_seconds"] for row in positives if not row["candidate"]]
    present_negative = [row["delta_seconds"] for row in negatives if row["candidate"]]
    absent_negative = [row["delta_seconds"] for row in negatives if not row["candidate"]]
    return {
        "schema_version": "alertgraph-long-transition-candidate-audit/2.0",
        "created_at_utc": utc_now(),
        "campaign_id": load_json(campaign / "campaign-manifest.json")["campaign_id"],
        "parameters_unchanged": {
            "window_seconds": window, "predecessor_cap": cap,
            "max_causal_bridges": manifest["parameters"]["max_causal_bridges"],
        },
        "meta_alerts_total": manifest["meta_alerts"], "verified_meta_alerts": len(verified),
        "candidate_pairs_total": len(candidates),
        "candidate_density_all_metas": len(candidates) / (manifest["meta_alerts"] * (manifest["meta_alerts"] - 1) / 2),
        "reference_relations": len(references),
        "reference_positive_relations": len(positives),
        "candidate_positive_relations": sum(row["candidate"] for row in positives),
        "positive_candidate_recall": sum(row["candidate"] for row in positives) / len(positives),
        "reference_negative_relations": len(negatives),
        "candidate_negative_relations": sum(row["candidate"] for row in negatives),
        "negative_candidate_recall": sum(row["candidate"] for row in negatives) / len(negatives),
        "expected_by_scope": dict(expected), "candidate_by_scope": dict(observed),
        "missing_by_scope": dict(missing), "missing_causes": dict(missing_causes),
        "distance_seconds": {
            "positive_present": _summary(present_positive), "positive_absent": _summary(absent_positive),
            "negative_present": _summary(present_negative), "negative_absent": _summary(absent_negative),
        },
        "causal_bridge_effect": {
            "manifest_causal_candidates": manifest["causal_candidates"],
            "verified_reference_candidates_with_causal_evidence": len(causal),
            "verified_reference_candidates_causal_only": len(causal_only),
            "causal_only_by_target": dict(Counter("positive" if row["target"] else "negative" for row in causal_only)),
            "causal_only_pairs": causal_only,
        },
        "predecessor_cap_effect": {
            "maximum_observed_predecessors": max(predecessor_counts.values(), default=0),
            "cap": cap, "cap_reached": max(predecessor_counts.values(), default=0) >= cap,
            "missing_attributed_to_cap": missing_causes.get("predecessor-cap", 0),
        },
        "graph_connectivity_using_only_verified_same_instance_candidates": graph,
        "missing_verified_relations": [row for row in references if not row["candidate"]],
        "reference_relations_are_evaluation_only": True,
        "missing_relations_added_to_ml": False,
        "model_trained": False, "training_ready": False,
    }


def compare(d3: dict[str, Any], baselines: dict[str, dict[str, Any]]) -> dict[str, Any]:
    comparison = {}
    for name, summary in baselines.items():
        expected = summary["expected_pair_categories_from_verified_metas"]
        missing = summary["missing_eligible_pairs"]
        positives = expected["positive-a1-a1"] + expected["positive-a2-a2"]
        missing_positive = missing["positive-a1-a1"] + missing["positive-a2-a2"]
        negatives = sum(value for key, value in expected.items() if key.startswith("negative-"))
        missing_negative = sum(value for key, value in missing.items() if key.startswith("negative-"))
        comparison[name] = {
            "meta_alerts_total": summary["meta_alerts_total"],
            "candidate_pairs_total": summary["candidate_pairs_total"],
            "strict_binary_pairs": summary["strict_binary_pairs"],
            "positive_candidate_recall": (positives - missing_positive) / positives,
            "negative_candidate_recall": (negatives - missing_negative) / negatives,
            "actual_activity_span_seconds": summary["actual_activity_span_seconds"],
        }
    return {
        "schema_version": "alertgraph-long-transition-comparison/2.0",
        "created_at_utc": utc_now(), "d3": d3, "baselines": comparison,
        "training_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--d1-summary", type=Path, required=True)
    parser.add_argument("--d2-summary", type=Path, required=True)
    parser.add_argument("--previous-summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = compare(audit_campaign(args.campaign_dir), {
        "d1": load_json(args.d1_summary), "d2": load_json(args.d2_summary),
        "initial_multiphase": load_json(args.previous_summary),
    })
    write_new_json(args.output, report)
    print(json.dumps({
        "positive_recall": report["d3"]["positive_candidate_recall"],
        "negative_recall": report["d3"]["negative_candidate_recall"],
        "missing_causes": report["d3"]["missing_causes"],
        "connectivity": report["d3"]["graph_connectivity_using_only_verified_same_instance_candidates"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
