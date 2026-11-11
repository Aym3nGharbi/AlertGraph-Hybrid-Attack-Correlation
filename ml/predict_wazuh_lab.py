#!/usr/bin/env python3
"""Applique l'ensemble gelé et construit les trois variantes de graphe du labo."""

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

from baseline_scores import causal_score, manual_hybrid_score, similarity_score
from graph_reconstruction import (
    DisjointSet,
    aggregate_graph_votes,
    bridge_prediction,
    legacy_mean_bridge_prediction,
)
from traceability import audit_traceability, require_complete_traceability


def _traceability_report(cache_dir: Path, meta: pd.DataFrame) -> dict[str, object]:
    manifest = json.loads((cache_dir / "manifest.json").read_text(encoding="utf-8"))
    raw_path = Path(manifest["input"])
    if not raw_path.is_absolute() and not raw_path.exists():
        raw_path = cache_dir.parents[1] / "alerts.jsonl"
    raw_ids = []
    with raw_path.open("r", encoding="utf-8-sig") as source:
        for line in source:
            if line.strip():
                raw_ids.append(str(json.loads(line)["id"]))
    report = audit_traceability(raw_ids, meta["member_alert_ids"])
    require_complete_traceability(report)
    report["source"] = str(raw_path)
    return report


def _rarity(signatures: np.ndarray, vocabulary, idf, unseen) -> np.ndarray:
    return np.asarray(
        [idf[vocabulary[x]] if x in vocabulary else unseen for x in signatures],
        dtype=np.float32,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_graph_policy(path: Path, folds: list[dict]) -> tuple[dict[str, float], float, float]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    thresholds = {
        item["scenario"]: float(item["selected_bridge_threshold"]["threshold"])
        for item in policy["ait"]["scenarios"]
    }
    held_out = [str(fold["held_out_scenario"]) for fold in folds]
    missing = sorted(set(held_out) - set(thresholds))
    if missing:
        raise ValueError(f"Seuils graphiques absents pour les folds: {missing}")
    return (
        thresholds,
        float(policy["manual_alpha"]),
        float(policy["manual_threshold"]),
    )


def _components(meta_ids: list[str], pairs: pd.DataFrame, prediction: np.ndarray) -> np.ndarray:
    vertex = {value: index for index, value in enumerate(meta_ids)}
    dsu = DisjointSet(len(meta_ids))
    for row in pairs.loc[prediction].itertuples(index=False):
        dsu.union(vertex[row.earlier_meta_id], vertex[row.later_meta_id])
    roots = [dsu.find(index) for index in range(len(meta_ids))]
    labels = {root: index for index, root in enumerate(dict.fromkeys(roots))}
    return np.asarray([labels[x] for x in roots], dtype=np.int32)


def _episodes(meta: pd.DataFrame, gap_seconds: float) -> dict[str, str]:
    """Segmente chaque hôte par inactivité, avec uniquement des temps observables."""

    result = {}
    state = {}
    ordered = meta.sort_values(["first_timestamp", "meta_id"])
    for row in ordered.itertuples(index=False):
        hosts = [value for value in row.entities if value.startswith("host:")]
        host = hosts[0] if hosts else (row.agent_names[0] if len(row.agent_names) else "unknown")
        previous_end, episode = state.get(host, (None, 0))
        if previous_end is not None and row.first_timestamp - previous_end > gap_seconds:
            episode += 1
        result[row.meta_id] = f"{host}:{episode}"
        state[host] = (max(float(row.last_timestamp), previous_end or float(row.last_timestamp)), episode)
    return result


def predict(
    cache_dir: Path,
    ensemble_path: Path,
    output_dir: Path,
    episode_gap_seconds: float | None = 15.0,
    graph_policy_path: Path = Path("output/manual-core-ml-bridges.json"),
) -> dict:
    bundle = joblib.load(ensemble_path)
    graph_thresholds, manual_alpha, manual_threshold = _load_graph_policy(
        graph_policy_path, bundle["folds"]
    )
    pairs = pq.read_table(cache_dir / "pair_examples.parquet").to_pandas()
    meta = pq.read_table(cache_dir / "meta_observable.parquet").to_pandas()
    traceability = _traceability_report(cache_dir, meta)
    if pairs.empty:
        raise ValueError("Le run ne contient aucune paire candidate")
    signature_by_id = dict(zip(meta["meta_id"], meta["signature"]))
    earlier_signatures = pairs["earlier_meta_id"].map(signature_by_id).to_numpy()
    later_signatures = pairs["later_meta_id"].map(signature_by_id).to_numpy()

    probabilities, votes = [], []
    vocabulary = bundle["signature_vocabulary"]
    for fold in bundle["folds"]:
        x = pairs.loc[:, fold["feature_names"]].to_numpy(dtype=np.float32)
        if fold["idf"] is not None:
            x = np.column_stack((
                x,
                _rarity(earlier_signatures, vocabulary, fold["idf"], fold["unseen_rarity"]),
                _rarity(later_signatures, vocabulary, fold["idf"], fold["unseen_rarity"]),
            )).astype(np.float32)
        probability = fold["model"].predict_proba(x)[:, 1]
        probabilities.append(probability)
        votes.append(probability >= fold["threshold"])
    scores = np.stack(probabilities)
    vote_matrix = np.stack(votes)
    ml_probability = scores.mean(axis=0)
    ml_prediction = vote_matrix.sum(axis=0) >= 4

    feature_rows = pairs.to_dict(orient="records")
    similarity = np.asarray([similarity_score(x) for x in feature_rows])
    causality = np.asarray([causal_score(x) for x in feature_rows])
    manual = np.asarray([manual_hybrid_score(x, alpha=0.25) for x in feature_rows])
    strict = ml_prediction & (manual >= manual_threshold)

    stage_known = pairs["stage_known_both"].to_numpy(dtype=bool)
    graph_scores = {
        "similarity": similarity,
        "causality": causality,
        "stage_known": stage_known,
        "same_stage": pairs["same_stage"].to_numpy(dtype=bool),
        "compatible": pairs["forward_progression_compatible"].to_numpy(dtype=bool),
    }
    legacy_bridge = legacy_mean_bridge_prediction(
        meta,
        pairs,
        ml_probability,
        ml_prediction,
        graph_scores,
        bridge_threshold=0.50,
        manual_alpha=manual_alpha,
        manual_threshold=manual_threshold,
    )
    fold_graph_predictions = []
    for fold, probability in zip(bundle["folds"], probabilities):
        held_out = str(fold["held_out_scenario"])
        fold_graph_predictions.append(
            bridge_prediction(
                meta,
                pairs,
                probability,
                graph_scores,
                float(fold["threshold"]),
                graph_thresholds[held_out],
                manual_alpha=manual_alpha,
                manual_threshold=manual_threshold,
            )
        )
    graph_vote_count, bridge = aggregate_graph_votes(fold_graph_predictions, quorum=4)

    episode_bridge = None
    if episode_gap_seconds is not None:
        episode_by_id = _episodes(meta, episode_gap_seconds)
        same_episode = np.asarray([
            episode_by_id[left_id] == episode_by_id[right_id]
            for left_id, right_id in zip(pairs["earlier_meta_id"], pairs["later_meta_id"])
        ])
        episode_bridge = bridge & same_episode

    pairs = pairs[["earlier_meta_id", "later_meta_id", "candidate_source"]].copy()
    pairs["similarity_score"] = similarity
    pairs["causality_score"] = causality
    pairs["manual_score"] = manual
    pairs["ml_probability"] = ml_probability
    pairs["ml_votes"] = vote_matrix.sum(axis=0).astype(np.int8)
    pairs["graph_votes"] = graph_vote_count
    pairs["ml_only"] = ml_prediction
    pairs["ml_and_manual"] = strict
    pairs["manual_core_ml_bridges_legacy_mean"] = legacy_bridge
    pairs["manual_core_ml_bridges"] = bridge
    if episode_bridge is not None:
        pairs["episode_constrained_bridges"] = episode_bridge

    meta_ids = meta["meta_id"].tolist()
    methods = [
        "ml_only",
        "ml_and_manual",
        "manual_core_ml_bridges_legacy_mean",
        "manual_core_ml_bridges",
    ]
    if episode_bridge is not None:
        methods.append("episode_constrained_bridges")
    summaries = {}
    for method in methods:
        prediction = pairs[method].to_numpy(dtype=bool)
        meta[f"{method}_component"] = _components(meta_ids, pairs, prediction)
        summaries[method] = {
            "edges": int(prediction.sum()),
            "components": int(meta[f"{method}_component"].nunique()),
            "largest_component": int(meta.groupby(f"{method}_component").size().max()),
        }
    output_dir.mkdir(parents=True, exist_ok=False)
    pq.write_table(pa.Table.from_pandas(pairs, preserve_index=False), output_dir / "pair_predictions.parquet", compression="zstd")
    pq.write_table(pa.Table.from_pandas(meta, preserve_index=False), output_dir / "nodes.parquet", compression="zstd")
    report = {
        "kind": "wazuh-lab-frozen-inference",
        "threshold_transfer": "eight frozen AIT thresholds; no lab labels used",
        "methods": summaries,
        "mapping_coverage": float(meta["observed_stage"].notna().mean()),
        "episode_gap_seconds": episode_gap_seconds,
        "episode_policy": (
            "optional hard inactivity boundary applied after the scientific vote"
            if episode_gap_seconds is not None
            else "disabled"
        ),
        "graph_reconstruction": {
            "aligned_method": "manual_core_ml_bridges",
            "legacy_method": "manual_core_ml_bridges_legacy_mean",
            "vote_rule": "at least 4 of 8 per-fold graph decisions",
            "post_vote_cycle_rule": "none",
            "manual_alpha": manual_alpha,
            "manual_threshold": manual_threshold,
            "folds": [
                {
                    "held_out_scenario": str(fold["held_out_scenario"]),
                    "relation_threshold": float(fold["threshold"]),
                    "bridge_threshold": graph_thresholds[str(fold["held_out_scenario"])],
                }
                for fold in bundle["folds"]
            ],
            "ensemble_sha256": _sha256(ensemble_path),
            "policy_path": str(graph_policy_path),
            "policy_sha256": _sha256(graph_policy_path),
        },
        "traceability": traceability,
    }
    (output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    node_rows = []
    for row in meta.itertuples(index=False):
        node_rows.append({
            "id": row.meta_id,
            "first_timestamp": float(row.first_timestamp),
            "last_timestamp": float(row.last_timestamp),
            "signature": row.signature,
            "description": row.signature_text,
            "stage": None if pd.isna(row.observed_stage) else row.observed_stage,
            "member_count": len(row.member_alert_ids),
            "member_alert_ids": list(row.member_alert_ids),
            "agents": list(row.agent_names),
            "severity": {
                "min": None if pd.isna(row.min_severity) else int(row.min_severity),
                "max": None if pd.isna(row.max_severity) else int(row.max_severity),
            },
            "observed_tactics": list(row.observed_tactics),
            "entities": list(row.entities),
            "components": {
                method: int(getattr(row, f"{method}_component"))
                for method in methods
            },
        })
    edge_rows = {
        method: [
            {
                "from": row.earlier_meta_id,
                "to": row.later_meta_id,
                "ml_probability": float(row.ml_probability),
                "manual_score": float(row.manual_score),
            }
            for row in pairs.loc[pairs[method]].itertuples(index=False)
        ]
        for method in methods
    }
    visualization = {
        "run_id": cache_dir.name,
        "report": report,
        "nodes": node_rows,
        "edges": edge_rows,
    }
    (output_dir / "visualization.json").write_text(
        json.dumps(visualization, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--ensemble", type=Path, default=Path("output/final-ensemble.joblib"))
    parser.add_argument(
        "--graph-policy",
        type=Path,
        default=Path("output/manual-core-ml-bridges.json"),
    )
    parser.add_argument("--episode-gap-seconds", type=float, default=15.0)
    parser.add_argument("--disable-episodes", action="store_true")
    args = parser.parse_args()
    episode_gap = None if args.disable_episodes else args.episode_gap_seconds
    print(json.dumps(predict(
        args.cache_dir,
        args.ensemble,
        args.output_dir,
        episode_gap,
        args.graph_policy,
    ), indent=2))


if __name__ == "__main__":
    main()
