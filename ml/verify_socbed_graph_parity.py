#!/usr/bin/env python3
"""Capture ou vérifie la parité exacte du graphe scientifique sur SOCBED."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from evaluate_cascade_graphs import graph_report
from evaluate_nested_baselines import load_scores
from optimize_graph_thresholds import load_meta, load_pair_ids
from optimize_manual_core_ml_bridges import bridge_prediction


DEFAULT_RUN = "host1_bestpractice_01"


def _hash_bytes(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def _hash_strings(values) -> str:
    return _hash_bytes("\n".join(map(str, values)).encode("utf-8"))


def _rarity(signatures: np.ndarray, vocabulary, idf, unseen) -> np.ndarray:
    return np.asarray(
        [idf[vocabulary[x]] if x in vocabulary else unseen for x in signatures],
        dtype=np.float32,
    )


def _bridge_thresholds(policy: dict) -> dict[str, float]:
    return {
        item["scenario"]: float(item["selected_bridge_threshold"]["threshold"])
        for item in policy["ait"]["scenarios"]
    }


def _canonical_components(
    meta_ids: list[str], pairs: pd.DataFrame, prediction: np.ndarray
) -> dict[str, str]:
    adjacency = {meta_id: set() for meta_id in meta_ids}
    for row in pairs.loc[prediction, ["earlier_meta_id", "later_meta_id"]].itertuples(
        index=False
    ):
        adjacency[row.earlier_meta_id].add(row.later_meta_id)
        adjacency[row.later_meta_id].add(row.earlier_meta_id)
    result: dict[str, str] = {}
    for start in meta_ids:
        if start in result:
            continue
        stack = [start]
        members = []
        while stack:
            current = stack.pop()
            if current in result:
                continue
            result[current] = "pending"
            members.append(current)
            stack.extend(adjacency[current] - result.keys())
        canonical = min(members)
        for member in members:
            result[member] = canonical
    return dict(sorted(result.items()))


def reconstruct(
    socbed_root: Path,
    ensemble_path: Path,
    policy_path: Path,
    external_predictions_root: Path,
    run_id: str,
) -> dict:
    bundle = joblib.load(ensemble_path)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    thresholds = _bridge_thresholds(policy)
    cache = socbed_root / run_id
    frame = pq.read_table(cache / "pair_examples.parquet").to_pandas()
    frame = frame[frame["target"].notna()].reset_index(drop=True)
    external = pq.read_table(
        external_predictions_root / run_id / "pair_predictions.parquet",
        columns=["earlier_meta_id", "later_meta_id", "target"],
    ).to_pandas().reset_index(drop=True)
    identity_columns = ["earlier_meta_id", "later_meta_id", "target"]
    # Parquet conserve ici la cible scientifique sous deux largeurs d'entier
    # différentes (int64 dans le cache, int8 dans l'export). L'identité utile
    # est celle des IDs ordonnés et des valeurs, pas celle du dtype physique.
    input_identity_equal = (
        frame["earlier_meta_id"].astype(str).tolist()
        == external["earlier_meta_id"].astype(str).tolist()
        and frame["later_meta_id"].astype(str).tolist()
        == external["later_meta_id"].astype(str).tolist()
        and np.array_equal(
            frame["target"].to_numpy(dtype=np.int8),
            external["target"].to_numpy(dtype=np.int8),
        )
    )
    if not input_identity_equal:
        raise ValueError("Les paires SOCBED ne sont pas identiques à la validation scientifique")

    meta_observable = pq.read_table(cache / "meta_observable.parquet").to_pandas()
    signature_by_id = dict(zip(meta_observable["meta_id"], meta_observable["signature"]))
    earlier_signatures = frame["earlier_meta_id"].map(signature_by_id).to_numpy()
    later_signatures = frame["later_meta_id"].map(signature_by_id).to_numpy()
    meta = load_meta(socbed_root, run_id)
    pairs = load_pair_ids(socbed_root, run_id)
    pairs_identity_equal = (
        pairs["earlier_meta_id"].astype(str).tolist()
        == frame["earlier_meta_id"].astype(str).tolist()
        and pairs["later_meta_id"].astype(str).tolist()
        == frame["later_meta_id"].astype(str).tolist()
        and np.array_equal(
            pairs["target"].to_numpy(dtype=np.int8),
            frame["target"].to_numpy(dtype=np.int8),
        )
    )
    if not pairs_identity_equal:
        raise ValueError("L'ordre des paires du graphe diffère du cache scientifique")

    scores = load_scores(socbed_root, run_id)
    vocabulary = bundle["signature_vocabulary"]
    fold_predictions = []
    fold_audit = []
    for fold in bundle["folds"]:
        feature_names = tuple(fold["feature_names"])
        x = frame.loc[:, feature_names].to_numpy(dtype=np.float32)
        if fold["idf"] is not None:
            x = np.column_stack(
                (
                    x,
                    _rarity(
                        earlier_signatures,
                        vocabulary,
                        fold["idf"],
                        fold["unseen_rarity"],
                    ),
                    _rarity(
                        later_signatures,
                        vocabulary,
                        fold["idf"],
                        fold["unseen_rarity"],
                    ),
                )
            ).astype(np.float32)
        probability = fold["model"].predict_proba(x)[:, 1]
        held_out = fold["held_out_scenario"]
        prediction = bridge_prediction(
            meta,
            pairs,
            probability,
            scores,
            float(fold["threshold"]),
            thresholds[held_out],
        )
        fold_predictions.append(prediction)
        fold_audit.append(
            {
                "held_out_scenario": held_out,
                "relation_threshold": float(fold["threshold"]),
                "bridge_threshold": thresholds[held_out],
                "feature_names": list(feature_names),
                "feature_matrix_shape": list(x.shape),
                "feature_matrix_sha256": _hash_bytes(x.tobytes(order="C")),
                "probability_sha256": _hash_bytes(
                    np.asarray(probability, dtype=np.float64).tobytes(order="C")
                ),
                "selected_edge_count": int(prediction.sum()),
            }
        )

    vote_matrix = np.stack(fold_predictions)
    vote_count = vote_matrix.sum(axis=0).astype(np.int8)
    prediction = vote_count >= 4
    selected = pairs.loc[
        prediction, ["earlier_meta_id", "later_meta_id"]
    ].sort_values(["earlier_meta_id", "later_meta_id"])
    selected_edges = selected.astype(str).agg("|".join, axis=1).tolist()
    meta_ids = meta["meta_id"].astype(str).tolist()
    return {
        "kind": "socbed-exact-scientific-graph-parity-reference",
        "run_id": run_id,
        "ensemble": str(ensemble_path),
        "graph_policy": str(policy_path),
        "inputs": {
            "cache": str(cache),
            "external_predictions": str(external_predictions_root / run_id),
            "pair_count": len(frame),
            "pair_identity_equal": input_identity_equal,
            "pair_ids_sha256": _hash_strings(
                frame["earlier_meta_id"].astype(str)
                + "|"
                + frame["later_meta_id"].astype(str)
            ),
            "targets_sha256": _hash_bytes(
                frame["target"].to_numpy(dtype=np.int8).tobytes(order="C")
            ),
            "meta_ids_sha256": _hash_strings(meta_ids),
        },
        "folds": fold_audit,
        "vote_quorum": 4,
        "vote_count_sha256": _hash_bytes(vote_count.tobytes(order="C")),
        "selected_edge_count": len(selected_edges),
        "selected_edges": selected_edges,
        "components": _canonical_components(meta_ids, pairs, prediction),
        "metrics": graph_report(meta, pairs, prediction),
    }


def _compare(reference: dict, actual: dict) -> dict:
    checks = {
        "run_id": actual["run_id"] == reference["run_id"],
        "inputs": actual["inputs"] == reference["inputs"],
        "folds": actual["folds"] == reference["folds"],
        "vote_count": actual["vote_count_sha256"] == reference["vote_count_sha256"],
        "edge_ids": actual["selected_edges"] == reference["selected_edges"],
        "components": actual["components"] == reference["components"],
        "metrics": actual["metrics"] == reference["metrics"],
    }
    return {"passed": all(checks.values()), "checks": checks}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socbed-root", type=Path, default=Path("data/processed/socbed_pairs_v3"))
    parser.add_argument("--ensemble", type=Path, default=Path("output/final-ensemble.joblib"))
    parser.add_argument("--policy", type=Path, default=Path("output/manual-core-ml-bridges.json"))
    parser.add_argument(
        "--external-predictions",
        type=Path,
        default=Path("output/socbed-external-validation"),
    )
    parser.add_argument("--run-id", default=DEFAULT_RUN)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    actual = reconstruct(
        args.socbed_root,
        args.ensemble,
        args.policy,
        args.external_predictions,
        args.run_id,
    )
    if args.capture:
        if args.reference.exists():
            raise FileExistsError(f"Référence déjà présente: {args.reference}")
        args.reference.parent.mkdir(parents=True, exist_ok=True)
        args.reference.write_text(
            json.dumps(actual, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"captured": str(args.reference), "edges": actual["selected_edge_count"]}))
        return
    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    comparison = _compare(reference, actual)
    print(json.dumps(comparison, indent=2))
    if not comparison["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
