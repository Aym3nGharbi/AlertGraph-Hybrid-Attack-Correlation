#!/usr/bin/env python3
"""Primitives partagées de reconstruction graphique, sans apprentissage."""

from __future__ import annotations

import numpy as np


MANUAL_ALPHA = 0.25
MANUAL_THRESHOLD = 0.50


class DisjointSet:
    def __init__(self, size: int):
        self.parent = np.arange(size, dtype=np.int32)
        self.rank = np.zeros(size, dtype=np.int8)

    def find(self, item: int) -> int:
        parent = self.parent
        root = item
        while parent[root] != root:
            root = int(parent[root])
        while parent[item] != item:
            next_item = int(parent[item])
            parent[item] = root
            item = next_item
        return root

    def union(self, left: int, right: int) -> bool:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return False
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1
        return True


def manual_score(
    scores: dict[str, np.ndarray], alpha: float = MANUAL_ALPHA
) -> np.ndarray:
    return alpha * scores["similarity"] + (1.0 - alpha) * scores["causality"]


def bridge_prediction(
    meta,
    pairs,
    probability: np.ndarray,
    scores: dict[str, np.ndarray],
    pair_threshold: float,
    bridge_threshold: float,
    manual_alpha: float = MANUAL_ALPHA,
    manual_threshold: float = MANUAL_THRESHOLD,
) -> np.ndarray:
    """Noyau précis puis forêt maximale de ponts ML, logique scientifique V1."""

    if len(pairs) != len(probability):
        raise ValueError("Désalignement des paires et probabilités")
    manual = manual_score(scores, manual_alpha)
    core = (probability >= pair_threshold) & (manual >= manual_threshold)
    allowed = ~scores["stage_known"] | scores["same_stage"] | scores["compatible"]
    candidates = np.flatnonzero(~core & allowed & (probability >= bridge_threshold))
    candidates = candidates[np.argsort(-probability[candidates], kind="stable")]

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


def aggregate_graph_votes(
    fold_predictions: list[np.ndarray], quorum: int = 4
) -> tuple[np.ndarray, np.ndarray]:
    """Vote scientifique exact; aucun retrait de cycle n'est fait après le vote."""

    if not fold_predictions:
        raise ValueError("Aucune prédiction de fold à agréger")
    matrix = np.stack(fold_predictions).astype(bool, copy=False)
    if quorum < 1 or quorum > matrix.shape[0]:
        raise ValueError("Quorum de vote invalide")
    counts = matrix.sum(axis=0).astype(np.int8)
    return counts, counts >= quorum


def legacy_mean_bridge_prediction(
    meta,
    pairs,
    mean_probability: np.ndarray,
    ml_prediction: np.ndarray,
    scores: dict[str, np.ndarray],
    bridge_threshold: float = 0.50,
    manual_alpha: float = MANUAL_ALPHA,
    manual_threshold: float = MANUAL_THRESHOLD,
) -> np.ndarray:
    """Reproduit l'ancienne reconstruction Wazuh fondée sur la moyenne."""

    manual = manual_score(scores, manual_alpha)
    core = ml_prediction & (manual >= manual_threshold)
    allowed = ~scores["stage_known"] | scores["same_stage"] | scores["compatible"]
    candidates = np.flatnonzero(
        ~core & allowed & (mean_probability >= bridge_threshold)
    )
    candidates = candidates[np.argsort(-mean_probability[candidates], kind="stable")]

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
