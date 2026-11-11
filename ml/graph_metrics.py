"""Métriques de groupes pondérées pour les graphes d'alertes."""

from __future__ import annotations

import numpy as np


def _comb2(values: np.ndarray) -> np.ndarray:
    return values * (values - 1.0) / 2.0


def clustering_metrics(
    gold_labels: np.ndarray,
    predicted_labels: np.ndarray,
    weights: np.ndarray | None = None,
) -> dict[str, float]:
    """B-cubed et ARI ; les poids entiers équivalent à l'expansion brute."""

    gold = np.asarray(gold_labels)
    predicted = np.asarray(predicted_labels)
    if len(gold) != len(predicted):
        raise ValueError("Les partitions doivent avoir la même taille")
    sample_weights = (
        np.ones(len(gold), dtype=np.float64)
        if weights is None
        else np.asarray(weights, dtype=np.float64)
    )
    if len(sample_weights) != len(gold) or np.any(sample_weights <= 0):
        raise ValueError("Chaque élément doit avoir un poids strictement positif")
    if not len(gold):
        return {"bcubed_precision": 0.0, "bcubed_recall": 0.0, "bcubed_f1": 0.0, "ari": 0.0}

    _, gold_codes = np.unique(gold, return_inverse=True)
    _, predicted_codes = np.unique(predicted, return_inverse=True)
    pair_keys = np.rec.fromarrays((gold_codes, predicted_codes))
    _, cell_codes = np.unique(pair_keys, return_inverse=True)
    cell_weights = np.bincount(cell_codes, weights=sample_weights)
    gold_weights = np.bincount(gold_codes, weights=sample_weights)
    predicted_weights = np.bincount(predicted_codes, weights=sample_weights)
    intersections = cell_weights[cell_codes]

    precision_items = intersections / predicted_weights[predicted_codes]
    recall_items = intersections / gold_weights[gold_codes]
    total_weight = float(sample_weights.sum())
    precision = float(np.dot(sample_weights, precision_items) / total_weight)
    recall = float(np.dot(sample_weights, recall_items) / total_weight)
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0

    index = float(_comb2(cell_weights).sum())
    row_pairs = float(_comb2(gold_weights).sum())
    column_pairs = float(_comb2(predicted_weights).sum())
    total_pairs = float(_comb2(np.array([total_weight]))[0])
    if total_pairs <= 0:
        ari = 1.0
    else:
        expected = row_pairs * column_pairs / total_pairs
        maximum = 0.5 * (row_pairs + column_pairs)
        denominator = maximum - expected
        ari = (index - expected) / denominator if denominator else 1.0
    return {
        "bcubed_precision": precision,
        "bcubed_recall": recall,
        "bcubed_f1": float(f1),
        "ari": float(ari),
    }


def attack_group_diagnostics(
    attack_instances: np.ndarray,
    predicted_labels: np.ndarray,
    weights: np.ndarray,
) -> dict[str, float]:
    """Mesure explicitement fragmentation et fusion des instances d'attaque."""

    instances = np.asarray(attack_instances)
    predicted = np.asarray(predicted_labels)
    sample_weights = np.asarray(weights, dtype=np.float64)
    fragmentation = []
    largest_coverage = []
    for instance in np.unique(instances):
        mask = instances == instance
        labels, inverse = np.unique(predicted[mask], return_inverse=True)
        cluster_weights = np.bincount(inverse, weights=sample_weights[mask])
        fragmentation.append(len(labels))
        largest_coverage.append(float(cluster_weights.max() / cluster_weights.sum()))

    fused_clusters = 0
    attack_clusters = 0
    for cluster in np.unique(predicted):
        cluster_instances = np.unique(instances[predicted == cluster])
        attack_clusters += 1
        fused_clusters += int(len(cluster_instances) > 1)
    return {
        "mean_fragments_per_attack": float(np.mean(fragmentation)) if fragmentation else 0.0,
        "max_fragments_per_attack": int(max(fragmentation, default=0)),
        "mean_largest_fragment_coverage": float(np.mean(largest_coverage)) if largest_coverage else 0.0,
        "fused_attack_clusters": int(fused_clusters),
        "attack_clusters": int(attack_clusters),
    }
