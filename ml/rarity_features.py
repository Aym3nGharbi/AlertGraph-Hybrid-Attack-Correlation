"""Rareté de signature apprise exclusivement sur les scénarios d'entraînement."""

from __future__ import annotations

import numpy as np


RARITY_FEATURE_NAMES = (
    "earlier_signature_train_idf",
    "later_signature_train_idf",
)


def signature_idf(counts: np.ndarray) -> np.ndarray:
    """IDF lissée ; une signature absente du train reçoit la valeur maximale."""

    values = np.asarray(counts, dtype=np.float64)
    if values.ndim != 1 or np.any(values < 0):
        raise ValueError("Les fréquences doivent former un vecteur positif")
    total = float(values.sum())
    return (np.log((total + 1.0) / (values + 1.0)) + 1.0).astype(np.float32)


def append_pair_rarity(
    x: np.ndarray,
    earlier_signature_codes: np.ndarray,
    later_signature_codes: np.ndarray,
    idf: np.ndarray,
    indices: np.ndarray | None = None,
) -> np.ndarray:
    """Ajoute les deux IDF à toutes les lignes ou à un sous-échantillon."""

    selected_x = x if indices is None else x[indices]
    earlier = earlier_signature_codes if indices is None else earlier_signature_codes[indices]
    later = later_signature_codes if indices is None else later_signature_codes[indices]
    return np.column_stack((selected_x, idf[earlier], idf[later])).astype(
        np.float32, copy=False
    )
