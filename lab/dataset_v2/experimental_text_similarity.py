"""Similarité textuelle expérimentale ; aucun entraînement de classifieur.

Le vocabulaire doit être ajusté exclusivement sur les groupes d'apprentissage.
Cette extension ne remplace aucune caractéristique de similarité ou causalité.
"""
import re
import unicodedata

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from .marker_normalization import normalize_instrumentation_markers, MARKER_TOKEN

CAMPAIGN = re.compile(r'(?i)\b(?:dev|validation|final-test)-[a-z0-9_-]*\d{8}-\d{3}(?:-r\d+)?\b')
UUID = re.compile(r'(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b')
PRIVATE_FIELD = re.compile(r'(?i)\b(?:campaign_id|run_id|activity_id|attack_instance_id|benign_activity_id|label_confidence|label_reason|evidence_ids|target)\s*[:=]')


def normalise_description(value, markers=()):
    if isinstance(value, dict):
        value = (value.get('rule') or {}).get('description') or ''
    if not isinstance(value, str): raise TypeError('description textuelle requise')
    if PRIVATE_FIELD.search(value): raise ValueError('texte contamine par des champs de supervision')
    text = normalize_instrumentation_markers(unicodedata.normalize('NFKC', value), markers)
    text = text.replace(MARKER_TOKEN, ' ')
    text = CAMPAIGN.sub(' ', UUID.sub(' ', text))
    return ' '.join(text.casefold().split())


class DescriptionSimilarity:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=4096,
            lowercase=False, norm='l2', sublinear_tf=True)
        self.markers = (); self.fitted = False

    def fit_development(self, values, provenance, *, allowed_training_groups, markers=()):
        if len(values) != len(provenance) or not values: raise ValueError('provenance incomplete')
        groups = set(allowed_training_groups)
        if not groups or any(p['partition'] != 'development' or p['group_id'] not in groups for p in provenance):
            raise PermissionError('vocabulaire reserve aux seuls groupes apprentissage autorises')
        self.markers = tuple(set(markers) | {p['group_id'] for p in provenance})
        clean = [normalise_description(v, self.markers) for v in values]
        self.vectorizer.fit(clean)
        self.fitted = True
        return self

    def pair_similarity(self, left, right):
        if not self.fitted: raise RuntimeError('vocabulaire non ajuste')
        matrix = self.vectorizer.transform([normalise_description(v, self.markers) for v in (left, right)])
        return float(np.clip(matrix[0].multiply(matrix[1]).sum(), 0., 1.))

    def augment_pair(self, base_features, left, right):
        key = 'experimental_tfidf_description_cosine'
        if key in base_features: raise ValueError('caracteristique deja presente')
        return {**base_features, key: self.pair_similarity(left, right)}


def local_embedding_cosine(left, right, *, local_encoder, markers=()):
    """Encodeur local fourni explicitement ; aucun chargement ou téléchargement."""
    vectors = np.asarray(local_encoder.encode([normalise_description(v, markers) for v in (left, right)]), dtype=float)
    if vectors.ndim != 2 or vectors.shape[0] != 2 or vectors.shape[1] == 0 or not np.isfinite(vectors).all():
        raise ValueError('embeddings invalides')
    norm = np.linalg.norm(vectors, axis=1)
    if (norm == 0).any(): return 0.
    return float(np.clip(np.dot(vectors[0], vectors[1]) / (norm[0] * norm[1]), -1., 1.))
