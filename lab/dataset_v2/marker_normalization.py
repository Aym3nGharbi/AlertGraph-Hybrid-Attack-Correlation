"""Neutralise les marqueurs de supervision dans les textes dérivés uniquement.

Le JSON Wazuh brut ne doit jamais passer par ces fonctions. La normalisation
s'applique à une copie destinée aux caractéristiques textuelles.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping


MARKER_TOKEN = "instrumentation_marker"

# Ces champs peuvent être conservés dans les tables de vérité ou les manifestes,
# mais ne doivent jamais apparaître dans un dictionnaire de caractéristiques ML.
SUPERVISION_ONLY_FIELDS = frozenset(
    {
        "campaign_id",
        "run_id",
        "attack_instance_id",
        "activity_id",
        "benign_activity_id",
        "marker_id",
        "marker_ids",
        "confidence",
        "label_confidence",
        "label_conflict",
        "annotation_source",
        "evidence_ids",
        "review_status",
        "partition",
        "target",
        "label_reason",
    }
)

# Format réservé aux futurs orchestrateurs V2. Il permet une défense en
# profondeur même si la liste explicite des marqueurs n'est pas transmise.
_GENERIC_MARKER = re.compile(r"(?i)\bagv2[-_:][a-z0-9][a-z0-9_-]{7,}\b")


def normalize_instrumentation_markers(
    text: str,
    marker_values: Iterable[str] = (),
) -> str:
    """Remplace les marqueurs connus dans une copie de texte observable.

    Les remplacements sont insensibles à la casse et effectués du marqueur le
    plus long au plus court pour éviter les remplacements partiels.
    """

    result = str(text)
    values = sorted(
        {str(value).strip() for value in marker_values if str(value).strip()},
        key=len,
        reverse=True,
    )
    if values:
        explicit = re.compile(
            "|".join(re.escape(value) for value in values), re.IGNORECASE
        )
        result = explicit.sub(MARKER_TOKEN, result)
    return _GENERIC_MARKER.sub(MARKER_TOKEN, result)


def assert_feature_record_has_no_supervision(
    feature_record: Mapping[str, object],
    *,
    forbidden_values: Iterable[str] = (),
) -> None:
    """Refuse les champs ou valeurs de supervision dans un vecteur ML."""

    forbidden_fields = sorted(set(feature_record) & SUPERVISION_ONLY_FIELDS)
    if forbidden_fields:
        raise ValueError(
            "Champs de supervision interdits dans les caractéristiques: "
            + ", ".join(forbidden_fields)
        )

    needles = {
        str(value).casefold()
        for value in forbidden_values
        if str(value).strip()
    }
    if not needles:
        return
    for name, value in feature_record.items():
        if not isinstance(value, str):
            continue
        folded = value.casefold()
        leaked = sorted(needle for needle in needles if needle in folded)
        if leaked:
            raise ValueError(
                f"Valeur de supervision détectée dans la caractéristique {name!r}"
            )
