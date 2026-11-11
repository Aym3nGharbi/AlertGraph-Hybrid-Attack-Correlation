"""Vérité terrain pair-à-pair pour la corrélation d'alertes."""

from __future__ import annotations

from dataclasses import dataclass

from ait_labels import LabelDecision


@dataclass(frozen=True)
class PairLabel:
    target: int | None
    confidence: str
    reason: str


def make_pair_label(left: LabelDecision, right: LabelDecision) -> PairLabel:
    """Classe une paire sans inventer de relation pour les labels inconnus.

    ``target=1`` signifie même instance d'attaque. ``target=0`` signifie que la
    paire ne peut pas appartenir à la même attaque. ``None`` exclut la paire du
    supervisé tant qu'aucune vérité terrain plus fiable n'est disponible.
    """

    if left.is_attack is None or right.is_attack is None:
        return PairLabel(None, "unknown", "unknown-alert-label")

    confidence = (
        "high"
        if left.label_confidence == right.label_confidence == "high"
        else "weak"
    )

    if left.is_attack and right.is_attack:
        if not left.attack_instance_id or not right.attack_instance_id:
            return PairLabel(None, "unknown", "missing-attack-instance")
        if left.attack_instance_id == right.attack_instance_id:
            return PairLabel(1, confidence, "same-attack-instance")
        return PairLabel(0, confidence, "different-attack-instances")

    if left.is_attack != right.is_attack:
        return PairLabel(0, confidence, "attack-versus-benign")

    return PairLabel(0, confidence, "benign-pair")

