"""Vérité terrain V2 stricte après compression observable.

La supervision est jointe après la compression et après la génération des
candidats. Elle n'est jamais ajoutée aux caractéristiques ML.
"""

from __future__ import annotations

from typing import Iterable, Mapping


def derive_verified_meta_truth(
    meta_rows: Iterable[Mapping[str, object]],
    event_activity: Mapping[str, str],
    activities: Mapping[str, Mapping[str, object]],
) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
    """Retourne les méta-labels vérifiés et les exclusions justifiées."""

    verified: dict[str, dict[str, object]] = {}
    excluded: dict[str, str] = {}
    for meta in meta_rows:
        meta_id = str(meta["meta_id"])
        members = [str(x) for x in meta.get("member_alert_ids", [])]
        if not members or any(alert_id not in event_activity for alert_id in members):
            excluded[meta_id] = "unverified-member-event"
            continue
        activity_ids = {event_activity[x] for x in members}
        activity_rows = [activities.get(x) for x in activity_ids]
        if any(x is None for x in activity_rows):
            excluded[meta_id] = "unknown-activity"
            continue
        truth_keys = set()
        for activity in activity_rows:
            assert activity is not None
            label_class = str(activity.get("class"))
            if label_class == "attack" and activity.get("attack_instance_id"):
                truth_keys.add(("attack", str(activity["attack_instance_id"])))
            elif label_class == "benign" and activity.get("benign_activity_id"):
                truth_keys.add(("benign", str(activity["benign_activity_id"])))
            else:
                truth_keys.add(("invalid", ""))
        if len(truth_keys) != 1 or next(iter(truth_keys))[0] == "invalid":
            excluded[meta_id] = "mixed-or-invalid-provenance"
            continue
        label_class, identity = next(iter(truth_keys))
        verified[meta_id] = {
            "class": label_class,
            "attack_instance_id": identity if label_class == "attack" else None,
            "benign_activity_id": identity if label_class == "benign" else None,
            "member_alert_ids": members,
            "activity_ids": sorted(activity_ids),
            "confidence": "verified",
        }
    return verified, excluded


def label_verified_candidates(
    candidates: Iterable[Mapping[str, object]],
    meta_truth: Mapping[str, Mapping[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    """Étiquette uniquement les candidats dont les deux extrémités sont vérifiées."""

    labels: list[dict[str, object]] = []
    excluded: list[dict[str, str]] = []
    for candidate in candidates:
        left_id = str(candidate["earlier_meta_id"]); right_id = str(candidate["later_meta_id"])
        left = meta_truth.get(left_id); right = meta_truth.get(right_id)
        if left is None or right is None:
            excluded.append({"earlier_meta_id": left_id, "later_meta_id": right_id, "reason": "unverified-endpoint"})
            continue
        left_class, right_class = left["class"], right["class"]
        if left_class == right_class == "attack":
            same = left["attack_instance_id"] == right["attack_instance_id"]
            target = 1 if same else 0
            reason = "same-verified-attack-instance" if same else "different-verified-attack-instances"
        elif {left_class, right_class} == {"attack", "benign"}:
            target = 0; reason = "verified-attack-versus-benign"
        else:
            excluded.append({"earlier_meta_id": left_id, "later_meta_id": right_id, "reason": "benign-benign-not-supervised"})
            continue
        labels.append({
            "schema_version": "alertgraph-verified-pair-label/2.0",
            "earlier_meta_id": left_id, "later_meta_id": right_id,
            "target": target, "label_reason": reason, "confidence": "verified",
        })
    return labels, excluded


def conditional_pair_estimate(
    attack_meta_counts: Mapping[str, int], benign_meta_count: int
) -> dict[str, int]:
    """Estimation combinatoire conditionnelle, avant filtrage par candidats."""

    counts = list(attack_meta_counts.values())
    positives = sum(n * (n - 1) // 2 for n in counts)
    different_attacks = sum(counts[i] * counts[j] for i in range(len(counts)) for j in range(i + 1, len(counts)))
    attack_benign = sum(counts) * benign_meta_count
    return {
        "conditional_positive_pairs_before_candidate_filter": positives,
        "conditional_negative_different_attack_pairs_before_candidate_filter": different_attacks,
        "conditional_negative_attack_benign_pairs_before_candidate_filter": attack_benign,
        "conditional_total_negative_pairs_before_candidate_filter": different_attacks + attack_benign,
    }
