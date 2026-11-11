"""Joint la supervision A1 vérifiée après compression et génération des candidats."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Mapping

import pyarrow.parquet as pq

from .io_utils import load_json, sha256_file, utc_now, write_new_bytes, write_new_json
from .prepare_campaign import verify_campaign_reservation
from .strict_verified_pairs import derive_verified_meta_truth, label_verified_candidates


PID = re.compile(r"sshd\[(\d+)\]")


def _jsonl(rows) -> bytes:
    return b"".join((json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for x in rows)


def finalize_a1(campaign_dir: str | Path, cache_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir); cache_dir = Path(cache_dir)
    manifest = verify_campaign_reservation(campaign_dir); plan = load_json(campaign_dir / "campaign-plan.json")
    activities = {str(x["activity_id"]): x for x in plan["activities"]}
    if len({x["attack_instance_id"] for x in activities.values()}) != 1:
        raise ValueError("A1 doit avoir une instance unique")
    raw_lines = (campaign_dir / "raw" / "alerts.jsonl").read_bytes().splitlines()
    events = {str(x["id"]): x for x in map(json.loads, raw_lines)}
    event_activity: dict[str, str] = {}; technical_identities = {}
    for activity in plan["activities"]:
        key = str(activity["activity_key"]); activity_id = str(activity["activity_id"])
        stage = load_json(campaign_dir / "stages" / key / "verification.json")
        ids = {str(x) for x in stage["wazuh_alert_ids"]}
        # Une fois le tuple/PID/BootId directement établi pour le succès,
        # les événements PAM du même PID ne sont acceptés que si leur message
        # existe octet pour octet dans la preuve journald conservée.
        if key == "a1-success":
            journal = [json.loads(x) for x in (campaign_dir / "stages" / key / "journal-pid.jsonl").read_bytes().splitlines()]
            messages = {str(x.get("MESSAGE") or "") for x in journal}
            pid = str(stage["sshd_pid"])
            for alert_id, event in events.items():
                match = PID.search(str(event.get("full_log") or ""))
                if match and match.group(1) == pid and any(m and m in str(event.get("full_log") or "") for m in messages):
                    ids.add(alert_id)
        for alert_id in ids:
            if alert_id not in events:
                raise ValueError(f"Alerte vérifiée absente du brut: {alert_id}")
            if alert_id in event_activity:
                raise ValueError(f"Alerte attribuée à plusieurs activités: {alert_id}")
            event_activity[alert_id] = activity_id
        technical_identities[activity_id] = {
            "attack_instance_id": activity["attack_instance_id"],
            "controller_tuple": stage["controller_tuple"], "sshd_pid": stage["sshd_pid"],
            "boot_id": stage["boot_id"], "wazuh_alert_ids": sorted(ids),
        }
    decisions = []
    for alert_id in events:
        activity_id = event_activity.get(alert_id)
        decisions.append({
            "wazuh_alert_id": alert_id,
            "decision": "member-verified" if activity_id else "excluded",
            "activity_id": activity_id,
            "attack_instance_id": activities[activity_id]["attack_instance_id"] if activity_id else None,
            "reason": "complete-independent-proof-chain" if activity_id else "no-preregistered-exclusive-identity",
            "ml_use": "verified-member" if activity_id else "excluded",
        })

    meta_rows = pq.read_table(cache_dir / "meta_observable.parquet").to_pylist()
    pair_rows = pq.read_table(cache_dir / "pair_examples.parquet").to_pylist()
    meta_truth, meta_excluded = derive_verified_meta_truth(meta_rows, event_activity, activities)
    labels, pair_excluded = label_verified_candidates(pair_rows, meta_truth)
    pair_index = {(str(x["earlier_meta_id"]), str(x["later_meta_id"])): x for x in pair_rows}
    analyses = []
    intra = inter = mixed = 0
    for label in labels:
        left = meta_truth[label["earlier_meta_id"]]; right = meta_truth[label["later_meta_id"]]
        left_activities = set(left["activity_ids"]); right_activities = set(right["activity_ids"])
        if left_activities == right_activities and len(left_activities) == 1:
            scope = "intra-activity"; intra += 1
        elif left_activities.isdisjoint(right_activities):
            scope = "inter-activities"; inter += 1
        else:
            scope = "overlapping-activity-provenance"; mixed += 1
        candidate = pair_index[(label["earlier_meta_id"], label["later_meta_id"])]
        analyses.append({**label, "relation_scope": scope,
                         "earlier_activity_ids": sorted(left_activities),
                         "later_activity_ids": sorted(right_activities),
                         "candidate_source": candidate.get("candidate_source")})

    output = campaign_dir / "supervision-a1-v2"
    write_new_bytes(output / "event-decisions.jsonl", _jsonl(decisions))
    write_new_bytes(output / "activity-identities.jsonl", _jsonl(
        [{"activity_id": k, **v} for k, v in technical_identities.items()]
    ))
    write_new_bytes(output / "meta-truth.jsonl", _jsonl(
        [{"meta_id": k, **v} for k, v in sorted(meta_truth.items())]
    ))
    write_new_bytes(output / "pair-truth.jsonl", _jsonl(analyses))
    write_new_json(output / "meta-excluded.json", meta_excluded)
    write_new_bytes(output / "pair-excluded.jsonl", _jsonl(pair_excluded))
    report = {
        "schema_version": "alertgraph-a1-supervision/2.0-experimental",
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "created_at_utc": utc_now(), "attack_instance_id": next(iter({x["attack_instance_id"] for x in activities.values()})),
        "raw_events": len(events), "member_verified": len(event_activity),
        "nonmember_verified": 0, "excluded_events": len(events) - len(event_activity),
        "meta_alerts": len(meta_rows), "verified_meta_alerts": len(meta_truth),
        "excluded_meta_alerts": len(meta_excluded), "candidate_pairs": len(pair_rows),
        "verified_positive_pairs": len(labels), "verified_negative_pairs": 0,
        "positive_intra_activity": intra, "positive_inter_activities": inter,
        "positive_overlapping_activity_provenance": mixed,
        "excluded_candidate_pairs": len(pair_excluded),
        "traceability_complete": sum(len(x["member_alert_ids"]) for x in meta_rows) == len(events),
        "supervision_fields_used_as_features": False, "training_ready": False,
        "files": {},
    }
    for name in ("event-decisions.jsonl", "activity-identities.jsonl", "meta-truth.jsonl",
                 "pair-truth.jsonl", "meta-excluded.json", "pair-excluded.jsonl"):
        report["files"][name] = sha256_file(output / name)
    write_new_json(output / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--cache-dir", required=True, type=Path); args = parser.parse_args()
    print(json.dumps(finalize_a1(args.campaign_dir, args.cache_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
