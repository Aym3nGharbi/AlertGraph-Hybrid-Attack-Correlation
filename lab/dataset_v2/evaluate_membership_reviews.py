"""Compare reproductiblement les annotations historiques et les revues V2."""

from __future__ import annotations

import argparse
import json
from itertools import combinations
from pathlib import Path

from .io_utils import load_json, utc_now, write_new_json
from .review_activity_membership import REVIEW_DIR


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def evaluate(campaign_dirs: list[Path], output: Path) -> dict[str, object]:
    campaigns=[]; assignments: dict[str, str] = {}; cross=[]; activity_members: dict[str, set[str]]={}
    for campaign in campaign_dirs:
        review=campaign/REVIEW_DIR
        manifest=load_json(review/"review-manifest.json")
        decisions=_jsonl(review/"membership-decisions.jsonl")
        raw=_jsonl(campaign/"raw"/"alerts.jsonl")
        raw_by_id={str(x["id"]):x for x in raw}
        member=[x for x in decisions if x["decision"]=="member-verified"]
        diversity=[]
        for item in member:
            event=raw_by_id[str(item["wazuh_alert_id"])]
            win=((event.get("data") or {}).get("win") or {})
            system=win.get("system") or {}
            diversity.append({"rule_id":str((event.get("rule") or {}).get("id")),
                              "event_id":str(system.get("eventID")) if system.get("eventID") is not None else None})
            alert_id=str(item["wazuh_alert_id"]);activity_id=str(item["activity_id"])
            if alert_id in assignments and assignments[alert_id]!=activity_id:
                cross.append({"alert_id":alert_id,"activities":[assignments[alert_id],activity_id]})
            assignments[alert_id]=activity_id;activity_members.setdefault(activity_id,set()).add(alert_id)
        campaigns.append({
            "campaign_id":manifest["campaign_id"],"old_counts":manifest["old_annotation_counts"],
            "new_counts":manifest["new_annotation_counts"],"total_events":len(raw),
            "member_verified":len(member),"independent_verified":sum(x["decision"]=="independent-verified" for x in decisions),
            "unresolved":sum(x["decision"]=="unresolved" for x in decisions),
            "verified_coverage":len(member)/len(raw) if raw else 0.0,
            "verified_event_diversity":sorted({(x["rule_id"],x["event_id"]) for x in diversity}),
        })
    potential_negative=sum(len(activity_members[a])*len(activity_members[b]) for a,b in combinations(activity_members,2))
    report={
        "schema_version":"alertgraph-membership-comparison/2.0-experimental",
        "created_at_utc":utc_now(),"method":"deterministic-evidence-graph-v2",
        "campaigns":campaigns,
        "aggregate":{
            "events":sum(x["total_events"] for x in campaigns),
            "old_verified":sum(x["old_counts"]["verified"] for x in campaigns),
            "new_member_verified":sum(x["member_verified"] for x in campaigns),
            "independent_verified":sum(x["independent_verified"] for x in campaigns),
            "unresolved":sum(x["unresolved"] for x in campaigns),
            "cross_associations":len(cross),
            "potential_verified_benign_negative_pairs_before_candidate_filter":potential_negative,
            "verified_attack_positive_pairs":0,
        },
        "cross_association_details":cross,
        "training_ready":False,
        "limitations":[
            "all campaigns are benign development data",
            "potential benign negatives still require the normal candidate-generation protocol",
            "no positive same-attack pair exists",
            "unresolved events are excluded rather than converted to negatives",
        ],
    }
    write_new_json(output,report);return report


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("output",type=Path);parser.add_argument("campaign_dirs",nargs="+",type=Path);args=parser.parse_args()
    print(json.dumps(evaluate(args.campaign_dirs,args.output),ensure_ascii=False,indent=2))


if __name__=="__main__":main()
