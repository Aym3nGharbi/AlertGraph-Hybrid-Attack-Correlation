"""Réévalue l'appartenance événement–activité avec un graphe de preuves exactes."""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Mapping

from .io_utils import canonical_json_bytes, load_json, sha256_bytes, sha256_file, utc_now, write_new_bytes, write_new_json
from .membership_supervision import MEMBER, UNRESOLVED, validate_membership_decisions
from .prepare_campaign import verify_campaign_reservation
from .validators import validate_bundle


REVIEW_DIR = "membership-review-evidence-graph-v2"


def _jsonl(items: list[Mapping[str, object]]) -> bytes:
    return b"".join((json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for x in items)


def _win(event: Mapping[str, object]) -> tuple[Mapping[str, object], Mapping[str, object]]:
    data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
    win = data.get("win") if isinstance(data.get("win"), Mapping) else {}
    return (
        win.get("system") if isinstance(win.get("system"), Mapping) else {},
        win.get("eventdata") if isinstance(win.get("eventdata"), Mapping) else {},
    )


def _evidence(*, evidence_id: str, manifest: Mapping[str, object], activity_id: str,
              kind: str, source: str, payload: object, alert_id: str, now: str) -> dict[str, object]:
    return {
        "schema_version": "alertgraph-evidence/2.0", "evidence_id": evidence_id,
        "campaign_id": manifest["campaign_id"], "run_id": manifest["run_id"],
        "activity_id": activity_id, "kind": kind, "recorded_at_utc": now,
        "source": source, "payload_sha256": sha256_bytes(canonical_json_bytes(payload)),
        "observed_in_alert_ids": [alert_id],
    }


def _decision(*, alert_id: str, decision: str, activity_id: str | None,
              evidence_ids: list[str], proof_families: list[str], relation_keys: dict[str, object],
              reason_codes: list[str], explanation: str, ml_use: str, now: str) -> dict[str, object]:
    return {
        "schema_version": "alertgraph-membership-decision/2.0",
        "decision_id": f"membership:{alert_id}:evidence-graph-v2",
        "wazuh_alert_id": alert_id, "decision": decision, "activity_id": activity_id,
        "other_activity_id": None, "evidence_ids": evidence_ids,
        "proof_families": proof_families, "relation_keys": relation_keys,
        "reason_codes": reason_codes, "explanation": explanation,
        "ml_use": ml_use, "created_at_utc": now,
    }


def _promote(annotation: dict[str, object], evidence_ids: list[str], now: str,
             revisions: list[dict[str, object]], reason: str,
             *, activity_id: str, benign_activity_id: str) -> None:
    before = {"confidence": annotation["confidence"], "class": annotation["class"],
              "activity_id": annotation["activity_id"], "evidence_ids": list(annotation["evidence_ids"])}
    annotation.update({
        "class": "benign", "confidence": "verified", "evidence_ids": evidence_ids,
        "activity_id": activity_id, "benign_activity_id": benign_activity_id,
        "review_status": "accepted", "reviewer_id": "automatic-evidence-graph-review-v2",
        "reviewed_at_utc": now, "annotation_source": "evidence-graph-membership-review-v2",
        "revision": 2,
    })
    revisions.append({
        "schema_version": "alertgraph-annotation-revision/2.0",
        "revision_id": f"revision:{annotation['annotation_id']}:2",
        "annotation_id": annotation["annotation_id"], "revision": 2,
        "previous_revision_id": None, "created_at_utc": now,
        "reviewer_id": "automatic-evidence-graph-review-v2", "reason": reason,
        "changes": {"before": before, "after": {"confidence": "verified", "class": "benign",
                                                       "activity_id": annotation["activity_id"],
                                                       "evidence_ids": evidence_ids}},
    })


def _review_ssh(campaign_dir: Path, manifest: Mapping[str, object], bundle: Mapping[str, object], now: str):
    activities = bundle["activities"]; activity = activities[0]; activity_id = str(activity["activity_id"])
    annotations = deepcopy(bundle["annotations"]); by_alert = {str(x["wazuh_alert_id"]): x for x in annotations}
    events = bundle["raw_events"]
    journal_path = next((campaign_dir / "supplementary").glob("linux-journal-pid-*.jsonl"))
    journal_lines = journal_path.read_bytes().splitlines(keepends=True)
    journal = [(json.loads(line), line) for line in journal_lines]
    boot_ids = {str(x.get("_BOOT_ID")) for x, _ in journal}; pids = {str(x.get("_PID")) for x, _ in journal}
    if len(boot_ids) != 1 or len(pids) != 1:
        raise ValueError("La chaîne journald ne possède pas une identité de processus unique")
    boot_id, pid = next(iter(boot_ids)), next(iter(pids))
    anchor = next(x for x in events if str((x.get("rule") or {}).get("id")) == "5715")
    anchor_id = str(anchor["id"]); anchor_annotation = by_alert[anchor_id]
    additions=[]; revisions=[]; decisions=[]
    for event in events:
        alert_id=str(event["id"]); annotation=by_alert[alert_id]
        full_log=str(event.get("full_log") or "")
        matches=[(entry,line) for entry,line in journal if str(entry.get("MESSAGE") or "") in full_log]
        if len(matches) != 1:
            decisions.append(_decision(
                alert_id=alert_id, decision=UNRESOLVED, activity_id=None, evidence_ids=[],
                proof_families=["wazuh-transport"], relation_keys={},
                reason_codes=["journal-entry-not-uniquely-matched"],
                explanation="Aucune entrée journald unique ne relie cet événement à l'ancre.",
                ml_use="excluded-unresolved", now=now)); continue
        entry,line=matches[0]
        if alert_id == anchor_id:
            decisions.append(_decision(
                alert_id=alert_id, decision=MEMBER, activity_id=activity_id,
                evidence_ids=list(anchor_annotation["evidence_ids"]),
                proof_families=["execution-receipt","controller-network","linux-journal","wazuh-transport"],
                relation_keys={"boot_id":boot_id,"pid":pid,"cursor":str(entry.get("__CURSOR"))},
                reason_codes=["exact-ssh-tuple-anchor"],
                explanation="Le tuple SSH du reçu correspond exactement à l'authentification cible.",
                ml_use="verified-benign-negative-only", now=now)); continue
        identity_id=f"evidence:{activity_id}:membership-path:{alert_id}"
        technical_id=f"evidence:{activity_id}:journal-process-instance:{alert_id}"
        additions.extend([
            _evidence(evidence_id=identity_id,manifest=manifest,activity_id=activity_id,
                      kind="artifact-identity",source="evidence-graph:receipt->ssh-tuple->boot-id+pid",
                      payload={"anchor_alert_id":anchor_id,"boot_id":boot_id,"pid":pid,
                               "anchor_cursor":next(str(x.get("__CURSOR")) for x,_ in journal if str(x.get("MESSAGE")) in str(anchor.get("full_log"))),
                               "linked_cursor":str(entry.get("__CURSOR"))},alert_id=alert_id,now=now),
            _evidence(evidence_id=technical_id,manifest=manifest,activity_id=activity_id,
                      kind="process-lineage",source="target-journald:boot-id+pid+cursor",
                      payload={"boot_id":boot_id,"pid":pid,"cursor":str(entry.get("__CURSOR")),
                               "monotonic_timestamp":str(entry.get("__MONOTONIC_TIMESTAMP")),
                               "journal_line_sha256":hashlib.sha256(line).hexdigest()},alert_id=alert_id,now=now),
        ])
        _promote(annotation,[identity_id,technical_id],now,revisions,
                 "Le même processus sshd est borné par BootId+PID et relié à l'ancre au tuple réseau exact.",
                 activity_id=activity_id, benign_activity_id=str(activity["benign_activity_id"]))
        decisions.append(_decision(
            alert_id=alert_id, decision=MEMBER, activity_id=activity_id,
            evidence_ids=[identity_id,technical_id],
            proof_families=["execution-receipt","controller-network","linux-journal","wazuh-transport"],
            relation_keys={"boot_id":boot_id,"pid":pid,"cursor":str(entry.get("__CURSOR"))},
            reason_codes=["exact-journal-process-instance-chain"],
            explanation="L'événement appartient au même processus sshd que l'ancre authentifiée.",
            ml_use="verified-benign-negative-only", now=now))
    return annotations, additions, revisions, decisions, {"journal_path":str(journal_path.relative_to(campaign_dir)),"journal_sha256":sha256_file(journal_path)}


def _review_windows(campaign_dir: Path, manifest: Mapping[str, object], bundle: Mapping[str, object], now: str):
    activity=bundle["activities"][0];activity_id=str(activity["activity_id"])
    annotations=deepcopy(bundle["annotations"]);by_alert={str(x["wazuh_alert_id"]):x for x in annotations};events=bundle["raw_events"]
    anchor=next(x for x in events if str((x.get("rule") or {}).get("id"))=="92052")
    anchor_id=str(anchor["id"]);_,anchor_data=_win(anchor)
    anchor_logon=str(anchor_data.get("logonId") or "").lower();parent_guid=str(anchor_data.get("parentProcessGuid") or "").lower();parent_pid=str(anchor_data.get("parentProcessId") or "")
    additions=[];revisions=[];decisions=[]
    for event in events:
        alert_id=str(event["id"]);annotation=by_alert[alert_id];system,data=_win(event);event_id=str(system.get("eventID") or "")
        relation=None;technical_kind=None;reason=None;keys={}
        if alert_id==anchor_id:
            decisions.append(_decision(alert_id=alert_id,decision=MEMBER,activity_id=activity_id,
                evidence_ids=list(annotation["evidence_ids"]),proof_families=["execution-receipt","windows-sysmon","wazuh-transport"],
                relation_keys={"process_guid":str(anchor_data.get("processGuid")),"process_id":str(anchor_data.get("processId"))},
                reason_codes=["exact-marker-pid-process-anchor"],explanation="Le marqueur, le PID, l'utilisateur et l'image correspondent au reçu WinRM.",
                ml_use="verified-benign-negative-only",now=now));continue
        if event_id=="4624" and str(data.get("targetLogonId") or "").lower()==anchor_logon:
            relation="sysmon-logonid-to-security-targetlogonid";technical_kind="authentication-telemetry";reason="exact-anchored-logon-session";keys={"logon_id":anchor_logon}
        elif event_id=="4634" and str(data.get("targetLogonId") or "").lower()==anchor_logon:
            relation="anchored-logonid-to-security-logoff";technical_kind="authentication-telemetry";reason="exact-anchored-logoff-session";keys={"logon_id":anchor_logon}
        elif event_id=="7" and str(data.get("processGuid") or "").lower()==parent_guid and str(data.get("processId") or "")==parent_pid:
            relation="child-parent-processguid-pid";technical_kind="file-telemetry";reason="exact-parent-process-instance";keys={"process_guid":parent_guid,"process_id":parent_pid}
        if relation:
            identity_id=f"evidence:{activity_id}:membership-path:{alert_id}";technical_id=f"evidence:{activity_id}:target-telemetry:{alert_id}"
            additions.extend([
                _evidence(evidence_id=identity_id,manifest=manifest,activity_id=activity_id,kind="artifact-identity",
                          source="evidence-graph:winrm-receipt->sysmon-anchor->exact-identity",
                          payload={"anchor_alert_id":anchor_id,"relation":relation,"keys":keys},alert_id=alert_id,now=now),
                _evidence(evidence_id=technical_id,manifest=manifest,activity_id=activity_id,kind=technical_kind,
                          source="wazuh-raw:"+("windows-security" if event_id in {"4624","4634"} else "windows-sysmon"),
                          payload={"event_id":event_id,"record_id":str(system.get("eventRecordID")),"keys":keys},alert_id=alert_id,now=now),
            ])
            _promote(annotation,[identity_id,technical_id],now,revisions,
                     "Identifiant exact propagé depuis le processus WinRM ancré par reçu.",
                     activity_id=activity_id, benign_activity_id=str(activity["benign_activity_id"]))
            families=["execution-receipt","windows-sysmon","wazuh-transport"]
            if event_id in {"4624","4634"}:families.append("windows-security")
            decisions.append(_decision(alert_id=alert_id,decision=MEMBER,activity_id=activity_id,
                evidence_ids=[identity_id,technical_id],proof_families=families,relation_keys=keys,
                reason_codes=[reason],explanation="Relation exacte dans la chaîne WinRM ancrée.",
                ml_use="verified-benign-negative-only",now=now))
        else:
            keys={k:str(data.get(k)) for k in ("targetLogonId","processGuid","processId") if data.get(k) is not None}
            reason_codes=["observable-identity-not-connected-to-activity-anchor"]
            if event_id in {"4624","4634"}:reason_codes.append("unanchored-logon-session")
            decisions.append(_decision(alert_id=alert_id,decision=UNRESOLVED,activity_id=None,evidence_ids=[],
                proof_families=["windows-security" if event_id in {"4624","4634"} else "windows-sysmon","wazuh-transport"],
                relation_keys=keys,reason_codes=reason_codes,
                explanation="L'identité technique est observable mais aucun chemin exact ne la relie au reçu de l'activité.",
                ml_use="excluded-unresolved",now=now))
    return annotations,additions,revisions,decisions,{}


def review_activity_membership(campaign_dir: str | Path, *, platform: str) -> dict[str, object]:
    campaign_dir=Path(campaign_dir);manifest=verify_campaign_reservation(campaign_dir)
    if manifest["partition"]!="development":raise PermissionError("La revue exige development")
    review_dir=campaign_dir/REVIEW_DIR
    if review_dir.exists():raise FileExistsError("La revue d'appartenance existe déjà")
    original=load_json(campaign_dir/"association"/"validation-bundle.json");now=utc_now()
    if platform=="ssh": annotations,additions,revisions,decisions,extra=_review_ssh(campaign_dir,manifest,original,now)
    elif platform=="windows": annotations,additions,revisions,decisions,extra=_review_windows(campaign_dir,manifest,original,now)
    else:raise ValueError("Plateforme attendue: ssh ou windows")
    evidence=[*original["evidence"],*additions]
    bundle={**original,"evidence":evidence,"annotations":annotations,"revisions":[*original.get("revisions",[]),*revisions]}
    validate_bundle(bundle,base_dir=campaign_dir)
    validate_membership_decisions(decisions,raw_alert_ids={str(x["id"]) for x in original["raw_events"]},
                                  activity_ids={str(x["activity_id"]) for x in original["activities"]},
                                  evidence_ids={str(x["evidence_id"]) for x in evidence})
    write_new_bytes(review_dir/"evidence-additions.jsonl",_jsonl(additions));write_new_bytes(review_dir/"annotations.jsonl",_jsonl(annotations))
    write_new_bytes(review_dir/"revisions.jsonl",_jsonl(revisions));write_new_bytes(review_dir/"membership-decisions.jsonl",_jsonl(decisions))
    write_new_json(review_dir/"validation-bundle.json",bundle)
    old_counts={k:sum(x["confidence"]==k for x in original["annotations"]) for k in ("verified","weak","unknown","conflict")}
    new_counts={k:sum(x["confidence"]==k for x in annotations) for k in ("verified","weak","unknown","conflict")}
    report={"schema_version":"alertgraph-membership-review/2.0-experimental","campaign_id":manifest["campaign_id"],"run_id":manifest["run_id"],
            "created_at_utc":now,"method":"deterministic-evidence-graph-v2","old_annotation_counts":old_counts,"new_annotation_counts":new_counts,
            "member_verified":sum(x["decision"]==MEMBER for x in decisions),"independent_verified":0,
            "unresolved":sum(x["decision"]==UNRESOLVED for x in decisions),"cross_associations":0,"training_ready":False,"extra_provenance":extra,
            "files":{name:sha256_file(review_dir/name) for name in ("evidence-additions.jsonl","annotations.jsonl","revisions.jsonl","membership-decisions.jsonl","validation-bundle.json")}}
    write_new_json(review_dir/"review-manifest.json",report);return report


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("campaign_dir",type=Path);parser.add_argument("--platform",choices=("ssh","windows"),required=True);args=parser.parse_args()
    print(json.dumps(review_activity_membership(args.campaign_dir,platform=args.platform),ensure_ascii=False,indent=2))


if __name__=="__main__":main()
