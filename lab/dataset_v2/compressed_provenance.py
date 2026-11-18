"""Contrôle des membres compressés avant toute supervision de candidats."""
import hashlib
import json
from pathlib import Path
import pyarrow.parquet as pq
from .io_utils import sha256_file, write_new_json
from .strict_verified_pairs import derive_verified_meta_truth


def audit_members(meta_rows, decisions, activities):
    decisions = list(decisions)
    by_id = {str(row["wazuh_alert_id"]): row for row in decisions}
    if len(by_id) != len(decisions):
        raise ValueError("décisions événementielles dupliquées")
    verified = {event_id: row["activity_id"] for event_id, row in by_id.items()
                if row.get("decision") == "member-verified" and row.get("activity_id") in activities
                and row.get("confidence", "verified") == "verified"
                and len((row.get("correlated_rule_context") or {}).get("context_identities") or []) <= 1}
    return derive_verified_meta_truth(list(meta_rows), verified, activities)


def audit_compressed_cache(campaign, cache, decisions, activities, *, output):
    campaign, cache, output = Path(campaign), Path(cache), Path(output)
    raw_path = campaign / "raw/alerts.jsonl"
    raw = {}; offset = 0
    for line_number, line in enumerate(raw_path.read_bytes().splitlines(keepends=True), 1):
        if line.strip():
            event_id = str(json.loads(line)["id"])
            if event_id in raw:
                raise ValueError("identifiant brut dupliqué")
            raw[event_id] = {"event_id": event_id, "line": line_number, "offset": offset,
                             "bytes": len(line), "sha256": hashlib.sha256(line).hexdigest()}
        offset += len(line)
    meta_path = cache / "meta_observable.parquet"
    rows = pq.read_table(meta_path).to_pylist()
    members = [str(i) for row in rows for i in row["member_alert_ids"]]
    if len(members) != len(set(members)) or set(members) != set(raw):
        raise ValueError("compression sans traçabilité complète et exclusive")
    if {str(d["wazuh_alert_id"]) for d in decisions} != set(raw):
        raise ValueError("décisions ne couvrant pas exactement les événements bruts")
    truth, excluded = audit_members(rows, decisions, activities)
    by_id = {str(d["wazuh_alert_id"]): d for d in decisions}
    receipt_hashes = {p.name: sha256_file(p) for p in (campaign / "receipts").glob("*.json")}
    report = {"raw_sha256": sha256_file(raw_path), "meta_cache_sha256": sha256_file(meta_path),
              "receipt_hashes": receipt_hashes, "collapse_seconds": 2.0,
              "verified_meta_count": len(truth), "excluded_meta_count": len(excluded),
              "meta_provenance": [{"meta_id": row["meta_id"],
                  "eligible": row["meta_id"] in truth, "truth": truth.get(row["meta_id"]),
                  "exclusion_reason": excluded.get(row["meta_id"]),
                  "members": [{**raw[str(i)], "attribution": by_id[str(i)]} for i in row["member_alert_ids"]]}
                  for row in rows], "training_ready": False}
    write_new_json(output, report)
    return report
