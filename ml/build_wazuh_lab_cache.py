#!/usr/bin/env python3
"""Construit un cache d'inférence Wazuh identique aux caches expérimentaux."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from audit_pair_candidates import add_observable_context, collapse_labeled_records
from build_pair_dataset import _combined_candidate
from candidates import iter_local_candidates
from causal_bridges import generate_causal_bridges
from graph_context import GRAPH_CONTEXT_FEATURE_NAMES, pair_graph_context, predecessor_index
from pair_features import make_pair_example
from traceability import audit_traceability, require_complete_traceability
from wazuh_dataset import iter_wazuh_jsonl, load_stage_mapping, mapping_audit


def build_cache(
    input_path: Path,
    output_root: Path,
    run_id: str,
    mapping_path: Path,
    *,
    collapse_seconds: float = 2.0,
    window_seconds: float = 60.0,
    cap: int = 50,
    max_causal_bridges: int = 5,
) -> dict[str, object]:
    target = output_root / run_id
    target.mkdir(parents=True, exist_ok=False)
    mapping = load_stage_mapping(mapping_path)
    records = list(iter_wazuh_jsonl(input_path, mapping, run_id=run_id))
    records.sort(key=lambda item: (item.timestamp, item.alert_id))
    audit = mapping_audit(records)
    meta = add_observable_context(collapse_labeled_records(records, collapse_seconds))
    traceability = audit_traceability(
        (item.alert_id for item in records),
        (item.member_alert_ids for item in meta),
    )
    require_complete_traceability(traceability)
    observable = [item.to_meta_alert() for item in meta]
    index = {item.meta_id: item for item in meta}

    observable_rows = []
    raw_by_id = {item.alert_id: item for item in records}
    for item in meta:
        observable_rows.append({
            "meta_id": item.meta_id,
            "first_timestamp": item.first_timestamp,
            "last_timestamp": item.last_timestamp,
            "sensor": item.sensor,
            "signature": item.signature,
            "signature_text": item.signature_text,
            "entities": list(item.entities),
            "member_alert_ids": list(item.member_alert_ids),
            "observed_stage": item.observed_stage,
            "protocols": list(item.protocols),
            "services": list(item.services),
            "observed_tactics": list(item.observed_tactics),
            "src_ips": list(item.src_ips),
            "dst_ips": list(item.dst_ips),
            "min_severity": item.min_severity,
            "max_severity": item.max_severity,
            "rule_description": item.signature_text,
            "agent_names": sorted({raw_by_id[x].host for x in item.member_alert_ids if raw_by_id[x].host}),
            "prior_entity_density_2s": item.prior_entity_density_2s,
            "prior_entity_density_10s": item.prior_entity_density_10s,
            "prior_entity_density_60s": item.prior_entity_density_60s,
            "prior_entity_density_150s": item.prior_entity_density_150s,
            "seconds_since_same_signature_entity": item.seconds_since_same_signature_entity,
        })
    pq.write_table(pa.Table.from_pylist(observable_rows), target / "meta_observable.parquet", compression="zstd")

    causal = generate_causal_bridges(observable, max_bridges_per_alert=max_causal_bridges)
    remaining = {(x.earlier_meta_id, x.later_meta_id): x for x in causal}
    pair_rows = []
    for local in iter_local_candidates(observable, window_seconds, cap):
        key = (local.earlier_meta_id, local.later_meta_id)
        bridge = remaining.pop(key, None)
        candidate = _combined_candidate(local, bridge) if bridge else local
        example = make_pair_example(index[candidate.earlier_meta_id], index[candidate.later_meta_id], candidate)
        pair_rows.append({
            "run_id": run_id,
            "earlier_meta_id": example.earlier_meta_id,
            "later_meta_id": example.later_meta_id,
            "candidate_source": candidate.source,
            **example.features.to_dict(),
        })
    for key in sorted(remaining):
        candidate = remaining[key]
        example = make_pair_example(index[candidate.earlier_meta_id], index[candidate.later_meta_id], candidate)
        pair_rows.append({
            "run_id": run_id,
            "earlier_meta_id": example.earlier_meta_id,
            "later_meta_id": example.later_meta_id,
            "candidate_source": candidate.source,
            **example.features.to_dict(),
        })
    predecessors = predecessor_index(
        (row["earlier_meta_id"], row["later_meta_id"]) for row in pair_rows
    )
    for row in pair_rows:
        values = pair_graph_context(
            row["earlier_meta_id"], row["later_meta_id"], predecessors
        )
        row.update(dict(zip(GRAPH_CONTEXT_FEATURE_NAMES, values)))
    if pair_rows:
        pq.write_table(pa.Table.from_pylist(pair_rows), target / "pair_examples.parquet", compression="zstd")
    else:
        pq.write_table(pa.table({"run_id": pa.array([], type=pa.string())}), target / "pair_examples.parquet")

    manifest = {
        "kind": "wazuh-lab-inference-cache",
        "run_id": run_id,
        "input": str(input_path),
        "parameters": {
            "collapse_seconds": collapse_seconds,
            "window_seconds": window_seconds,
            "cap": cap,
            "max_causal_bridges": max_causal_bridges,
        },
        "raw_alerts": len(records),
        "meta_alerts": len(meta),
        "pair_candidates": len(pair_rows),
        "causal_candidates": len(causal),
        "mapping_audit": audit,
        "traceability": traceability,
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("run_id")
    parser.add_argument("--mapping", type=Path, default=Path("config/wazuh-stage-mapping.json"))
    parser.add_argument("--collapse-seconds", type=float, default=2.0)
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--cap", type=int, default=50)
    args = parser.parse_args()
    print(json.dumps(build_cache(args.input, args.output_root, args.run_id, args.mapping, collapse_seconds=args.collapse_seconds, window_seconds=args.window_seconds, cap=args.cap), indent=2))


if __name__ == "__main__":
    main()
