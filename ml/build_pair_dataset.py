#!/usr/bin/env python3
"""Construit un cache Parquet AIT-ADS séparant observations et vérité terrain."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from ait_dataset import iter_ait_scenario_chronological
from audit_pair_candidates import add_observable_context, collapse_labeled_records
from candidates import PairCandidate, iter_local_candidates
from causal_bridges import generate_causal_bridges
from pair_features import make_pair_example
from split_protocol import AIT_SCENARIOS


CACHE_VERSION = 2


def _combined_candidate(
    local: PairCandidate, causal: PairCandidate
) -> PairCandidate:
    return PairCandidate(
        earlier_meta_id=local.earlier_meta_id,
        later_meta_id=local.later_meta_id,
        delta_seconds=min(local.delta_seconds, causal.delta_seconds),
        shared_entities=tuple(
            sorted(set(local.shared_entities) | set(causal.shared_entities))
        ),
        source="causal-bridge+local-window",
    )


def _write_meta_tables(meta_alerts, target: Path) -> None:
    observable_rows = []
    truth_rows = []
    for item in meta_alerts:
        observable_rows.append(
            {
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
                "prior_entity_density_2s": item.prior_entity_density_2s,
                "prior_entity_density_10s": item.prior_entity_density_10s,
                "prior_entity_density_60s": item.prior_entity_density_60s,
                "prior_entity_density_150s": item.prior_entity_density_150s,
                "seconds_since_same_signature_entity": (
                    item.seconds_since_same_signature_entity
                ),
            }
        )
        truth_rows.append(
            {
                "meta_id": item.meta_id,
                "is_attack": item.is_attack,
                "attack_instance_id": item.attack_instance_id,
                "ground_truth_phases": list(item.ground_truth_phases),
                "truth_confidence": item.truth_confidence,
            }
        )
    pq.write_table(
        pa.Table.from_pylist(observable_rows),
        target / "meta_observable.parquet",
        compression="zstd",
    )
    pq.write_table(
        pa.Table.from_pylist(truth_rows),
        target / "meta_truth.parquet",
        compression="zstd",
    )


def _pair_row(scenario: str, candidate: PairCandidate, index) -> dict[str, object]:
    example = make_pair_example(
        index[candidate.earlier_meta_id],
        index[candidate.later_meta_id],
        candidate,
    )
    return {
        "scenario": scenario,
        "earlier_meta_id": example.earlier_meta_id,
        "later_meta_id": example.later_meta_id,
        "candidate_source": candidate.source,
        **example.features.to_dict(),
        "target": example.supervision.target,
        "label_confidence": example.supervision.confidence,
        "label_reason": example.supervision.reason,
    }


def _write_pair_rows(rows, destination: Path, batch_size: int = 50_000) -> int:
    writer = None
    batch = []
    total = 0
    try:
        for row in rows:
            batch.append(row)
            if len(batch) < batch_size:
                continue
            table = pa.Table.from_pylist(
                batch, schema=writer.schema if writer is not None else None
            )
            if writer is None:
                writer = pq.ParquetWriter(destination, table.schema, compression="zstd")
            writer.write_table(table)
            total += len(batch)
            batch.clear()
        if batch:
            table = pa.Table.from_pylist(
                batch, schema=writer.schema if writer is not None else None
            )
            if writer is None:
                writer = pq.ParquetWriter(destination, table.schema, compression="zstd")
            writer.write_table(table)
            total += len(batch)
    finally:
        if writer is not None:
            writer.close()
    return total


def build_scenario_cache(
    raw_archive: str | Path,
    compact_archive: str | Path,
    output_root: str | Path,
    scenario: str,
    collapse_seconds: float = 2.0,
    window_seconds: float = 60.0,
    cap: int = 50,
    max_causal_bridges: int = 5,
) -> dict[str, object]:
    target = Path(output_root) / scenario
    target.mkdir(parents=True, exist_ok=False)

    meta_alerts = add_observable_context(
        collapse_labeled_records(
            iter_ait_scenario_chronological(raw_archive, compact_archive, scenario),
            collapse_seconds,
        )
    )
    _write_meta_tables(meta_alerts, target)
    observable = [item.to_meta_alert() for item in meta_alerts]
    index = {item.meta_id: item for item in meta_alerts}
    causal = generate_causal_bridges(
        observable, max_bridges_per_alert=max_causal_bridges
    )
    remaining_causal = {
        (item.earlier_meta_id, item.later_meta_id): item for item in causal
    }

    def rows():
        for local in iter_local_candidates(observable, window_seconds, cap):
            key = (local.earlier_meta_id, local.later_meta_id)
            causal_match = remaining_causal.pop(key, None)
            candidate = (
                _combined_candidate(local, causal_match)
                if causal_match is not None
                else local
            )
            yield _pair_row(scenario, candidate, index)
        for key in sorted(remaining_causal):
            yield _pair_row(scenario, remaining_causal[key], index)

    pair_count = _write_pair_rows(rows(), target / "pair_examples.parquet")
    manifest = {
        "cache_version": CACHE_VERSION,
        "scenario": scenario,
        "parameters": {
            "collapse_seconds": collapse_seconds,
            "window_seconds": window_seconds,
            "cap": cap,
            "max_causal_bridges": max_causal_bridges,
        },
        "raw_alerts": sum(len(item.member_alert_ids) for item in meta_alerts),
        "meta_alerts": len(meta_alerts),
        "pair_examples": pair_count,
        "causal_candidates": len(causal),
        "files": {
            "meta_observable": "meta_observable.parquet",
            "meta_truth": "meta_truth.parquet",
            "pair_examples": "pair_examples.parquet",
        },
    }
    (target / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_archive")
    parser.add_argument("compact_archive")
    parser.add_argument("output_root")
    parser.add_argument("--scenarios", default=",".join(AIT_SCENARIOS))
    parser.add_argument("--collapse-seconds", type=float, default=2.0)
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--cap", type=int, default=50)
    parser.add_argument("--max-causal-bridges", type=int, default=5)
    args = parser.parse_args()

    scenarios = tuple(item.strip() for item in args.scenarios.split(",") if item.strip())
    manifests = []
    for scenario in scenarios:
        manifest = build_scenario_cache(
            args.raw_archive,
            args.compact_archive,
            args.output_root,
            scenario,
            args.collapse_seconds,
            args.window_seconds,
            args.cap,
            args.max_causal_bridges,
        )
        manifests.append(manifest)
        print(json.dumps(manifest, ensure_ascii=False), flush=True)

    output = Path(args.output_root)
    all_manifests = []
    for scenario_manifest in sorted(output.glob("*/manifest.json")):
        all_manifests.append(
            json.loads(scenario_manifest.read_text(encoding="utf-8"))
        )
    root_manifest = {
        "cache_version": CACHE_VERSION,
        "scenarios": all_manifests,
    }
    (output / "manifest.json").write_text(
        json.dumps(root_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
