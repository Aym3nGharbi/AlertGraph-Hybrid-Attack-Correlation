"""Micro-benchmark synthétique des générateurs; ne produit aucune donnée ML."""

from __future__ import annotations

import argparse
import json
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable

from .experimental_candidate_generators import corroborated_long_candidates, local_candidates, merge_candidates
from .io_utils import utc_now, write_new_json


def synthetic_metas(size: int, regime: str) -> list[dict[str, Any]]:
    if size <= 0 or regime not in {"partitioned", "noisy-hub"}:
        raise ValueError("taille positive et régime synthétique valide requis")
    rows = []
    for index in range(size):
        group = index % 20
        entities = [f"host:h{group}", f"ip:10.0.{group}.1", f"user:u{index % 50}"]
        if regime == "noisy-hub":
            entities.append("agent:synthetic-hub")
        rows.append({
            "meta_id": f"m-{index:06d}", "first_timestamp": float(index), "last_timestamp": float(index),
            "sensor": "wazuh:sshd" if index % 3 else "wazuh:syscheck_integrity_changed",
            "signature": f"wazuh:{5710 + index % 4}", "signature_text": f"synthetic observable rule {index % 4}",
            "entities": entities, "observed_stage": "LATERAL_MOVEMENT" if index % 2 else "DEFENSE_EVASION",
            "src_ips": [f"10.0.{group}.1"], "dst_ips": [], "protocols": ["tcp"], "services": ["ssh"],
        })
    return rows


def measure(factory: Callable[[], list[Any]]) -> dict[str, float | int]:
    tracemalloc.start(); started = time.perf_counter(); result = factory()
    runtime = (time.perf_counter() - started) * 1000; _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    return {"candidates": len(result), "runtime_ms": runtime, "peak_tracemalloc_kib": peak / 1024}


def benchmark(sizes: list[int]) -> dict[str, Any]:
    rows = []
    for regime in ("partitioned", "noisy-hub"):
        for size in sizes:
            metas = synthetic_metas(size, regime)
            baseline = measure(lambda: local_candidates(metas, 60, 50))
            conservative = measure(lambda: merge_candidates(
                local_candidates(metas, 60, 50),
                corroborated_long_candidates(metas, max_age=180, min_bundles=4, per_alert_cap=3),
            ))
            rows.append({"regime": regime, "meta_alerts": size, "baseline": baseline, "conservative": conservative})
    return {
        "schema_version": "alertgraph-candidate-generator-synthetic-scaling/2.0",
        "created_at_utc": utc_now(), "rows": rows,
        "synthetic_only": True, "real_experimental_result": False,
        "labels_used": False, "model_trained": False, "training_ready": False,
        "complexity_warning": "worst case remains quadratic when an entity is ubiquitous",
    }


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sizes", default="100,250,500")
    args = parser.parse_args(); sizes = [int(value) for value in args.sizes.split(",")]
    result = benchmark(sizes); write_new_json(args.output, result)
    print(json.dumps(result, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
