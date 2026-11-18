"""Générateurs candidats V2 expérimentaux, séparés du pipeline opérationnel."""

from __future__ import annotations

import argparse
import json
import math
import re
import time
import tracemalloc
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from statistics import mean, median
from typing import Any, Callable, Iterable

import pyarrow.parquet as pq

from .io_utils import load_json, utc_now, write_new_bytes, write_new_json
from .long_transition_audit import connected_components, relation_scope


TOKEN = re.compile(r"[a-z0-9]+")
ACCESS = {"BRUTE_FORCE_CREDS", "PUBLIC_APP_EXP", "REMOTE_SERVICE_EXP", "SERVICE_SPECIFIC", "VALID_ACCOUNT_ACCESS"}
POST_ACCESS = {"USER_PRIV_ESC", "ROOT_PRIV_ESC", "PRIV_ESC", "ARBITRARY_CODE_EXE", "PERSISTENCE"}
CONTROL = {"DEFENSE_EVASION", "COMMAND_AND_CONTROL", "LATERAL_MOVEMENT"}
OUTCOME = {"DATA_EXFILTRATION", "SERVICE_STOP", "NETWORK_DOS", "END_POINT_DOS"}
DISCOVERY = {"HOST_DISC", "SERVICE_DISC", "VULN_DISC", "INFO_DISC"}


@dataclass(frozen=True)
class ExperimentalCandidate:
    earlier_meta_id: str
    later_meta_id: str
    delta_seconds: float
    sources: tuple[str, ...]
    reasons: tuple[str, ...]
    evidence_bundles: tuple[str, ...] = ()


def _tokens(value: str) -> set[str]:
    return set(TOKEN.findall((value or "").casefold()))


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _progression(earlier: str | None, later: str | None) -> bool:
    if not earlier or not later or "NON_MALICIOUS" in {earlier, later}:
        return False
    if earlier in DISCOVERY:
        return later in ACCESS
    if earlier in ACCESS:
        return later in POST_ACCESS | CONTROL | OUTCOME
    if earlier in POST_ACCESS:
        return later in CONTROL | OUTCOME
    if earlier in CONTROL:
        return later in CONTROL | OUTCOME
    return False


def _ordered(metas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(metas, key=lambda row: (float(row["first_timestamp"]), str(row["meta_id"])))


def _pair(left: dict[str, Any], right: dict[str, Any]) -> tuple[str, str]:
    return str(left["meta_id"]), str(right["meta_id"])


def local_candidates(metas: list[dict[str, Any]], window: float, cap: int) -> list[ExperimentalCandidate]:
    """Même blocage observable et même préférence récente que V1/V2-0."""
    by_entity: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    result = []
    for current in _ordered(metas):
        possible: dict[str, dict[str, Any]] = {}
        cutoff = float(current["first_timestamp"]) - window
        for entity in current["entities"]:
            queue = by_entity[str(entity)]
            while queue and float(queue[0]["last_timestamp"]) < cutoff:
                queue.popleft()
            for previous in queue:
                possible[str(previous["meta_id"])] = previous
        recent = sorted(
            possible.values(), key=lambda row: (float(row["last_timestamp"]), str(row["meta_id"])), reverse=True,
        )[:cap]
        for previous in reversed(recent):
            result.append(ExperimentalCandidate(
                *_pair(previous, current),
                max(0.0, float(current["first_timestamp"]) - float(previous["last_timestamp"])),
                (f"local-window-{int(window)}s",), ("shared-entity", "bounded-time-window"),
            ))
        for entity in current["entities"]:
            by_entity[str(entity)].append(current)
    return result


def evidence_bundles(left: dict[str, Any], right: dict[str, Any]) -> tuple[str, ...]:
    """Paquets observables; aucun identifiant de supervision n'est accepté."""
    left_entities, right_entities = set(left["entities"]), set(right["entities"])
    shared = left_entities & right_entities
    bundles = []
    operational = {value for value in shared if value.startswith(("ip:", "user:", "path:"))}
    if operational:
        bundles.append("operational-entity-continuity")
    src_l, src_r = set(left.get("src_ips") or []), set(right.get("src_ips") or [])
    dst_l, dst_r = set(left.get("dst_ips") or []), set(right.get("dst_ips") or [])
    if src_l & src_r or dst_l & dst_r or dst_l & src_r or src_l & dst_r:
        bundles.append("network-direction-continuity")
    text_similarity = _jaccard(_tokens(left.get("signature_text", "")), _tokens(right.get("signature_text", "")))
    if left["signature"] == right["signature"] or text_similarity >= 0.5:
        bundles.append("semantic-continuity")
    stage_left, stage_right = left.get("observed_stage"), right.get("observed_stage")
    if stage_left and stage_right and (stage_left == stage_right or _progression(stage_left, stage_right)):
        bundles.append("behavioral-compatibility")
    if left["sensor"] == right["sensor"]:
        bundles.append("same-observation-channel")
    left_family, right_family = str(left["sensor"]), str(right["sensor"])
    if ("sshd" in left_family or "pam" in left_family) and ("pam" in right_family or "syscheck" in right_family):
        bundles.append("ssh-to-session-or-fim-chain")
    protocols_l, protocols_r = set(left.get("protocols") or []), set(right.get("protocols") or [])
    services_l, services_r = set(left.get("services") or []), set(right.get("services") or [])
    if protocols_l & protocols_r or services_l & services_r:
        bundles.append("service-or-protocol-continuity")
    return tuple(sorted(bundles))


def corroborated_long_candidates(
    metas: list[dict[str, Any]], *, local_window: float = 60.0,
    max_age: float = 180.0, min_bundles: int = 2, per_alert_cap: int | None = None,
) -> list[ExperimentalCandidate]:
    """Propose uniquement des relations longues partageant une entité observable."""
    ordered = _ordered(metas)
    by_entity: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    by_later: dict[str, list[tuple[int, float, dict[str, Any], tuple[str, ...]]]] = defaultdict(list)
    for right in ordered:
        possible: dict[str, dict[str, Any]] = {}
        cutoff = float(right["first_timestamp"]) - max_age
        for entity in right["entities"]:
            queue = by_entity[str(entity)]
            while queue and float(queue[0]["last_timestamp"]) < cutoff:
                queue.popleft()
            for left in queue:
                possible[str(left["meta_id"])] = left
        for left in possible.values():
            delta = max(0.0, float(right["first_timestamp"]) - float(left["last_timestamp"]))
            if delta <= local_window or delta > max_age:
                continue
            if not (set(left["entities"]) & set(right["entities"])):
                continue
            bundles = evidence_bundles(left, right)
            if len(bundles) < min_bundles:
                continue
            by_later[str(right["meta_id"])].append((len(bundles), delta, left, bundles))
        for entity in right["entities"]:
            by_entity[str(entity)].append(right)
    result = []
    for later_id in sorted(by_later):
        ranked = sorted(by_later[later_id], key=lambda row: (-row[0], row[1], str(row[2]["meta_id"])))
        if per_alert_cap is not None:
            ranked = ranked[:per_alert_cap]
        right = next(row for row in ordered if str(row["meta_id"]) == later_id)
        for score, delta, left, bundles in ranked:
            result.append(ExperimentalCandidate(
                *_pair(left, right), delta, ("corroborated-long-bridge",),
                (f"evidence-bundles>={min_bundles}", f"age<={int(max_age)}s"), bundles,
            ))
    return result


def merge_candidates(*sets: Iterable[ExperimentalCandidate]) -> list[ExperimentalCandidate]:
    merged: dict[tuple[str, str], ExperimentalCandidate] = {}
    for candidates in sets:
        for candidate in candidates:
            key = (candidate.earlier_meta_id, candidate.later_meta_id)
            previous = merged.get(key)
            if previous is None:
                merged[key] = candidate
            else:
                merged[key] = ExperimentalCandidate(
                    *key, min(previous.delta_seconds, candidate.delta_seconds),
                    tuple(sorted(set(previous.sources) | set(candidate.sources))),
                    tuple(sorted(set(previous.reasons) | set(candidate.reasons))),
                    tuple(sorted(set(previous.evidence_bundles) | set(candidate.evidence_bundles))),
                )
    return [merged[key] for key in sorted(merged)]


def baseline_from_cache(rows: list[dict[str, Any]]) -> list[ExperimentalCandidate]:
    return [ExperimentalCandidate(
        str(row["earlier_meta_id"]), str(row["later_meta_id"]), float(row["delta_seconds"]),
        tuple(sorted(str(row["candidate_source"]).split("+"))), ("historical-generator-exact",),
    ) for row in rows]


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_campaign(run: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    caches = sorted(
        path for path in (run / "derived-cache").glob("*")
        if (path / "meta_observable.parquet").exists() and (path / "pair_examples.parquet").exists()
    )
    if len(caches) != 1:
        raise ValueError(f"un cache observable unique est requis, trouvé: {len(caches)}")
    cache = caches[0]
    metas = pq.read_table(cache / "meta_observable.parquet").to_pylist()
    pairs = pq.read_table(cache / "pair_examples.parquet").to_pylist()
    truth_paths = [
        run / "supervision-multiphase-fim-v2" / "meta-truth.jsonl",
        run / "supervision-multi-instance-v2-exclusive-correlation" / "meta-truth.jsonl",
    ]
    truth_path = next((path for path in truth_paths if path.exists()), None)
    if truth_path is None:
        raise FileNotFoundError("vérité de méta-alertes stricte introuvable")
    truth = {row["meta_id"]: row for row in _jsonl(truth_path)}
    return metas, pairs, truth


def _reference(metas: list[dict[str, Any]], truth: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    meta = {row["meta_id"]: row for row in metas}
    verified = {key: value for key, value in truth.items() if value.get("confidence") == "verified"}
    refs = []
    ordered_ids = sorted(verified, key=lambda key: (meta[key]["first_timestamp"], key))
    for left_id, right_id in combinations(ordered_ids, 2):
        scope = relation_scope(verified[left_id], verified[right_id])
        if scope is None:
            continue
        refs.append({"pair": (left_id, right_id), "scope": scope, "target": int(scope.startswith("positive-"))})
    return refs


def evaluate(
    metas: list[dict[str, Any]], truth: dict[str, dict[str, Any]], candidates: list[ExperimentalCandidate],
) -> dict[str, Any]:
    references = _reference(metas, truth); keys = {(row.earlier_meta_id, row.later_meta_id) for row in candidates}
    reference_by_key = {row["pair"]: row for row in references}
    positives = [row for row in references if row["target"] == 1]
    negatives = [row for row in references if row["target"] == 0]
    candidate_positive = [row for row in positives if row["pair"] in keys]
    candidate_negative = [row for row in negatives if row["pair"] in keys]
    unknown = [key for key in keys if key not in reference_by_key]
    inter_attack = [row for row in candidate_negative if row["scope"] == "negative-a1-a2"]
    graph = {}
    for identity in ("A1", "A2"):
        nodes = sorted(key for key, value in truth.items() if value.get("confidence") == "verified" and (value.get("attack_instance_id") or "").endswith(identity.lower()))
        scope = f"positive-{identity.lower()}-{identity.lower()}"
        edges = [row["pair"] for row in candidate_positive if row["scope"] == scope]
        components = connected_components(nodes, edges)
        graph[identity] = {"components": len(components), "isolated": sum(len(x) == 1 for x in components), "connected": len(components) == 1}
    return {
        "candidates": len(candidates), "positive_reference": len(positives),
        "positive_candidates": len(candidate_positive), "positive_recall": len(candidate_positive) / len(positives),
        "negative_reference": len(negatives), "negative_candidates": len(candidate_negative),
        "negative_recall": len(candidate_negative) / len(negatives),
        "inter_attack_candidates": len(inter_attack), "unknown_or_non_strict_candidates": len(unknown),
        "fragmentation": graph,
        "recovered_positive_pairs": [list(row["pair"]) for row in candidate_positive],
        "missing_positive_pairs": [list(row["pair"]) for row in positives if row["pair"] not in keys],
    }


def benchmark(factory: Callable[[], list[ExperimentalCandidate]], repetitions: int = 25) -> dict[str, float]:
    durations = []
    tracemalloc.start()
    for _ in range(repetitions):
        started = time.perf_counter(); factory(); durations.append((time.perf_counter() - started) * 1000)
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    return {"median_runtime_ms": median(durations), "mean_runtime_ms": mean(durations), "peak_tracemalloc_kib": peak / 1024, "repetitions": repetitions}


def campaign_variants(run: Path) -> tuple[dict[str, Any], dict[str, list[ExperimentalCandidate]]]:
    metas, baseline_rows, truth = load_campaign(run)
    baseline = baseline_from_cache(baseline_rows)
    historical_causal = [row for row in baseline if "causal-bridge" in row.sources]
    factories: dict[str, Callable[[], list[ExperimentalCandidate]]] = {
        "v2-0-baseline": lambda: baseline_from_cache(baseline_rows),
        "v2-1-window-120": lambda: merge_candidates(local_candidates(metas, 120, 50), historical_causal),
        "v2-1-window-180": lambda: merge_candidates(local_candidates(metas, 180, 50), historical_causal),
        "v2-2-corroborated-exhaustive": lambda: merge_candidates(
            baseline, corroborated_long_candidates(metas, max_age=180, min_bundles=2, per_alert_cap=None)
        ),
        "v2-3-hybrid-sparse": lambda: merge_candidates(
            baseline, corroborated_long_candidates(metas, max_age=180, min_bundles=2, per_alert_cap=3)
        ),
        "v2-3-hybrid-conservative": lambda: merge_candidates(
            baseline, corroborated_long_candidates(metas, max_age=180, min_bundles=4, per_alert_cap=3)
        ),
    }
    variants = {name: factory() for name, factory in factories.items()}
    evaluated = {}
    baseline_keys = {(x.earlier_meta_id, x.later_meta_id) for x in baseline}
    for name, candidates in variants.items():
        metrics = evaluate(metas, truth, candidates)
        metrics["additional_candidates_vs_baseline"] = len({(x.earlier_meta_id, x.later_meta_id) for x in candidates} - baseline_keys)
        metrics["cost"] = benchmark(factories[name])
        evaluated[name] = metrics
    sensitivity = {}
    for window in (60, 90, 120, 180):
        candidates = merge_candidates(local_candidates(metas, window, 50), historical_causal)
        sensitivity[f"window-{window}"] = evaluate(metas, truth, candidates)
    for threshold in (2, 3, 4):
        for bridge_cap in (1, 3, 5):
            candidates = merge_candidates(
                baseline,
                corroborated_long_candidates(metas, max_age=180, min_bundles=threshold, per_alert_cap=bridge_cap),
            )
            sensitivity[f"hybrid-bundles-{threshold}-cap-{bridge_cap}"] = evaluate(metas, truth, candidates)
    meta_by_id = {row["meta_id"]: row for row in metas}
    missing_positive_analysis = []
    for left_id, right_id in evaluated["v2-0-baseline"]["missing_positive_pairs"]:
        left, right = meta_by_id[left_id], meta_by_id[right_id]
        shared = sorted(set(left["entities"]) & set(right["entities"]))
        delta = max(0.0, float(right["first_timestamp"]) - float(left["last_timestamp"]))
        compatible = _progression(left.get("observed_stage"), right.get("observed_stage"))
        missing_positive_analysis.append({
            "earlier_meta_id": left_id, "later_meta_id": right_id, "delta_seconds": delta,
            "earlier_signature": left["signature"], "later_signature": right["signature"],
            "earlier_sensor": left["sensor"], "later_sensor": right["sensor"],
            "earlier_stage": left.get("observed_stage"), "later_stage": right.get("observed_stage"),
            "shared_entities": shared, "observable_evidence_bundles": evidence_bundles(left, right),
            "outside_local_window": delta > 60.0,
            "historical_progression_compatible": compatible,
            "historical_latest_per_entity_stage_can_overwrite": bool(compatible and shared),
            "exclusion_reason": "outside-60s-and-not-selected-by-historical-five-causal-bridges",
        })
    return {
        "campaign_id": load_json(run / "campaign-manifest.json")["campaign_id"],
        "meta_alerts": len(metas), "variants": evaluated, "sensitivity": sensitivity,
        "baseline_missing_positive_analysis": missing_positive_analysis,
        "generation_uses_truth": False, "truth_used_after_generation_for_evaluation": True,
    }, variants


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    results = []; all_variants = {}
    for run in args.campaign:
        report, variants = campaign_variants(run); results.append(report)
        all_variants[report["campaign_id"]] = variants
    args.output_dir.mkdir(parents=True, exist_ok=False)
    for campaign_id, variants in all_variants.items():
        directory = args.output_dir / campaign_id; directory.mkdir()
        for name, candidates in variants.items():
            payload = b"".join((json.dumps({
                "earlier_meta_id": row.earlier_meta_id, "later_meta_id": row.later_meta_id,
                "delta_seconds": row.delta_seconds, "sources": row.sources,
                "reasons": row.reasons, "evidence_bundles": row.evidence_bundles,
            }, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for row in candidates)
            write_new_bytes(directory / f"{name}.jsonl", payload)
    summary = {
        "schema_version": "alertgraph-experimental-candidate-generators/2.0",
        "created_at_utc": utc_now(), "campaigns": results,
        "experimental_only": True, "pipeline_modified": False, "model_trained": False,
        "weak_labels_used": False, "training_ready": False,
    }
    write_new_json(args.output_dir / "comparison.json", summary)
    print(json.dumps({row["campaign_id"]: {
        name: {key: metrics[key] for key in ("candidates", "positive_recall", "negative_recall", "inter_attack_candidates", "unknown_or_non_strict_candidates")}
        for name, metrics in row["variants"].items()
    } for row in results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
