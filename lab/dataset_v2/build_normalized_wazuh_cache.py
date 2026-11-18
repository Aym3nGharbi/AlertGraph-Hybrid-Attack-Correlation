"""Construit un cache Wazuh V2 depuis une copie dérivée neutralisée."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .io_utils import sha256_file, write_new_bytes, write_new_json
from .marker_normalization import normalize_instrumentation_markers

ML_ROOT=Path(__file__).resolve().parents[2]/"ml"
if str(ML_ROOT) not in sys.path: sys.path.insert(0,str(ML_ROOT))
from build_wazuh_lab_cache import build_cache  # noqa: E402


def _normalize(value: object, markers: list[str]) -> object:
    if isinstance(value,str): return normalize_instrumentation_markers(value,markers)
    if isinstance(value,list): return [_normalize(item,markers) for item in value]
    if isinstance(value,dict): return {key:_normalize(item,markers) for key,item in value.items()}
    return value


def supervision_markers(plan: dict[str, object]) -> list[str]:
    """Retourne les valeurs de supervision à neutraliser dans la copie ML."""

    values: set[str] = {str(plan["campaign_id"]), str(plan["run_id"])}
    for activity in plan.get("activities") or []:
        for name in ("marker_id", "activity_id", "attack_instance_id", "benign_activity_id"):
            value = activity.get(name)
            if value:
                values.add(str(value))
    policies = []
    if plan.get("fim_pilot_policy"):
        policies.append(plan["fim_pilot_policy"])
    policies.extend((plan.get("fim_activity_policies") or {}).values())
    for policy in policies:
        for name in ("marker", "initial_sha256", "modified_sha256"):
            value = policy.get(name)
            if value:
                values.add(str(value))
    return sorted(values, key=lambda value: (-len(value), value))


def build_normalized_cache(campaign_dir: str|Path, *, mapping: str|Path) -> dict[str,object]:
    campaign_dir=Path(campaign_dir); plan=json.loads((campaign_dir/"campaign-plan.json").read_text())
    raw_path=campaign_dir/"raw"/"alerts.jsonl"; raw_bytes=raw_path.read_bytes()
    markers=supervision_markers(plan)
    rows=[json.loads(line) for line in raw_bytes.splitlines() if line]
    normalized=[_normalize(row,markers) for row in rows]
    target_input=campaign_dir/"derived-normalized-input"/"alerts.features.jsonl"
    payload=b"".join((json.dumps(row,ensure_ascii=False,separators=(",",":"))+"\n").encode() for row in normalized)
    write_new_bytes(target_input,payload)
    folded=payload.decode("utf-8").casefold()
    leaked=[value for value in markers if value.casefold() in folded]
    if leaked: raise ValueError("marqueur de supervision encore présent dans la copie dérivée")
    cache_root=campaign_dir/"derived-cache"
    run_id=(
        "multiphase-fim-observable-normalized"
        if plan.get("fim_activity_policies") else "benign-fim-observable-normalized"
    )
    cache=build_cache(target_input,cache_root,run_id,Path(mapping),collapse_seconds=2.0,window_seconds=60.0,cap=50)
    report={
        "schema_version":"alertgraph-normalized-wazuh-cache/2.0-experimental",
        "raw_sha256":sha256_file(raw_path),"normalized_input_sha256":sha256_file(target_input),
        "raw_preserved":raw_path.read_bytes()==raw_bytes,"markers_removed":len(markers),
        "forbidden_values_remaining":leaked,"cache":cache,"training_ready":False,
    }
    write_new_json(campaign_dir/"derived-normalized-input"/"manifest.json",report); return report


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("campaign_dir",type=Path)
    parser.add_argument("--mapping",type=Path,default=Path("config/wazuh-stage-mapping.json")); args=parser.parse_args()
    print(json.dumps(build_normalized_cache(args.campaign_dir,mapping=args.mapping),ensure_ascii=False,indent=2))


if __name__=="__main__": main()
