"""Audit temporel V2 avec sondes injectables et politique préenregistrée."""

from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Protocol

from jsonschema import Draft202012Validator

from .io_utils import load_json, sha256_file, utc_now, write_new_json
from .prepare_campaign import verify_campaign_reservation
from .temporal_policy import validate_temporal_policy
from .validators import SCHEMA_DIR


@dataclass(frozen=True)
class ClockSample:
    request_started_at_utc: str
    request_ended_at_utc: str
    remote_time_utc: str
    synchronized: bool | None
    sync_source: str
    samples: tuple[Mapping[str, object], ...] = ()
    selection_policy: str | None = None
    selected_sample_index: int | None = None


class ClockProbe(Protocol):
    def measure(self, machine: Mapping[str, object]) -> ClockSample: ...


class StaticClockProbe:
    """Sonde locale pour tests et réponses capturées hors bande."""

    def __init__(self, responses: Mapping[str, Mapping[str, object]]):
        self.responses = responses

    def measure(self, machine: Mapping[str, object]) -> ClockSample:
        role = str(machine["role"])
        if role not in self.responses:
            raise KeyError(f"Réponse d'horloge absente pour {role}")
        value = self.responses[role]
        return ClockSample(
            request_started_at_utc=str(value["request_started_at_utc"]),
            request_ended_at_utc=str(value["request_ended_at_utc"]),
            remote_time_utc=str(value["remote_time_utc"]),
            synchronized=value.get("synchronized"),
            sync_source=str(value.get("sync_source") or "unknown"),
            samples=tuple(value.get("samples") or ()),
            selection_policy=(str(value["selection_policy"]) if value.get("selection_policy") else None),
            selected_sample_index=(int(value["selected_sample_index"])
                                   if value.get("selected_sample_index") is not None else None),
        )


class ClockPolicyError(RuntimeError):
    def __init__(self, report: Mapping[str, object], report_path: Path):
        self.report = report
        self.report_path = report_path
        super().__init__(
            "Audit d'horloge rejeté: " + "; ".join(report["rejection_reasons"])
        )


def _epoch(value: str) -> float:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"Horodatage non UTC: {value}")
    return parsed.timestamp()


def _audit_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"clock-{stamp}-{uuid.uuid4().hex[:8]}"


def audit_campaign_clocks(
    campaign_dir: str | Path,
    probe: ClockProbe,
    *,
    allow_final_test_audit: bool = False,
    raise_on_rejection: bool = True,
) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest = verify_campaign_reservation(campaign_dir)
    if manifest["partition"] == "final-test" and not allow_final_test_audit:
        raise PermissionError("L'audit final-test exige une autorisation explicite")
    plan = load_json(campaign_dir / "campaign-plan.json")
    policy = validate_temporal_policy(plan["temporal_policy"])
    machines = manifest["machines"]
    by_role: dict[str, Mapping[str, object]] = {}
    for machine in machines:
        role = str(machine["role"])
        if role in by_role:
            raise ValueError(f"Rôle machine dupliqué: {role}")
        by_role[role] = machine

    measurements = []
    rejection_reasons = []
    for role in policy["required_roles"]:
        machine = by_role.get(role)
        if machine is None:
            rejection_reasons.append(f"required-role-missing:{role}")
            continue
        try:
            sample = probe.measure(machine)
            raw_samples = list(sample.samples) or [{
                "sample_index": 0,
                "request_started_at_utc": sample.request_started_at_utc,
                "request_ended_at_utc": sample.request_ended_at_utc,
                "remote_time_utc": sample.remote_time_utc,
            }]
            sample_rows = []
            for index, raw in enumerate(raw_samples):
                started_i = _epoch(str(raw["request_started_at_utc"]))
                ended_i = _epoch(str(raw["request_ended_at_utc"]))
                remote_i = _epoch(str(raw["remote_time_utc"]))
                if ended_i < started_i:
                    raise ValueError("fin de mesure antérieure au début")
                midpoint_i = (started_i + ended_i) / 2.0
                sample_rows.append({
                    "sample_index": int(raw.get("sample_index", index)),
                    "request_started_at_utc": str(raw["request_started_at_utc"]),
                    "request_ended_at_utc": str(raw["request_ended_at_utc"]),
                    "remote_time_utc": str(raw["remote_time_utc"]),
                    "rtt_ms": (ended_i - started_i) * 1000.0,
                    "offset_ms": (remote_i - midpoint_i) * 1000.0,
                    "uncertainty_ms": (ended_i - started_i) * 500.0,
                })
            selected_row = min(
                sample_rows,
                key=lambda item: (float(item["rtt_ms"]), int(item["sample_index"])),
            )
            if (sample.selected_sample_index is not None
                    and int(selected_row["sample_index"]) != sample.selected_sample_index):
                raise ValueError("sélection de sonde incohérente avec le RTT minimal")
            started = _epoch(str(selected_row["request_started_at_utc"]))
            ended = _epoch(str(selected_row["request_ended_at_utc"]))
            remote = _epoch(str(selected_row["remote_time_utc"]))
            if ended < started:
                raise ValueError("fin de mesure antérieure au début")
            midpoint = (started + ended) / 2.0
            offset_ms = (remote - midpoint) * 1000.0
            uncertainty_ms = (ended - started) * 500.0
            reasons = []
            if abs(offset_ms) > policy["max_abs_offset_ms"]:
                reasons.append("offset-exceeds-policy")
            if uncertainty_ms > policy["max_uncertainty_ms"]:
                reasons.append("uncertainty-exceeds-policy")
            if policy["require_synchronized"] and sample.synchronized is not True:
                reasons.append("synchronization-not-confirmed")
            interval_low = max(float(x["offset_ms"]) - float(x["uncertainty_ms"]) for x in sample_rows)
            interval_high = min(float(x["offset_ms"]) + float(x["uncertainty_ms"]) for x in sample_rows)
            if interval_low > interval_high:
                reasons.append("inconsistent-clock-samples")
            accepted = not reasons
            if not accepted:
                rejection_reasons.extend(f"{role}:{reason}" for reason in reasons)
            measurements.append(
                {
                    "role": role,
                    "host": str(machine["host"]),
                    "request_started_at_utc": sample.request_started_at_utc,
                    "request_ended_at_utc": sample.request_ended_at_utc,
                    "remote_time_utc": sample.remote_time_utc,
                    "offset_ms": offset_ms,
                    "uncertainty_ms": uncertainty_ms,
                    "synchronized": sample.synchronized,
                    "sync_source": sample.sync_source,
                    "selection_policy": (sample.selection_policy or "single-sample"),
                    "selected_sample_index": int(selected_row["sample_index"]),
                    "samples": sample_rows,
                    "consistent_offset_interval_ms": (
                        {"lower": interval_low, "upper": interval_high}
                        if interval_low <= interval_high else None
                    ),
                    "accepted": accepted,
                    "reasons": reasons,
                }
            )
        except Exception as exc:
            rejection_reasons.append(f"{role}:probe-failed:{type(exc).__name__}")

    audit_id = _audit_id()
    report = {
        "schema_version": "alertgraph-clock-audit/2.0",
        "audit_id": audit_id,
        "campaign_id": manifest["campaign_id"],
        "run_id": manifest["run_id"],
        "created_at_utc": utc_now(),
        "policy": policy,
        "measurements": measurements,
        "accepted": not rejection_reasons,
        "rejection_reasons": rejection_reasons,
    }
    schema = json.loads((SCHEMA_DIR / "clock-audit.schema.json").read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(report))
    if errors:
        raise ValueError("Rapport d'horloge invalide: " + "; ".join(x.message for x in errors))
    directory = campaign_dir / "preflight" / "clock-audits" / audit_id
    write_new_json(directory / "clock-audit.json", report)
    write_new_json(
        directory / "audit-seal.json",
        {
            "schema_version": "alertgraph-clock-audit-seal/2.0",
            "clock_audit_sha256": sha256_file(directory / "clock-audit.json"),
        },
    )
    if rejection_reasons and raise_on_rejection:
        raise ClockPolicyError(report, directory / "clock-audit.json")
    return report


def require_clock_ready(campaign_dir: str | Path) -> dict[str, object]:
    root = Path(campaign_dir) / "preflight" / "clock-audits"
    reports = sorted(root.glob("*/clock-audit.json")) if root.exists() else []
    if not reports:
        raise RuntimeError("Aucun audit d'horloge disponible")
    report_path = reports[-1]
    seal = load_json(report_path.with_name("audit-seal.json"))
    if sha256_file(report_path) != seal["clock_audit_sha256"]:
        raise ValueError("Rapport d'horloge modifié après scellement")
    report = load_json(report_path)
    if not report["accepted"]:
        raise ClockPolicyError(report, report_path)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--responses", required=True, type=Path)
    parser.add_argument("--allow-final-test-audit", action="store_true")
    args = parser.parse_args()
    responses = json.loads(args.responses.read_text(encoding="utf-8"))
    report = audit_campaign_clocks(
        args.campaign_dir,
        StaticClockProbe(responses),
        allow_final_test_audit=args.allow_final_test_audit,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
