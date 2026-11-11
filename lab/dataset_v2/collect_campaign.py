"""Collecte locale versionnée d'une campagne Wazuh V2.

Le mode actuel accepte uniquement un export JSONL local et exige ``--dry-run``.
Il ne contacte jamais le manager Wazuh. Les lignes sélectionnées sont copiées
octet pour octet, puis indexées et scellées par SHA-256.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import pyarrow as pa
import pyarrow.parquet as pq
from jsonschema import Draft202012Validator

from lab.collect_wazuh import alert_timestamp, instant

from .io_utils import load_json, sha256_bytes, sha256_file, utc_now, write_new_bytes, write_new_json
from .prepare_campaign import verify_campaign_reservation
from .validators import SCHEMA_DIR


def _utc_timestamp(value: object) -> float:
    text = str(value or "")
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"Timestamp Wazuh non UTC: {value!r}")
    return alert_timestamp({"timestamp": text})


def verify_collection(campaign_dir: str | Path) -> dict[str, object]:
    campaign_dir = Path(campaign_dir)
    manifest_path = campaign_dir / "raw" / "collection-manifest.json"
    manifest = load_json(manifest_path)
    for entry in manifest["files"]:
        path = (campaign_dir / entry["path"]).resolve()
        try:
            path.relative_to(campaign_dir.resolve())
        except ValueError as exc:
            raise ValueError(f"Chemin hors campagne: {entry['path']}") from exc
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size != entry["bytes"]:
            raise ValueError(f"Taille modifiée: {entry['path']}")
        if sha256_file(path) != entry["sha256"]:
            raise ValueError(f"SHA-256 modifié: {entry['path']}")
    return manifest


def collect_local_export(
    campaign_dir: str | Path,
    source_jsonl: str | Path,
    *,
    since: float,
    until: float,
    agents: set[str],
    dry_run: bool,
    source_label: str | None = None,
) -> dict[str, object]:
    """Filtre un export local sans réencoder les événements sélectionnés."""

    if not dry_run:
        raise PermissionError("Cette étape autorise uniquement la collecte locale --dry-run")
    if until < since:
        raise ValueError("until doit être postérieur à since")
    campaign_dir = Path(campaign_dir)
    source_jsonl = Path(source_jsonl)
    campaign = verify_campaign_reservation(campaign_dir)
    if campaign["partition"] == "final-test":
        raise PermissionError("La collecte final-test reste scellée à cette étape")
    raw_dir = campaign_dir / "raw"
    if raw_dir.exists():
        raise FileExistsError(f"Une collecte existe déjà: {raw_dir}")
    if not source_jsonl.is_file():
        raise FileNotFoundError(source_jsonl)

    selected_lines: list[bytes] = []
    index_rows: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    lines_read = malformed = 0
    source_offset = 0
    with source_jsonl.open("rb") as source:
        for raw_line in source:
            lines_read += 1
            line_offset = source_offset
            source_offset += len(raw_line)
            try:
                text = raw_line.decode("utf-8")
                raw = json.loads(text)
                timestamp = _utc_timestamp(raw.get("timestamp"))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                malformed += 1
                raise ValueError(f"Ligne JSONL invalide {lines_read}: {exc}") from exc
            agent = str(raw.get("agent", {}).get("name", ""))
            if not (since <= timestamp <= until and (not agents or agent in agents)):
                continue
            alert_id = raw.get("id")
            if not isinstance(alert_id, str) or not alert_id:
                raise ValueError(f"Événement sélectionné sans id à la ligne {lines_read}")
            if alert_id in seen_ids:
                raise ValueError(f"Identifiant Wazuh dupliqué: {alert_id}")
            seen_ids.add(alert_id)
            selected_lines.append(raw_line)
            rule = raw.get("rule", {}) if isinstance(raw.get("rule"), Mapping) else {}
            decoder = raw.get("decoder", {}) if isinstance(raw.get("decoder"), Mapping) else {}
            index_rows.append(
                {
                    "wazuh_alert_id": alert_id,
                    "selected_line_number": len(selected_lines),
                    "source_line_number": lines_read,
                    "source_byte_offset": line_offset,
                    "source_byte_length": len(raw_line),
                    "raw_line_sha256": sha256_bytes(raw_line),
                    "timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                    "agent_name": agent,
                    "rule_id": str(rule.get("id", "")),
                    "decoder_name": str(decoder.get("name", "")),
                }
            )

    raw_dir.mkdir(parents=True, exist_ok=False)
    alerts_path = raw_dir / "alerts.jsonl"
    write_new_bytes(alerts_path, b"".join(selected_lines))
    index_path = raw_dir / "alert-index.parquet"
    table = pa.Table.from_pylist(index_rows) if index_rows else pa.table(
        {
            "wazuh_alert_id": pa.array([], type=pa.string()),
            "selected_line_number": pa.array([], type=pa.int64()),
            "source_line_number": pa.array([], type=pa.int64()),
            "source_byte_offset": pa.array([], type=pa.int64()),
            "source_byte_length": pa.array([], type=pa.int64()),
            "raw_line_sha256": pa.array([], type=pa.string()),
            "timestamp_utc": pa.array([], type=pa.string()),
            "agent_name": pa.array([], type=pa.string()),
            "rule_id": pa.array([], type=pa.string()),
            "decoder_name": pa.array([], type=pa.string()),
        }
    )
    pq.write_table(table, index_path, compression="zstd")
    files = []
    for role, path in (("raw-alerts", alerts_path), ("alert-index", index_path)):
        files.append(
            {
                "role": role,
                "path": path.relative_to(campaign_dir).as_posix(),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    manifest = {
        "schema_version": "alertgraph-collection-manifest/2.0",
        "campaign_id": campaign["campaign_id"],
        "run_id": campaign["run_id"],
        "created_at_utc": utc_now(),
        "since_utc": datetime.fromtimestamp(since, timezone.utc).isoformat(),
        "until_utc": datetime.fromtimestamp(until, timezone.utc).isoformat(),
        "source": source_label or f"local-dry-run:{source_jsonl.resolve()}",
        "agent_filter": sorted(agents),
        "lines_read": lines_read,
        "alerts_written": len(selected_lines),
        "malformed_lines": malformed,
        "files": files,
    }
    schema = json.loads(
        (SCHEMA_DIR / "collection-manifest.schema.json").read_text(encoding="utf-8")
    )
    errors = list(Draft202012Validator(schema).iter_errors(manifest))
    if errors:
        raise ValueError("Manifest de collecte invalide: " + "; ".join(x.message for x in errors))
    write_new_json(raw_dir / "collection-manifest.json", manifest)
    verify_collection(campaign_dir)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--source-jsonl", required=True, type=Path)
    parser.add_argument("--since", required=True, type=instant)
    parser.add_argument("--until", required=True, type=instant)
    parser.add_argument("--agents", default="")
    parser.add_argument("--dry-run", action="store_true", required=True)
    args = parser.parse_args()
    report = collect_local_export(
        args.campaign_dir,
        args.source_jsonl,
        since=args.since,
        until=args.until,
        agents={value.strip() for value in args.agents.split(",") if value.strip()},
        dry_run=args.dry_run,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
