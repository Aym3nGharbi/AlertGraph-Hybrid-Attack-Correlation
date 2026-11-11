"""Validation sémantique des documents de la base supervisée Wazuh V2.

Les JSON Schemas décrivent la forme des documents. Ce module applique les
contraintes inter-documents qui ne peuvent pas être exprimées proprement avec
un schéma seul : références, partitions, preuves indépendantes, conflits,
unicité globale et empreintes de fichiers.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator


PARTITIONS = frozenset({"development", "validation", "final-test"})
CONFIDENCES = frozenset({"verified", "weak", "unknown", "conflict"})
CLASSES = frozenset({"attack", "benign", "unknown"})
IDENTITY_EVIDENCE = frozenset(
    {"unique-marker", "process-guid", "artifact-identity", "command-hash"}
)
TECHNICAL_EVIDENCE = frozenset(
    {
        "wazuh-rule-semantic",
        "process-lineage",
        "file-telemetry",
        "network-telemetry",
        "authentication-telemetry",
    }
)
CONTEXT_EVIDENCE = frozenset(
    {"time-window", "host-match", "agent-match", "execution-receipt"}
)
EVIDENCE_KINDS = IDENTITY_EVIDENCE | TECHNICAL_EVIDENCE | CONTEXT_EVIDENCE
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SCHEMA_DIR = Path(__file__).with_name("schemas")
_SECTION_SCHEMAS = {
    "registry": "campaign-registry.schema.json",
    "campaign_manifest": "campaign-manifest.schema.json",
    "activities": "activity.schema.json",
    "evidence": "evidence.schema.json",
    "annotations": "event-annotation.schema.json",
    "conflicts": "annotation-conflict.schema.json",
    "revisions": "annotation-revision.schema.json",
    "collection_manifest": "collection-manifest.schema.json",
    "release_manifest": "release-manifest.schema.json",
}


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: [{self.code}] {self.message}"


class DatasetValidationError(ValueError):
    def __init__(self, issues: Sequence[ValidationIssue]):
        self.issues = tuple(issues)
        super().__init__("\n".join(str(issue) for issue in self.issues))


def _issue(
    issues: list[ValidationIssue], path: str, code: str, message: str
) -> None:
    issues.append(ValidationIssue(path, code, message))


def _require_keys(
    document: Mapping[str, object],
    keys: Iterable[str],
    path: str,
    issues: list[ValidationIssue],
) -> None:
    for key in keys:
        if key not in document:
            _issue(issues, f"{path}.{key}", "missing-field", "champ obligatoire")


def _is_utc(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _check_utc(
    document: Mapping[str, object],
    fields: Iterable[str],
    path: str,
    issues: list[ValidationIssue],
) -> None:
    for field in fields:
        value = document.get(field)
        if value is not None and not _is_utc(value):
            _issue(
                issues,
                f"{path}.{field}",
                "timestamp-not-utc",
                "horodatage RFC 3339 avec décalage UTC obligatoire",
            )


def _index_unique(
    items: Sequence[Mapping[str, object]],
    key: str,
    path: str,
    issues: list[ValidationIssue],
) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for index, item in enumerate(items):
        value = item.get(key)
        item_path = f"{path}[{index}].{key}"
        if not isinstance(value, str) or not value:
            _issue(issues, item_path, "invalid-id", "identifiant non vide obligatoire")
            continue
        if value in result:
            _issue(issues, item_path, "duplicate-id", f"identifiant réutilisé: {value}")
        else:
            result[value] = item
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_schema_documents(
    bundle: Mapping[str, object], issues: list[ValidationIssue]
) -> None:
    """Applique les schémas de forme avant les règles inter-documents."""

    for section, filename in _SECTION_SCHEMAS.items():
        value = bundle.get(section)
        schema = json.loads((SCHEMA_DIR / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        documents = value if section in {
            "activities", "evidence", "annotations", "conflicts", "revisions"
        } and isinstance(value, list) else [value]
        for document_index, document in enumerate(documents):
            prefix = f"$.{section}"
            if isinstance(value, list):
                prefix += f"[{document_index}]"
            for error in sorted(validator.iter_errors(document), key=lambda item: list(item.path)):
                suffix = "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.path)
                _issue(issues, prefix + suffix, "schema", error.message)


def _validate_file_entries(
    entries: Sequence[Mapping[str, object]],
    path: str,
    issues: list[ValidationIssue],
    base_dir: Path | None,
) -> None:
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        item_path = f"{path}[{index}]"
        relative = entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(relative, str) or not relative:
            _issue(issues, f"{item_path}.path", "invalid-path", "chemin obligatoire")
            continue
        if relative in seen:
            _issue(issues, f"{item_path}.path", "duplicate-path", relative)
        seen.add(relative)
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            _issue(issues, f"{item_path}.sha256", "invalid-sha256", "64 hex minuscules obligatoires")
            continue
        if base_dir is None:
            continue
        candidate = (base_dir / relative).resolve()
        try:
            candidate.relative_to(base_dir.resolve())
        except ValueError:
            _issue(issues, f"{item_path}.path", "path-escape", relative)
            continue
        if not candidate.exists():
            _issue(issues, f"{item_path}.path", "file-missing", relative)
            continue
        if candidate.is_file() and _sha256(candidate) != expected:
            _issue(issues, f"{item_path}.sha256", "sha256-mismatch", relative)
        expected_bytes = entry.get("bytes")
        if isinstance(expected_bytes, int) and candidate.stat().st_size != expected_bytes:
            _issue(issues, f"{item_path}.bytes", "size-mismatch", relative)


def validate_bundle(
    bundle: Mapping[str, object],
    *,
    base_dir: str | Path | None = None,
    raise_on_error: bool = True,
) -> list[ValidationIssue]:
    """Valide une campagne V2 et retourne toutes les erreurs trouvées."""

    issues: list[ValidationIssue] = []
    root = Path(base_dir) if base_dir is not None else None
    required_sections = (
        "registry",
        "campaign_manifest",
        "activities",
        "evidence",
        "annotations",
        "conflicts",
        "revisions",
        "collection_manifest",
        "release_manifest",
    )
    _require_keys(bundle, required_sections, "$", issues)
    if issues:
        if raise_on_error:
            raise DatasetValidationError(issues)
        return issues

    _validate_schema_documents(bundle, issues)

    registry = bundle["registry"]
    manifest = bundle["campaign_manifest"]
    activities = bundle["activities"]
    evidence = bundle["evidence"]
    annotations = bundle["annotations"]
    conflicts = bundle["conflicts"]
    revisions = bundle["revisions"]
    collection = bundle["collection_manifest"]
    release = bundle["release_manifest"]
    raw_events = bundle.get("raw_events")
    sections = (registry, manifest, collection, release)
    if not all(isinstance(value, Mapping) for value in sections) or not all(
        isinstance(value, list)
        for value in (activities, evidence, annotations, conflicts, revisions)
    ):
        _issue(issues, "$", "invalid-structure", "types de sections invalides")
        if raise_on_error:
            raise DatasetValidationError(issues)
        return issues

    registry_campaigns = registry.get("campaigns", [])
    if not isinstance(registry_campaigns, list):
        registry_campaigns = []
        _issue(issues, "$.registry.campaigns", "invalid-type", "liste obligatoire")
    campaign_index = _index_unique(
        registry_campaigns, "campaign_id", "$.registry.campaigns", issues
    )
    campaign_id = manifest.get("campaign_id")
    run_id = manifest.get("run_id")
    partition = manifest.get("partition")
    if partition not in PARTITIONS:
        _issue(issues, "$.campaign_manifest.partition", "invalid-partition", str(partition))
    registered = campaign_index.get(str(campaign_id))
    if registered is None:
        _issue(issues, "$.campaign_manifest.campaign_id", "unregistered-campaign", str(campaign_id))
    elif registered.get("partition") != partition:
        _issue(issues, "$.campaign_manifest.partition", "partition-mismatch", "registre et manifeste diffèrent")

    _check_utc(
        registry,
        ("frozen_at_utc",),
        "$.registry",
        issues,
    )
    _check_utc(
        manifest,
        ("created_at_utc", "started_at_utc", "ended_at_utc"),
        "$.campaign_manifest",
        issues,
    )
    for index, machine in enumerate(manifest.get("machines", [])):
        if isinstance(machine, Mapping):
            _check_utc(
                machine,
                ("clock_audited_at_utc",),
                f"$.campaign_manifest.machines[{index}]",
                issues,
            )

    activity_index = _index_unique(activities, "activity_id", "$.activities", issues)
    _index_unique(activities, "marker_id", "$.activities", issues)
    evidence_index = _index_unique(evidence, "evidence_id", "$.evidence", issues)
    annotation_index = _index_unique(annotations, "annotation_id", "$.annotations", issues)
    _index_unique(annotations, "wazuh_alert_id", "$.annotations", issues)
    conflict_index = _index_unique(conflicts, "conflict_id", "$.conflicts", issues)
    revision_index = _index_unique(revisions, "revision_id", "$.revisions", issues)
    raw_event_index: dict[str, Mapping[str, object]] | None = None
    if raw_events is not None:
        if not isinstance(raw_events, list):
            _issue(issues, "$.raw_events", "invalid-type", "liste obligatoire")
        else:
            raw_event_index = _index_unique(raw_events, "id", "$.raw_events", issues)
            for index, raw in enumerate(raw_events):
                if not _is_utc(raw.get("timestamp")):
                    _issue(
                        issues,
                        f"$.raw_events[{index}].timestamp",
                        "timestamp-not-utc",
                        "horodatage Wazuh UTC obligatoire dans le fixture V2",
                    )

    for index, item in enumerate(activities):
        path = f"$.activities[{index}]"
        if item.get("campaign_id") != campaign_id or item.get("run_id") != run_id:
            _issue(issues, path, "activity-scope-mismatch", "campagne/run incohérent")
        kind = item.get("class")
        attack_id = item.get("attack_instance_id")
        benign_id = item.get("benign_activity_id")
        if kind == "attack" and (not attack_id or benign_id is not None):
            _issue(issues, path, "invalid-attack-identity", "attaque exige attack_instance_id seul")
        elif kind == "benign" and (not benign_id or attack_id is not None):
            _issue(issues, path, "invalid-benign-identity", "bénin exige benign_activity_id seul")
        elif kind not in {"attack", "benign"}:
            _issue(issues, f"{path}.class", "invalid-class", str(kind))
        _check_utc(
            item,
            (
                "started_at_utc",
                "ended_at_utc",
                "controller_started_at_utc",
                "controller_ended_at_utc",
                "target_started_at_utc",
                "target_ended_at_utc",
            ),
            path,
            issues,
        )
        for evidence_id in item.get("evidence_ids", []):
            linked = evidence_index.get(evidence_id)
            if linked is None:
                _issue(issues, f"{path}.evidence_ids", "unknown-evidence", str(evidence_id))
            elif linked.get("activity_id") != item.get("activity_id"):
                _issue(issues, f"{path}.evidence_ids", "evidence-activity-mismatch", str(evidence_id))

    for index, item in enumerate(evidence):
        path = f"$.evidence[{index}]"
        if item.get("kind") not in EVIDENCE_KINDS:
            _issue(issues, f"{path}.kind", "invalid-evidence-kind", str(item.get('kind')))
        if item.get("campaign_id") != campaign_id or item.get("run_id") != run_id:
            _issue(issues, path, "evidence-scope-mismatch", "campagne/run incohérent")
        activity_id = item.get("activity_id")
        if activity_id not in activity_index:
            _issue(issues, f"{path}.activity_id", "unknown-activity", str(activity_id))
        _check_utc(item, ("recorded_at_utc",), path, issues)
        digest = item.get("payload_sha256")
        if digest is not None and (not isinstance(digest, str) or not SHA256.fullmatch(digest)):
            _issue(issues, f"{path}.payload_sha256", "invalid-sha256", str(digest))
        if raw_event_index is not None:
            for alert_id in item.get("observed_in_alert_ids", []):
                if alert_id not in raw_event_index:
                    _issue(issues, f"{path}.observed_in_alert_ids", "unknown-raw-event", str(alert_id))

    for index, item in enumerate(annotations):
        path = f"$.annotations[{index}]"
        confidence = item.get("confidence")
        label_class = item.get("class")
        if confidence not in CONFIDENCES:
            _issue(issues, f"{path}.confidence", "invalid-confidence", str(confidence))
        if label_class not in CLASSES:
            _issue(issues, f"{path}.class", "invalid-class", str(label_class))
        if raw_event_index is not None and item.get("wazuh_alert_id") not in raw_event_index:
            _issue(issues, f"{path}.wazuh_alert_id", "unknown-raw-event", str(item.get('wazuh_alert_id')))
        _check_utc(item, ("created_at_utc", "reviewed_at_utc"), path, issues)
        evidence_ids = item.get("evidence_ids", [])
        known_evidence = []
        for evidence_id in evidence_ids:
            evidence_item = evidence_index.get(evidence_id)
            if evidence_item is None:
                _issue(issues, f"{path}.evidence_ids", "unknown-evidence", str(evidence_id))
            else:
                known_evidence.append(evidence_item)
        activity = activity_index.get(item.get("activity_id"))

        if activity is not None:
            foreign = [
                value.get("evidence_id")
                for value in known_evidence
                if value.get("activity_id") != item.get("activity_id")
            ]
            if foreign:
                _issue(issues, path, "annotation-evidence-activity-mismatch", ", ".join(map(str, foreign)))

        if confidence == "verified":
            kinds = {value.get("kind") for value in known_evidence}
            if not (kinds & IDENTITY_EVIDENCE):
                _issue(issues, path, "verified-without-identity-proof", "preuve d'identité directe obligatoire")
            if not (kinds & TECHNICAL_EVIDENCE):
                _issue(issues, path, "verified-without-technical-proof", "preuve technique obligatoire")
            alert_id = item.get("wazuh_alert_id")
            direct_for_alert = {
                value.get("kind")
                for value in known_evidence
                if alert_id in value.get("observed_in_alert_ids", [])
            }
            if not (direct_for_alert & IDENTITY_EVIDENCE) or not (
                direct_for_alert & TECHNICAL_EVIDENCE
            ):
                _issue(
                    issues,
                    path,
                    "verified-proof-not-bound-to-alert",
                    "les preuves d'identité et technique doivent référencer cet événement",
                )
            if item.get("review_status") != "accepted":
                _issue(issues, path, "verified-not-accepted", "un label vérifié doit être accepté")
        if confidence == "weak" and not known_evidence:
            _issue(issues, path, "weak-without-evidence", "au moins une preuve contextuelle obligatoire")
        if confidence == "unknown":
            if label_class != "unknown" or item.get("activity_id") is not None:
                _issue(issues, path, "invalid-unknown-label", "unknown ne doit pas attribuer une activité")
        if confidence == "conflict":
            if not item.get("label_conflict") or item.get("conflict_id") not in conflict_index:
                _issue(issues, path, "untracked-conflict", "conflit référencé obligatoire")
            if label_class != "unknown" or any(
                item.get(field) is not None
                for field in ("activity_id", "attack_instance_id", "benign_activity_id")
            ):
                _issue(
                    issues,
                    path,
                    "conflict-selects-a-claim",
                    "un conflit non résolu ne doit sélectionner aucune revendication",
                )
        elif item.get("label_conflict"):
            _issue(issues, path, "conflict-confidence-mismatch", "label_conflict exige confidence=conflict")

        if label_class == "attack":
            if activity is None or activity.get("class") != "attack":
                _issue(issues, path, "attack-activity-mismatch", "activité offensive obligatoire")
            elif item.get("attack_instance_id") != activity.get("attack_instance_id"):
                _issue(issues, path, "attack-instance-mismatch", "instance différente de l'activité")
            if item.get("benign_activity_id") is not None:
                _issue(issues, path, "attack-has-benign-id", "identité bénigne interdite")
        elif label_class == "benign":
            if activity is None or activity.get("class") != "benign":
                _issue(issues, path, "benign-activity-mismatch", "activité bénigne obligatoire")
            elif item.get("benign_activity_id") != activity.get("benign_activity_id"):
                _issue(issues, path, "benign-instance-mismatch", "activité bénigne différente")
            if item.get("attack_instance_id") is not None:
                _issue(issues, path, "benign-has-attack-id", "instance d'attaque interdite")

    for index, item in enumerate(conflicts):
        path = f"$.conflicts[{index}]"
        annotation_id = item.get("annotation_id")
        if annotation_id not in annotation_index:
            _issue(issues, f"{path}.annotation_id", "unknown-annotation", str(annotation_id))
        claims = item.get("claims", [])
        if not isinstance(claims, list) or len(claims) < 2:
            _issue(issues, f"{path}.claims", "insufficient-conflict-claims", "au moins deux revendications")
        elif len(
            {
                (
                    claim.get("class"),
                    claim.get("attack_instance_id"),
                    claim.get("benign_activity_id"),
                    claim.get("activity_id"),
                )
                for claim in claims
            }
        ) < 2:
            _issue(
                issues,
                f"{path}.claims",
                "identical-conflict-claims",
                "les revendications doivent réellement être différentes",
            )
        _check_utc(item, ("created_at_utc", "resolved_at_utc"), path, issues)
        if isinstance(claims, list):
            for claim_index, claim in enumerate(claims):
                for evidence_id in claim.get("evidence_ids", []):
                    if evidence_id not in evidence_index:
                        _issue(
                            issues,
                            f"{path}.claims[{claim_index}].evidence_ids",
                            "unknown-evidence",
                            str(evidence_id),
                        )
        if item.get("status") == "resolved" and item.get("resolution_revision_id") not in revision_index:
            _issue(issues, path, "resolution-without-revision", "révision de résolution obligatoire")

    for index, item in enumerate(revisions):
        path = f"$.revisions[{index}]"
        if item.get("annotation_id") not in annotation_index:
            _issue(issues, f"{path}.annotation_id", "unknown-annotation", str(item.get('annotation_id')))
        previous = item.get("previous_revision_id")
        if previous is not None and previous not in revision_index:
            _issue(issues, f"{path}.previous_revision_id", "unknown-revision", str(previous))
        _check_utc(item, ("created_at_utc",), path, issues)

    for section_name, section in (
        ("collection_manifest", collection),
        ("release_manifest", release),
    ):
        if section.get("campaign_id") not in {None, campaign_id}:
            _issue(issues, f"$.{section_name}.campaign_id", "campaign-mismatch", str(section.get('campaign_id')))
        _check_utc(
            section,
            ("created_at_utc", "collected_at_utc", "frozen_at_utc", "since_utc", "until_utc"),
            f"$.{section_name}",
            issues,
        )
        files = section.get("files", [])
        if not isinstance(files, list):
            _issue(issues, f"$.{section_name}.files", "invalid-type", "liste obligatoire")
        else:
            _validate_file_entries(files, f"$.{section_name}.files", issues, root)

    if campaign_id not in release.get("campaign_ids", []):
        _issue(issues, "$.release_manifest.campaign_ids", "missing-campaign", str(campaign_id))
    if raw_event_index is not None and collection.get("alerts_written") != len(raw_event_index):
        _issue(
            issues,
            "$.collection_manifest.alerts_written",
            "raw-event-count-mismatch",
            f"manifest={collection.get('alerts_written')} fixture={len(raw_event_index)}",
        )

    if raise_on_error and issues:
        raise DatasetValidationError(issues)
    return issues


def validate_dataset_bundles(
    bundles: Sequence[Mapping[str, object]],
    *,
    raise_on_error: bool = True,
) -> list[ValidationIssue]:
    """Valide plusieurs campagnes et interdit toute identité inter-partition."""

    issues: list[ValidationIssue] = []
    ownership: dict[tuple[str, str], tuple[str, str]] = {}
    run_ids: dict[str, str] = {}
    for bundle_index, bundle in enumerate(bundles):
        issues.extend(validate_bundle(bundle, raise_on_error=False))
        manifest = bundle.get("campaign_manifest", {})
        if not isinstance(manifest, Mapping):
            continue
        campaign_id = str(manifest.get("campaign_id"))
        partition = str(manifest.get("partition"))
        run_id = str(manifest.get("run_id"))
        if run_id in run_ids and run_ids[run_id] != campaign_id:
            _issue(issues, f"$[{bundle_index}].campaign_manifest.run_id", "cross-campaign-id-reuse", run_id)
        run_ids[run_id] = campaign_id
        activities = bundle.get("activities", [])
        if not isinstance(activities, list):
            continue
        for item in activities:
            for kind, field in (
                ("activity", "activity_id"),
                ("attack", "attack_instance_id"),
                ("benign", "benign_activity_id"),
                ("marker", "marker_id"),
            ):
                value = item.get(field)
                if value is None:
                    continue
                key = (kind, str(value))
                previous = ownership.get(key)
                current = (campaign_id, partition)
                if previous is not None and previous != current:
                    _issue(
                        issues,
                        f"$[{bundle_index}].activities.{field}",
                        "cross-campaign-id-reuse",
                        f"{value} appartient déjà à {previous[0]} ({previous[1]})",
                    )
                else:
                    ownership[key] = current
        for section, id_field in (
            ("evidence", "evidence_id"),
            ("annotations", "annotation_id"),
            ("conflicts", "conflict_id"),
            ("revisions", "revision_id"),
        ):
            values = bundle.get(section, [])
            if not isinstance(values, list):
                continue
            for item in values:
                value = item.get(id_field)
                if value is None:
                    continue
                key = (section, str(value))
                previous = ownership.get(key)
                current = (campaign_id, partition)
                if previous is not None and previous != current:
                    _issue(
                        issues,
                        f"$[{bundle_index}].{section}.{id_field}",
                        "cross-campaign-id-reuse",
                        f"{value} appartient déjà à {previous[0]} ({previous[1]})",
                    )
                else:
                    ownership[key] = current
    if raise_on_error and issues:
        raise DatasetValidationError(issues)
    return issues


def derive_pair_supervision(
    left: Mapping[str, object], right: Mapping[str, object]
) -> dict[str, object]:
    """Dérive une cible sans exposer la vérité dans les caractéristiques."""

    confidences = {left.get("confidence"), right.get("confidence")}
    if confidences & {"unknown", "conflict"}:
        return {"target": None, "confidence": "unknown", "label_reason": "unknown-or-conflict"}
    pair_confidence = "verified" if confidences == {"verified"} else "weak"
    left_class, right_class = left.get("class"), right.get("class")
    if left_class == right_class == "attack":
        same = left.get("attack_instance_id") == right.get("attack_instance_id")
        return {
            "target": int(same),
            "confidence": pair_confidence,
            "label_reason": "same-attack-instance" if same else "different-attack-instances",
        }
    if "attack" in {left_class, right_class} and "benign" in {left_class, right_class}:
        return {"target": 0, "confidence": pair_confidence, "label_reason": "attack-versus-benign"}
    if left_class == right_class == "benign":
        independent = left.get("benign_activity_id") != right.get("benign_activity_id")
        if not independent:
            return {"target": None, "confidence": "unknown", "label_reason": "same-benign-activity"}
        return {"target": 0, "confidence": pair_confidence, "label_reason": "independent-benign-activities"}
    return {"target": None, "confidence": "unknown", "label_reason": "unsupported-label-combination"}
