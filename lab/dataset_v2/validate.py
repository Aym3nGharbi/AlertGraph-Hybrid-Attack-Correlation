"""Interface en lecture seule du validateur AlertGraph Wazuh V2."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .synthetic_fixture import synthetic_bundle
from .validators import DatasetValidationError, validate_bundle


def validation_summary(bundle: dict[str, object]) -> dict[str, object]:
    return {
        "valid": True,
        "campaign_id": bundle["campaign_manifest"]["campaign_id"],
        "partition": bundle["campaign_manifest"]["partition"],
        "raw_events": len(bundle.get("raw_events", [])),
        "activities": len(bundle["activities"]),
        "evidence": len(bundle["evidence"]),
        "annotations": len(bundle["annotations"]),
        "conflicts": len(bundle["conflicts"]),
        "training_ready": bundle["release_manifest"]["training_ready"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle", type=Path, help="bundle JSON V2 à valider")
    source.add_argument("--synthetic", action="store_true", help="valide le fixture intégré")
    parser.add_argument(
        "--base-dir",
        type=Path,
        help="racine utilisée pour vérifier les fichiers et leurs SHA-256",
    )
    args = parser.parse_args()
    bundle = (
        synthetic_bundle()
        if args.synthetic
        else json.loads(args.bundle.read_text(encoding="utf-8"))
    )
    try:
        validate_bundle(bundle, base_dir=args.base_dir)
    except DatasetValidationError as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "issue_count": len(exc.issues),
                    "issues": [
                        {"path": x.path, "code": x.code, "message": x.message}
                        for x in exc.issues
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        raise SystemExit(2) from exc
    print(json.dumps(validation_summary(bundle), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
