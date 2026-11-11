#!/usr/bin/env python3
"""Fusionne plusieurs propositions d'instances en refusant tout conflit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()
    proposals = {}
    for path in args.inputs:
        document = json.loads(path.read_text(encoding="utf-8"))
        for alert_id, value in document["proposals"].items():
            previous = proposals.get(alert_id)
            if previous and previous["attack_instance_id"] != value["attack_instance_id"]:
                raise ValueError(f"Conflit d'instance pour {alert_id}")
            proposals[alert_id] = value
    result = {
        "policy": "unlisted alerts are unknown, never implicitly benign",
        "sources": [str(x) for x in args.inputs],
        "proposals": proposals,
        "counts": {"proposed_attack": len(proposals)},
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], indent=2))


if __name__ == "__main__":
    main()
