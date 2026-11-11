"""Primitives d'écriture atomique et d'empreinte pour la V2."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def write_new_bytes(path: str | Path, payload: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def write_new_json(path: str | Path, document: object) -> None:
    write_new_bytes(path, canonical_json_bytes(document))


def replace_json_atomic(path: str | Path, document: object) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".part")
    if temporary.exists():
        raise FileExistsError(f"Écriture atomique déjà en cours: {temporary}")
    write_new_bytes(temporary, canonical_json_bytes(document))
    os.replace(temporary, target)


def load_json(path: str | Path) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))
