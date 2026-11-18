"""Identité UUID des boots Linux ; aucune mutation des preuves sources."""
import re
import uuid

_FORM = re.compile(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\Z")


def canonical_boot_id(value):
    if not isinstance(value, str) or not _FORM.fullmatch(value):
        raise ValueError("BootId UUID absent ou invalide")
    return uuid.UUID(value).hex


def same_boot_id(left, right):
    try:
        return canonical_boot_id(left) == canonical_boot_id(right)
    except ValueError:
        return False
