"""Fondations isolées de la base supervisée Wazuh V2."""

from .marker_normalization import (
    SUPERVISION_ONLY_FIELDS,
    assert_feature_record_has_no_supervision,
    normalize_instrumentation_markers,
)
from .validators import (
    DatasetValidationError,
    ValidationIssue,
    derive_pair_supervision,
    validate_bundle,
    validate_dataset_bundles,
)

__all__ = [
    "DatasetValidationError",
    "SUPERVISION_ONLY_FIELDS",
    "ValidationIssue",
    "assert_feature_record_has_no_supervision",
    "derive_pair_supervision",
    "normalize_instrumentation_markers",
    "validate_bundle",
    "validate_dataset_bundles",
]
