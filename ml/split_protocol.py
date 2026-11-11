"""Découpage imbriqué par scénario, sans fuite entre paires apparentées."""

from __future__ import annotations

from dataclasses import asdict, dataclass


AIT_SCENARIOS = (
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
)


@dataclass(frozen=True)
class InnerFold:
    validation_scenario: str
    train_scenarios: tuple[str, ...]


@dataclass(frozen=True)
class OuterFold:
    test_scenario: str
    development_scenarios: tuple[str, ...]
    inner_folds: tuple[InnerFold, ...]


def nested_leave_one_scenario_out(
    scenarios: tuple[str, ...] = AIT_SCENARIOS,
) -> tuple[OuterFold, ...]:
    """Construit un LOSO externe et interne entièrement déterministe."""

    unique = tuple(dict.fromkeys(item.strip() for item in scenarios if item.strip()))
    if len(unique) < 3:
        raise ValueError("Au moins trois scénarios distincts sont nécessaires")

    outer_folds = []
    for test in unique:
        development = tuple(item for item in unique if item != test)
        inner = tuple(
            InnerFold(
                validation_scenario=validation,
                train_scenarios=tuple(
                    item for item in development if item != validation
                ),
            )
            for validation in development
        )
        outer_folds.append(
            OuterFold(
                test_scenario=test,
                development_scenarios=development,
                inner_folds=inner,
            )
        )
    return tuple(outer_folds)


def validate_folds(
    folds: tuple[OuterFold, ...],
    scenarios: tuple[str, ...] = AIT_SCENARIOS,
) -> None:
    expected = set(scenarios)
    if {fold.test_scenario for fold in folds} != expected:
        raise ValueError("Chaque scénario doit apparaître exactement en test externe")

    for outer in folds:
        development = set(outer.development_scenarios)
        if development | {outer.test_scenario} != expected:
            raise ValueError("Partition externe incomplète")
        if outer.test_scenario in development:
            raise ValueError("Fuite du scénario de test dans le développement")
        if {fold.validation_scenario for fold in outer.inner_folds} != development:
            raise ValueError("Chaque scénario de développement doit servir en validation")
        for inner in outer.inner_folds:
            train = set(inner.train_scenarios)
            if inner.validation_scenario in train or outer.test_scenario in train:
                raise ValueError("Chevauchement train/validation/test")
            if train | {inner.validation_scenario} != development:
                raise ValueError("Partition interne incomplète")


def manifest() -> dict[str, object]:
    folds = nested_leave_one_scenario_out()
    validate_folds(folds)
    return {
        "strategy": "nested-leave-one-scenario-out",
        "group_key": "scenario_id",
        "outer_folds": [asdict(fold) for fold in folds],
    }

