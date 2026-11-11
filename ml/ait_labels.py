"""Adaptation conservative des labels AIT-ADS vers une vérité terrain canonique."""

from __future__ import annotations

from dataclasses import asdict, dataclass


ATTACK_A_PHASES = frozenset(
    {
        "network_scans",
        "service_scans",
        "wpscan",
        "dirb",
        "webshell",
        "cracking",
        "reverse_shell",
        "privilege_escalation",
    }
)

ATTACK_B_PHASES = frozenset({"service_stop", "dnsteal"})

# Les noms proviennent de get_ts_label() dans le dépôt officiel AIT-ADS.
EVENT_TO_PHASE = {
    "dns_scan": "network_scans",
    "service_scan": "service_scans",
    "wpscan": "wpscan",
    "dirb": "dirb",
    "webshell_cmd": "webshell",
    "crack_passwords": "cracking",
    "online_cracking": "cracking",
    "attacker_change_user": "privilege_escalation",
    "escalated_sudo_command": "privilege_escalation",
    "dnsteal": "dnsteal",
}


@dataclass(frozen=True)
class LabelDecision:
    scenario_id: str
    time_phase: str | None
    event_phase: str | None
    selected_phase: str | None
    attack_family: str | None
    attack_instance_id: str | None
    is_attack: bool | None
    label_source: str
    label_confidence: str
    label_conflict: bool
    raw_time_label: str
    raw_event_label: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def attack_family_for_phase(phase: str | None) -> str | None:
    if phase in ATTACK_A_PHASES:
        return "A"
    if phase in ATTACK_B_PHASES:
        return "B"
    return None


def _time_phase(raw_label: str) -> str | None:
    label = raw_label.strip()
    return label if label in ATTACK_A_PHASES or label in ATTACK_B_PHASES else None


def adapt_label(scenario: str, time_label: str, event_label: str) -> LabelDecision:
    """Retourne une décision sans convertir les valeurs ambiguës en certitudes.

    Un label événementiel reconnu est prioritaire sur une fenêtre temporelle.
    Un tiret dans ``event_label`` signifie seulement que l'événement n'est pas
    labellisé individuellement.
    """

    raw_time = (time_label or "").strip()
    raw_event = (event_label or "").strip()
    time_phase = _time_phase(raw_time)
    event_phase = EVENT_TO_PHASE.get(raw_event)

    if event_phase is not None:
        family = attack_family_for_phase(event_phase)
        return LabelDecision(
            scenario_id=scenario,
            time_phase=time_phase,
            event_phase=event_phase,
            selected_phase=event_phase,
            attack_family=family,
            attack_instance_id=f"{scenario}:{family}" if family else None,
            is_attack=True,
            label_source="event",
            label_confidence="high",
            label_conflict=time_phase != event_phase,
            raw_time_label=raw_time,
            raw_event_label=raw_event,
        )

    if raw_event not in {"", "-"}:
        return LabelDecision(
            scenario_id=scenario,
            time_phase=time_phase,
            event_phase=None,
            selected_phase=None,
            attack_family=None,
            attack_instance_id=None,
            is_attack=None,
            label_source="unknown",
            label_confidence="unknown",
            label_conflict=False,
            raw_time_label=raw_time,
            raw_event_label=raw_event,
        )

    if time_phase is not None:
        family = attack_family_for_phase(time_phase)
        return LabelDecision(
            scenario_id=scenario,
            time_phase=time_phase,
            event_phase=None,
            selected_phase=time_phase,
            attack_family=family,
            attack_instance_id=f"{scenario}:{family}" if family else None,
            is_attack=True,
            label_source="time",
            label_confidence="weak",
            label_conflict=False,
            raw_time_label=raw_time,
            raw_event_label=raw_event,
        )

    if raw_time.startswith("false_positive"):
        return LabelDecision(
            scenario_id=scenario,
            time_phase=None,
            event_phase=None,
            selected_phase=None,
            attack_family=None,
            attack_instance_id=None,
            is_attack=False,
            label_source="time",
            label_confidence="weak",
            label_conflict=False,
            raw_time_label=raw_time,
            raw_event_label=raw_event,
        )

    return LabelDecision(
        scenario_id=scenario,
        time_phase=time_phase,
        event_phase=None,
        selected_phase=None,
        attack_family=None,
        attack_instance_id=None,
        is_attack=None,
        label_source="unknown",
        label_confidence="unknown",
        label_conflict=False,
        raw_time_label=raw_time,
        raw_event_label=raw_event,
    )

