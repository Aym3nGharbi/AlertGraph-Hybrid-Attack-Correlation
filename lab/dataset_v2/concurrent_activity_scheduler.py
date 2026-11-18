"""Ordonnanceur V2 à époque commune, sans action réseau ni retry implicite."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence


@dataclass(frozen=True)
class ScheduledActivity:
    key: str
    order: int
    offset_seconds: float
    maximum_duration_seconds: float


def schedule_from_plan(activities: Sequence[Mapping[str, object]]) -> list[ScheduledActivity]:
    result = []
    for row in activities:
        item = ScheduledActivity(
            key=str(row.get("activity_key") or row.get("key") or ""),
            order=int(row["execution_order"]),
            offset_seconds=float(row["planned_offset_seconds"]),
            maximum_duration_seconds=float(row["maximum_duration_seconds"]),
        )
        if not item.key or item.offset_seconds < 0 or item.maximum_duration_seconds <= 0:
            raise ValueError("activité concurrente invalide")
        result.append(item)
    if len({item.key for item in result}) != len(result):
        raise ValueError("clé d'activité concurrente réutilisée")
    return sorted(result, key=lambda item: item.order)


def run_concurrent_schedule(
    activities: Sequence[Mapping[str, object]],
    worker: Callable[[str], object],
    *,
    maximum_start_lateness_seconds: float,
    global_grace_seconds: float = 5.0,
    monotonic: Callable[[], float] = time.monotonic,
    critical_failure_callback: Callable[[], object] | None = None,
    cleanup_wait_seconds: float = 5.0,
) -> dict[str, object]:
    """Lance chaque activité par rapport à la même époque monotone.

    Une erreur annule les activités qui n'ont pas encore démarré. Les activités
    déjà lancées ne sont jamais répétées et terminent sous leur propre timeout.
    """

    schedule = schedule_from_plan(activities)
    if maximum_start_lateness_seconds < 0 or global_grace_seconds < 0:
        raise ValueError("bornes temporelles invalides")
    barrier = threading.Barrier(len(schedule) + 1)
    cancel = threading.Event()
    lock = threading.Lock()
    results: dict[str, dict[str, object]] = {}
    epoch_box: list[float] = []
    callback_lock = threading.Lock(); callback_called = False
    cleanup_failures = []

    def critical_failure() -> None:
        nonlocal callback_called
        cancel.set()
        if critical_failure_callback is not None:
            with callback_lock:
                if not callback_called:
                    callback_called = True
                    try:
                        cleanup = critical_failure_callback()
                        if isinstance(cleanup, dict) and cleanup.get("confirmed_stopped") is False:
                            cleanup_failures.append(cleanup)
                    except Exception as exc:
                        cleanup_failures.append({"error_type": type(exc).__name__, "error": str(exc)})

    def execute(item: ScheduledActivity) -> None:
        barrier.wait()
        epoch = epoch_box[0]
        target = epoch + item.offset_seconds
        while not cancel.is_set():
            remaining = target - monotonic()
            if remaining <= 0:
                break
            cancel.wait(min(remaining, 0.05))
        if cancel.is_set():
            with lock:
                results[item.key] = {
                    "activity_key": item.key, "execution_order": item.order,
                    "status": "cancelled-before-start", "planned_offset_seconds": item.offset_seconds,
                    "started": False,
                }
            return
        started = monotonic(); actual_offset = started - epoch
        if actual_offset - item.offset_seconds > maximum_start_lateness_seconds:
            critical_failure()
            with lock:
                results[item.key] = {
                    "activity_key": item.key, "execution_order": item.order,
                    "status": "start-lateness-exceeded", "planned_offset_seconds": item.offset_seconds,
                    "actual_start_offset_seconds": actual_offset, "started": False,
                }
            return
        try:
            value = worker(item.key)
            ended = monotonic(); elapsed = ended - started
            if elapsed > item.maximum_duration_seconds:
                raise TimeoutError(f"durée maximale dépassée pour {item.key}")
            row = {
                "activity_key": item.key, "execution_order": item.order, "status": "completed",
                "planned_offset_seconds": item.offset_seconds,
                "actual_start_offset_seconds": actual_offset,
                "completed_offset_seconds": ended - epoch,
                "duration_seconds": elapsed, "started": True, "result": value,
            }
        except Exception as exc:
            critical_failure()
            row = {
                "activity_key": item.key, "execution_order": item.order, "status": "failed",
                "planned_offset_seconds": item.offset_seconds,
                "actual_start_offset_seconds": actual_offset,
                "completed_offset_seconds": monotonic() - epoch, "started": True,
                "error_type": type(exc).__name__, "error": str(exc),
            }
        with lock:
            results[item.key] = row

    threads = [threading.Thread(target=execute, args=(item,), name=f"agv2-{item.key}") for item in schedule]
    for thread in threads:
        thread.start()
    epoch_box.append(monotonic())
    barrier.wait()
    global_deadline = epoch_box[0] + max(
        item.offset_seconds + item.maximum_duration_seconds for item in schedule
    ) + global_grace_seconds
    for thread in threads:
        thread.join(max(0.0, global_deadline - monotonic()))
    alive = [thread.name for thread in threads if thread.is_alive()]
    if alive:
        critical_failure()
        for thread in threads:
            thread.join(cleanup_wait_seconds)
        alive = [thread.name for thread in threads if thread.is_alive()]
        if alive:
            raise RuntimeError("nettoyage non confirmé; activités encore actives: " + ",".join(alive))
        raise TimeoutError("timeout global; processus suivis nettoyés")
    ordered = [results[item.key] for item in schedule]
    return {
        "common_epoch_monotonic": epoch_box[0],
        "activities": ordered,
        "cancelled": cancel.is_set(),
        "all_completed": all(row["status"] == "completed" for row in ordered) and not cleanup_failures,
        "cleanup_failures": cleanup_failures,
        "automatic_retries": 0,
    }
