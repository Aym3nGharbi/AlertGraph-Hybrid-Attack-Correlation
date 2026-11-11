"""Observateur TCP persistant non privilégié basé sur psutil."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Callable, Iterable

import psutil


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PersistentSocketObserver:
    """Échantillonne la table TCP après avoir signalé explicitement ``ready``."""

    def __init__(
        self, target_ip: str, target_port: int,
        *, poll_interval_seconds: float = 0.001,
        provider: Callable[[], Iterable[object]] | None = None,
    ) -> None:
        if poll_interval_seconds < 0:
            raise ValueError("poll_interval_seconds doit être positif ou nul")
        self.target_ip = target_ip; self.target_port = int(target_port)
        self.poll_interval_seconds = poll_interval_seconds
        self._provider = provider or (lambda: psutil.net_connections(kind="tcp"))
        self._ready = threading.Event(); self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock(); self._observations: list[dict[str, object]] = []
        self._errors: list[str] = []; self._scans = 0
        self.started_at_utc: str | None = None
        self.ready_at_utc: str | None = None
        self.stopped_at_utc: str | None = None

    def start(self, timeout: float = 5.0) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("L'observateur est déjà actif")
        self._stop.clear(); self._ready.clear()
        self.started_at_utc = _utc_now(); self.ready_at_utc = None; self.stopped_at_utc = None
        self._thread = threading.Thread(target=self._loop, name="alertgraph-tcp-observer", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            self.stop(); raise TimeoutError("L'observateur TCP n'est pas devenu prêt")
        if self._errors:
            self.stop(); raise RuntimeError(self._errors[0])

    def _loop(self) -> None:
        first_scan = True
        while not self._stop.is_set():
            scan_started_utc = _utc_now(); scan_started_ns = time.monotonic_ns()
            try:
                connections = list(self._provider()); self._scans += 1
                for connection in connections:
                    remote = getattr(connection, "raddr", None); local = getattr(connection, "laddr", None)
                    if not remote or not local:
                        continue
                    remote_ip = getattr(remote, "ip", remote[0]); remote_port = int(getattr(remote, "port", remote[1]))
                    if remote_ip != self.target_ip or remote_port != self.target_port:
                        continue
                    local_ip = getattr(local, "ip", local[0]); local_port = int(getattr(local, "port", local[1]))
                    item = {
                        "observed_at_utc": scan_started_utc, "observed_at_monotonic_ns": scan_started_ns,
                        "pid": getattr(connection, "pid", None), "status": str(getattr(connection, "status", "")),
                        "source_ip": str(local_ip), "source_port": local_port,
                        "target_ip": str(remote_ip), "target_port": remote_port,
                        "observer": "psutil-net-connections-persistent-v1",
                    }
                    with self._lock:
                        self._observations.append(item)
            except Exception as exc:
                self._errors.append(f"{type(exc).__name__}:{exc}")
            finally:
                if first_scan:
                    self.ready_at_utc = _utc_now()
                    self._ready.set(); first_scan = False
            if self.poll_interval_seconds:
                self._stop.wait(self.poll_interval_seconds)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
            if self._thread.is_alive():
                raise TimeoutError("L'observateur TCP ne s'est pas arrêté")
        self.stopped_at_utc = _utc_now()

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and self._thread is not None and self._thread.is_alive()

    def observations(self, *, pid: int | None = None) -> list[dict[str, object]]:
        with self._lock:
            items = [dict(x) for x in self._observations]
        return [x for x in items if pid is None or x["pid"] == pid]

    def health(self) -> dict[str, object]:
        return {
            "started_at_utc": self.started_at_utc, "ready_at_utc": self.ready_at_utc,
            "stopped_at_utc": self.stopped_at_utc, "scans": self._scans,
            "observations": len(self.observations()), "errors": list(self._errors),
        }

    def __enter__(self):
        self.start(); return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
