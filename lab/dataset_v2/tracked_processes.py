"""Registre conservateur des processus et de leurs enfants (PID + create_time)."""
from __future__ import annotations
import subprocess
import threading
import time
from typing import Sequence
import psutil


class TrackedProcessSupervisor:
    def __init__(self):
        self._lock = threading.RLock()
        self._processes = {}
        self._records = {}
        self._events = []
        self._cancelled = False
        self._discovery_errors = {}

    def _remember(self, process, root):
        identity = (process.pid, process.create_time())
        self._records.setdefault(identity, {"pid": process.pid, "create_time": identity[1],
            "root_pid": root, "process": process, "state": "active", "error": None})

    def spawn(self, argv: Sequence[str]):
        with self._lock:
            if self._cancelled:
                raise RuntimeError("superviseur annulé : aucun nouveau lancement")
            kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
            if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True
            process = subprocess.Popen(list(argv), **kwargs)
            self._processes[process.pid] = process
            try:
                self._remember(psutil.Process(process.pid), process.pid)
            except psutil.Error as exc:
                self._records[(process.pid, None)] = {"pid": process.pid, "create_time": None,
                    "root_pid": process.pid, "process": None, "state": "uncertain", "error": type(exc).__name__}
            self._events.append({"event": "spawned", "pid": process.pid})
            return process

    def _check(self, record):
        if record["state"] == "stopped-confirmed":
            return False
        process = record["process"]
        try:
            if process is None:
                root = self._processes.get(record["pid"])
                if root is not None and root.poll() is not None:
                    record["state"] = "stopped-confirmed"
                    return False
                record["state"] = "uncertain"
                return True
            # L'objet psutil mémorise create_time et détecte la réutilisation PID.
            if not process.is_running():
                record["state"] = "stopped-confirmed"
                return False
            return True
        except psutil.NoSuchProcess:
            record["state"] = "stopped-confirmed"
            return False
        except psutil.Error as exc:
            record.update(state="uncertain", error=type(exc).__name__)
            return True

    def _discover(self):
        with self._lock:
            for record in list(self._records.values()):
                if not self._check(record) or record["process"] is None:
                    continue
                try:
                    for child in record["process"].children(recursive=True):
                        self._remember(child, record["root_pid"])
                except psutil.NoSuchProcess:
                    self._check(record)
                except psutil.Error as exc:
                    record.update(state="uncertain", error="children:" + type(exc).__name__)
                    self._discovery_errors[record["root_pid"]] = record["error"]

    def communicate(self, process, *, timeout):
        deadline = time.monotonic() + timeout
        while True:
            self._discover()
            try:
                result = process.communicate(timeout=max(.001, min(.05, deadline-time.monotonic())))
                self.confirm_clean()
                return result
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    cleanup = self.terminate_tree(process.pid)
                    if not cleanup["confirmed_stopped"]:
                        raise RuntimeError(f"nettoyage non confirmé après timeout pid={process.pid}")
                    raise TimeoutError(f"timeout individuel pid={process.pid}")

    def _wait(self, records, seconds):
        deadline = time.monotonic() + seconds
        while True:
            alive = [r for r in records if self._check(r)]
            if not alive or time.monotonic() >= deadline:
                return alive
            time.sleep(min(.02, max(0, deadline-time.monotonic())))

    def terminate_tree(self, root_pid, *, graceful_seconds=1., kill_seconds=2.):
        self._discover()
        with self._lock:
            records = [r for r in self._records.values() if r["root_pid"] == root_pid]
        for action, seconds in (("terminate", graceful_seconds), ("kill", kill_seconds)):
            for record in reversed(records):
                if not self._check(record) or record["process"] is None:
                    continue
                record["state"] = "termination-requested"
                try:
                    getattr(record["process"], action)()
                except psutil.NoSuchProcess:
                    record["state"] = "stopped-confirmed"
                except psutil.Error as exc:
                    record.update(state="uncertain", error=f"{action}:{type(exc).__name__}")
            if not self._wait(records, seconds):
                break
        root = self._processes.get(root_pid)
        if root is not None:
            root.poll()
        result = {"event": "terminated", "root_pid": root_pid,
                  "tracked_pids": sorted({r["pid"] for r in records}),
                  "unconfirmed_pids": sorted({r["pid"] for r in records if self._check(r)}),
                  "confirmed_stopped": not any(self._check(r) for r in records) and root_pid not in self._discovery_errors}
        with self._lock: self._events.append(result)
        return result

    def terminate_all(self):
        with self._lock:
            self._cancelled = True
            roots = list(self._processes)
        results = [self.terminate_tree(pid) for pid in roots]
        return {**self.confirm_clean(), "results": results}

    def confirm_clean(self):
        with self._lock:
            alive = [r for r in self._records.values() if self._check(r)]
            return {"confirmed_stopped": not alive and not self._discovery_errors,
                    "alive_tracked_root_pids": sorted({r["root_pid"] for r in alive}),
                    "unresolved_discovery_errors": dict(self._discovery_errors),
                    "unconfirmed_pids": sorted({r["pid"] for r in alive})}

    def report(self):
        with self._lock:
            return {**self.confirm_clean(), "events": list(self._events),
                    "process_states": [{k:v for k,v in r.items() if k != "process"} for r in self._records.values()],
                    "automatic_retries": 0}
