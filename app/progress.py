"""Shared progress state for a running scan/discovery job.

A single dict, mutated by the background scan thread and read by the
Flask request handlers. CPython dict ops are atomic enough for reads,
but writes that touch multiple keys are guarded by a lock.
"""

import threading
import time

PHASES = ["idle", "nmap", "mdns", "ssdp", "netbios", "traceroute", "snmp", "done"]

_lock = threading.Lock()
_state: dict = {}


def reset(target: str | None = None):
    with _lock:
        _state.clear()
        _state.update({
            "phase": "starting",
            "percent": 0.0,
            "message": "Starting…",
            "eta_seconds": None,
            "started_at": time.time(),
            "target": target,
            "hosts_found": 0,
        })


def update(**kw):
    with _lock:
        _state.update(kw)


def finish(message: str = "Done", error: bool = False):
    with _lock:
        _state["phase"] = "error" if error else "done"
        _state["percent"] = 100.0
        _state["message"] = message
        _state["eta_seconds"] = None


def snapshot() -> dict:
    with _lock:
        s = dict(_state)
    if s.get("started_at"):
        s["elapsed_seconds"] = int(time.time() - s["started_at"])
    return s
