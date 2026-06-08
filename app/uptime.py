"""Background uptime poller.

Periodically pings every known host (one-off ICMP), records up/down state
and round-trip time, and prunes samples older than 30 days.
"""

import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

from . import db

log = logging.getLogger(__name__)

_RTT = re.compile(r"time[=<]([\d.]+)\s*ms")
_thread: threading.Thread | None = None
_stop = threading.Event()


def _now():
    return datetime.now(timezone.utc)


def ping(ip: str, timeout: float = 1.0) -> tuple[bool, float | None]:
    try:
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", str(int(max(1, timeout))), "-n", ip],
            text=True, stderr=subprocess.DEVNULL, timeout=timeout + 2,
        )
        m = _RTT.search(out)
        return True, float(m.group(1)) if m else None
    except subprocess.CalledProcessError:
        return False, None
    except (FileNotFoundError, subprocess.SubprocessError):
        return False, None


def sweep_once():
    ts = _now().isoformat(timespec="seconds")
    with db.get_db() as conn:
        rows = conn.execute("SELECT id, ip FROM hosts").fetchall()
    for r in rows:
        up, rtt = ping(r["ip"])
        db.record_status(r["id"], up, rtt, ts)
    # Prune old samples (>30 days).
    cutoff = (_now() - timedelta(days=30)).isoformat(timespec="seconds")
    db.prune_status(cutoff)


def _loop(interval: int):
    log.info("Uptime poller started (interval=%ds)", interval)
    # Stagger first sweep so the app finishes startup first.
    if _stop.wait(min(15, interval)):
        return
    while not _stop.is_set():
        try:
            sweep_once()
        except Exception as e:  # noqa: BLE001
            log.warning("Uptime sweep failed: %s", e)
        if _stop.wait(interval):
            return


def start():
    global _thread
    interval = int(os.environ.get("NETSCAN_UPTIME_INTERVAL", "300"))
    if interval <= 0:
        log.info("Uptime poller disabled (NETSCAN_UPTIME_INTERVAL=0)")
        return
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(interval,), daemon=True,
                               name="uptime-poller")
    _thread.start()


def stop():
    _stop.set()
