"""Offline OUI -> vendor lookup using the IEEE MA-L CSV."""

import csv
import logging
import os
import threading

log = logging.getLogger(__name__)

_OUI_PATH = os.environ.get("NETSCAN_OUI_CSV", "/app/data/oui.csv")
_table: dict[str, str] = {}
_loaded = False
_lock = threading.Lock()


def _normalize(mac: str) -> str:
    return "".join(c for c in mac.lower() if c in "0123456789abcdef")


def _load():
    global _loaded
    with _lock:
        if _loaded:
            return
        _loaded = True
        if not os.path.exists(_OUI_PATH):
            log.warning("OUI CSV not found at %s", _OUI_PATH)
            return
        try:
            with open(_OUI_PATH, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = (row.get("Assignment") or "").strip().lower()
                    org = (row.get("Organization Name") or "").strip()
                    if len(prefix) == 6 and org:
                        _table[prefix] = org
            log.info("Loaded %d OUI entries", len(_table))
        except Exception as e:  # noqa: BLE001
            log.warning("OUI load failed: %s", e)


def vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    _load()
    norm = _normalize(mac)
    if len(norm) < 6:
        return None
    return _table.get(norm[:6])
