"""Topology discovery via traceroute and SNMP LLDP/CDP."""

import logging
import os
import re
import subprocess
from datetime import datetime, timezone

from . import db

log = logging.getLogger(__name__)

SELF = "__self__"


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_TRACE_HOP = re.compile(r"^\s*(\d+)\s+(\S+)")


def traceroute(ip: str, max_hops: int = 12, timeout: float = 15.0) -> list[str]:
    """Return ordered list of intermediate hop IPs (final target excluded)."""
    cmd = ["traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops), ip]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=timeout,
                                      stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        log.debug("traceroute %s failed: %s", ip, e)
        return []

    hops: list[str] = []
    for line in out.splitlines():
        m = _TRACE_HOP.match(line)
        if not m:
            continue
        host = m.group(2)
        if host == "*":
            continue
        hops.append(host)
    # Drop the destination itself from the path if present.
    if hops and hops[-1] == ip:
        hops = hops[:-1]
    return hops


def traceroute_and_store(ip: str):
    """Run traceroute against a single IP and persist hop links."""
    ts = _now()
    hops = traceroute(ip)
    prev = SELF
    for i, hop in enumerate(hops):
        db.upsert_link(prev, hop, "traceroute", i, ts)
        prev = hop
    db.upsert_link(prev, ip, "traceroute", len(hops), ts)


def map_topology(target_ips: list[str]):
    """Run traceroute against each target IP and persist hop links."""
    for ip in target_ips:
        traceroute_and_store(ip)


# ---------- SNMP / LLDP ----------

LLDP_REM_SYS_NAME = ".1.0.8802.1.1.2.1.4.1.1.9"   # lldpRemSysName
LLDP_REM_PORT_ID = ".1.0.8802.1.1.2.1.4.1.1.7"    # lldpRemPortId
CDP_CACHE_DEVICE_ID = ".1.3.6.1.4.1.9.9.23.1.2.1.1.6"  # cdpCacheDeviceId

_OID_LINE = re.compile(r"^(\S+)\s*=\s*\S+:\s*(.*)$")


def _snmpwalk(target: str, community: str, oid: str, timeout: int = 3) -> list[tuple[str, str]]:
    try:
        out = subprocess.check_output(
            ["snmpwalk", "-v2c", "-c", community, "-t", str(timeout),
             "-r", "1", "-Onq", target, oid],
            text=True, timeout=timeout + 2, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    pairs = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # -Onq gives "<oid> <value>"
        parts = line.split(None, 1)
        if len(parts) == 2:
            pairs.append((parts[0], parts[1].strip('"')))
    return pairs


def snmp_neighbors(target: str, community: str) -> list[dict]:
    """Best-effort LLDP + CDP neighbor walk for a single SNMP-speaking device."""
    if not community:
        return []
    neighbors = []
    for oid, source in ((LLDP_REM_SYS_NAME, "lldp"), (CDP_CACHE_DEVICE_ID, "cdp")):
        for _, name in _snmpwalk(target, community, oid):
            if name:
                neighbors.append({"source": source, "name": name})
    return neighbors


def snmp_walk_and_store(ip: str, community: str | None = None):
    community = community or os.environ.get("NETSCAN_SNMP_COMMUNITY", "")
    if not community:
        return
    ts = _now()
    for n in snmp_neighbors(ip, community):
        db.upsert_link(ip, n["name"], n["source"], None, ts)


def map_snmp(target_ips: list[str], community: str | None = None):
    community = community or os.environ.get("NETSCAN_SNMP_COMMUNITY", "")
    if not community:
        return
    for ip in target_ips:
        snmp_walk_and_store(ip, community)
