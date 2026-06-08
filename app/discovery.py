"""Passive / active LAN discovery: mDNS, SSDP/UPnP, NetBIOS."""

import logging
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ZeroconfServiceTypes

log = logging.getLogger(__name__)


# ---------- mDNS ----------

class _MdnsCollector(ServiceListener):
    def __init__(self):
        self.by_ip: dict[str, list[dict]] = {}

    def add_service(self, zc, type_, name):
        try:
            info = zc.get_service_info(type_, name, timeout=2000)
            if not info:
                return
            ips = [socket.inet_ntoa(a) for a in info.addresses if len(a) == 4]
            for ip in ips:
                entry = {
                    "type": type_,
                    "name": name,
                    "port": info.port,
                    "server": (info.server or "").rstrip("."),
                }
                self.by_ip.setdefault(ip, []).append(entry)
        except Exception as e:  # noqa: BLE001
            log.debug("mdns add_service failed: %s", e)

    def update_service(self, zc, type_, name):
        pass

    def remove_service(self, zc, type_, name):
        pass


def discover_mdns(duration: float = 5.0) -> dict[str, list[dict]]:
    """Browse common mDNS service types for `duration` seconds.

    Returns {ip: [{type, name, port, server}, ...]}.
    """
    zc = Zeroconf()
    listener = _MdnsCollector()
    browsers = []
    try:
        types = list(ZeroconfServiceTypes.find(zc=zc, timeout=duration / 2))
    except Exception as e:  # noqa: BLE001
        log.warning("mDNS type discovery failed: %s", e)
        types = [
            "_airplay._tcp.local.", "_googlecast._tcp.local.",
            "_ipp._tcp.local.", "_printer._tcp.local.",
            "_hap._tcp.local.", "_smb._tcp.local.",
            "_workstation._tcp.local.", "_http._tcp.local.",
            "_ssh._tcp.local.", "_raop._tcp.local.",
        ]
    for t in types:
        try:
            browsers.append(ServiceBrowser(zc, t, listener))
        except Exception as e:  # noqa: BLE001
            log.debug("mdns browse %s failed: %s", t, e)
    time.sleep(duration)
    zc.close()
    return listener.by_ip


# ---------- SSDP / UPnP ----------

_SSDP_REQ = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


def _parse_ssdp(payload: bytes) -> dict:
    headers = {}
    for line in payload.decode("utf-8", errors="replace").splitlines()[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def _fetch_upnp_meta(url: str) -> dict:
    try:
        r = requests.get(url, timeout=2)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        ns = ""
        m = re.match(r"\{([^}]+)\}", root.tag)
        if m:
            ns = m.group(1)
        dev = root.find(f"{{{ns}}}device") if ns else root.find("device")
        if dev is None:
            return {}
        get = lambda tag: (dev.findtext(f"{{{ns}}}{tag}" if ns else tag) or "").strip()
        return {
            "friendly_name": get("friendlyName"),
            "manufacturer": get("manufacturer"),
            "model": get("modelName"),
            "device_type": get("deviceType"),
        }
    except Exception as e:  # noqa: BLE001
        log.debug("UPnP meta fetch failed for %s: %s", url, e)
        return {}


def discover_ssdp(duration: float = 4.0) -> dict[str, list[dict]]:
    """Return {ip: [{server, location, st, usn, friendly_name, manufacturer, model}, ...]}."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    by_ip: dict[str, list[dict]] = {}
    seen_locations: set[str] = set()
    try:
        sock.sendto(_SSDP_REQ, ("239.255.255.250", 1900))
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                continue
            ip = addr[0]
            h = _parse_ssdp(data)
            entry = {
                "server": h.get("server"),
                "location": h.get("location"),
                "st": h.get("st"),
                "usn": h.get("usn"),
            }
            loc = entry.get("location")
            if loc and loc not in seen_locations:
                seen_locations.add(loc)
                entry.update(_fetch_upnp_meta(loc))
                # Use location host for IP key if it differs from source.
                try:
                    p = urlparse(loc)
                    if p.hostname:
                        ip = p.hostname
                except Exception:
                    pass
            by_ip.setdefault(ip, []).append(entry)
    finally:
        sock.close()
    # De-dupe per IP by (st, usn).
    for ip, items in by_ip.items():
        unique, seen = [], set()
        for it in items:
            key = (it.get("st"), it.get("usn"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(it)
        by_ip[ip] = unique
    return by_ip


# ---------- NetBIOS ----------

_NMB_LINE = re.compile(r"^\s*(\S+)\s+<([0-9A-Fa-f]{2})>\s+-\s+(.*)$")


def netbios_name(ip: str, timeout: float = 2.0) -> str | None:
    """Use nmblookup -A to query NetBIOS name for an IP."""
    try:
        out = subprocess.check_output(
            ["nmblookup", "-A", ip],
            text=True, timeout=timeout, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    workstation = None
    for line in out.splitlines():
        m = _NMB_LINE.match(line)
        if not m:
            continue
        name, code, flags = m.group(1), m.group(2).upper(), m.group(3)
        if "GROUP" in flags:
            continue
        # <00> = Workstation service; the first one is usually the host name.
        if code == "00" and not workstation:
            workstation = name
    return workstation


def discover_netbios(ips: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for ip in ips:
        name = netbios_name(ip)
        if name:
            out[ip] = name
    return out
