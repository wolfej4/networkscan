import ipaddress
import socket
import subprocess
from datetime import datetime, timezone

import nmap

from . import db


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def detect_local_cidr():
    """Best-effort detection of the host's primary IPv4 /24."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "get", "1.1.1.1"], text=True, timeout=2
        )
        # Example: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.42 uid 0"
        parts = out.split()
        if "src" in parts:
            ip = parts[parts.index("src") + 1]
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
    except Exception:
        pass
    return None


def gateway_ip():
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "show", "default"], text=True, timeout=2
        )
        parts = out.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except Exception:
        return None
    return None


def _scan_arguments(profile):
    """Return nmap arguments for a given profile.

    quick    : ping sweep + top 100 ports, no OS detection (fastest)
    standard : top 1000 ports, service detection
    deep     : full TCP scan + OS detection (slow, needs root)
    """
    if profile == "quick":
        return "-T4 --top-ports 100 -sV --version-light -n"
    if profile == "deep":
        return "-T4 -p- -sV -O --osscan-guess -n"
    return "-T4 --top-ports 1000 -sV -O --osscan-guess -n"


def run_scan(target, profile="standard"):
    """Run an nmap scan against target (CIDR or IP) and persist results.

    Returns (scan_id, summary_dict). Raises on fatal errors.
    """
    started = _now()
    scan_id = db.create_scan(target, started)

    try:
        # Validate target parses as a network or IP.
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            try:
                ipaddress.ip_address(target)
            except ValueError as e:
                raise ValueError(f"Invalid target '{target}': {e}")

        nm = nmap.PortScanner()
        args = _scan_arguments(profile)
        nm.scan(hosts=target, arguments=args)

        found = 0
        with db.get_db() as conn:
            for host in nm.all_hosts():
                h = nm[host]
                state = h.state()
                if state != "up":
                    continue
                found += 1

                ip = host
                addresses = h.get("addresses", {}) or {}
                mac = addresses.get("mac")
                vendor_map = h.get("vendor", {}) or {}
                vendor = vendor_map.get(mac) if mac else None

                hostname = h.hostname() or None
                if not hostname:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = None

                os_name = None
                osmatches = h.get("osmatch") or []
                if osmatches:
                    os_name = osmatches[0].get("name")

                ts = _now()
                host_id = db.upsert_host(conn, ip, mac, vendor, hostname, os_name, state, ts)

                for proto in h.all_protocols():
                    for port in h[proto].keys():
                        p = h[proto][port]
                        db.upsert_port(
                            conn,
                            host_id,
                            int(port),
                            proto,
                            p.get("state"),
                            p.get("name"),
                            p.get("product"),
                            p.get("version"),
                            ts,
                        )

        db.finish_scan(scan_id, "complete", f"{found} host(s) up", _now())
        return scan_id, {"hosts_found": found}

    except Exception as e:  # noqa: BLE001 - we want to log any nmap failure
        db.finish_scan(scan_id, "error", str(e), _now())
        raise
