import ipaddress
import logging
import socket
import subprocess
from datetime import datetime, timezone

import nmap

from . import db, device_type, discovery, oui, topology

log = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def detect_local_cidr():
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "get", "1.1.1.1"], text=True, timeout=2
        )
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
    if profile == "quick":
        return "-T4 --top-ports 100 -sV --version-light -n"
    if profile == "deep":
        return "-T4 -p- -sV -O --osscan-guess -n"
    return "-T4 --top-ports 1000 -sV -O --osscan-guess -n"


def _enrich_after_scan(scanned_ips: list[str], gw: str | None):
    """Run mDNS/SSDP/NetBIOS + topology + classification for the given IPs."""
    log.info("Enriching %d hosts", len(scanned_ips))

    try:
        mdns_by_ip = discovery.discover_mdns(duration=5.0)
    except Exception as e:  # noqa: BLE001
        log.warning("mDNS discovery failed: %s", e)
        mdns_by_ip = {}

    try:
        ssdp_by_ip = discovery.discover_ssdp(duration=4.0)
    except Exception as e:  # noqa: BLE001
        log.warning("SSDP discovery failed: %s", e)
        ssdp_by_ip = {}

    try:
        nb_by_ip = discovery.discover_netbios(scanned_ips)
    except Exception as e:  # noqa: BLE001
        log.warning("NetBIOS discovery failed: %s", e)
        nb_by_ip = {}

    # Persist enrichment + classify.
    with db.get_db() as conn:
        for ip in set(scanned_ips) | set(mdns_by_ip) | set(ssdp_by_ip) | set(nb_by_ip):
            host_id = db.host_id_for_ip(conn, ip)
            if not host_id:
                continue
            row = conn.execute(
                "SELECT mac, vendor FROM hosts WHERE id=?", (host_id,)
            ).fetchone()
            mac = row["mac"] if row else None
            existing_vendor = row["vendor"] if row else None
            vendor_guess = existing_vendor or oui.vendor(mac)

            mdns = mdns_by_ip.get(ip, [])
            ssdp = ssdp_by_ip.get(ip, [])
            nb = nb_by_ip.get(ip)

            ports = [dict(p) for p in conn.execute(
                "SELECT port, state FROM ports WHERE host_id=?", (host_id,)
            ).fetchall()]

            dtype = device_type.classify(
                vendor=vendor_guess,
                ports=ports,
                mdns=mdns,
                ssdp=ssdp,
                netbios=nb,
                is_gateway=(gw is not None and ip == gw),
            )

            db.update_host_enrichment(
                conn, host_id,
                vendor=vendor_guess,
                device_type=dtype,
                mdns=mdns,
                ssdp=ssdp,
                netbios=nb,
            )

    # Topology: traceroute to every host (cheap on LAN), plus SNMP/LLDP.
    try:
        topology.map_topology(scanned_ips)
    except Exception as e:  # noqa: BLE001
        log.warning("Traceroute mapping failed: %s", e)
    try:
        topology.map_snmp(scanned_ips)
    except Exception as e:  # noqa: BLE001
        log.warning("SNMP mapping failed: %s", e)


def run_scan(target, profile="standard", enrich=True):
    started = _now()
    scan_id = db.create_scan(target, started)
    scanned_ips: list[str] = []

    try:
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
                scanned_ips.append(host)

                ip = host
                addresses = h.get("addresses", {}) or {}
                mac = addresses.get("mac")
                vendor_map = h.get("vendor", {}) or {}
                vendor = vendor_map.get(mac) if mac else None
                if not vendor and mac:
                    vendor = oui.vendor(mac)

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
                            conn, host_id, int(port), proto,
                            p.get("state"), p.get("name"),
                            p.get("product"), p.get("version"), ts,
                        )

        if enrich and scanned_ips:
            _enrich_after_scan(scanned_ips, gateway_ip())

        db.finish_scan(scan_id, "complete", f"{found} host(s) up", _now())
        return scan_id, {"hosts_found": found}

    except Exception as e:  # noqa: BLE001
        db.finish_scan(scan_id, "error", str(e), _now())
        raise


def run_discovery_only():
    """Run discovery + enrichment without a full nmap sweep — useful for
    refreshing mDNS/SSDP/NetBIOS info between scans."""
    ips = db.all_host_ips()
    _enrich_after_scan(ips, gateway_ip())
    return {"enriched": len(ips)}
