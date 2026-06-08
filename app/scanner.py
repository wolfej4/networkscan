import ipaddress
import logging
import os
import re
import shlex
import socket
import subprocess
import tempfile
from datetime import datetime, timezone

import nmap

from . import db, device_type, discovery, oui, progress, topology

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


# ---------- nmap with live progress ----------

_RE_PCT = re.compile(r"About\s+([\d.]+)%\s+done")
_RE_REMAINING = re.compile(r"\((\d+):(\d+):(\d+)\s+remaining\)")
_RE_STATS = re.compile(
    r"Stats:\s+\S+\s+elapsed;\s+(\d+)\s+hosts\s+completed.*?undergoing\s+(.+)$"
)
_RE_DISCOVERED = re.compile(r"Discovered open port|Nmap scan report for")
_RE_HOSTS_UP = re.compile(r"(\d+)\s+hosts? up")


def _run_nmap_with_progress(target: str, profile: str) -> str:
    """Run nmap as a subprocess so we can parse live progress.

    Returns the XML output (later fed to python-nmap's parser).
    """
    args = _scan_arguments(profile).split()
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w") as tmp:
        xml_path = tmp.name

    cmd = ["nmap", *args, "-v", "--stats-every", "2s", "-oX", xml_path, target]
    log.info("Running: %s", " ".join(shlex.quote(c) for c in cmd))
    progress.update(phase="nmap", percent=0.0, message=f"Starting nmap on {target}")

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    activity = "starting"
    last_pct = 0.0
    hosts_seen = 0
    try:
        for raw in proc.stdout:  # type: ignore[union-attr]
            line = raw.rstrip()
            if not line:
                continue

            m = _RE_STATS.search(line)
            if m:
                hosts_seen = int(m.group(1))
                activity = m.group(2).strip().rstrip(".")
                progress.update(hosts_found=hosts_seen)

            m = _RE_PCT.search(line)
            if m:
                last_pct = float(m.group(1))
                eta = None
                em = _RE_REMAINING.search(line)
                if em:
                    h, mi, s = (int(em.group(i)) for i in (1, 2, 3))
                    eta = h * 3600 + mi * 60 + s
                progress.update(
                    phase="nmap",
                    percent=last_pct,
                    message=f"nmap · {activity}",
                    eta_seconds=eta,
                )

            if "Nmap scan report for" in line:
                hosts_seen += 1
                progress.update(hosts_found=hosts_seen)
    finally:
        proc.wait()

    if proc.returncode != 0:
        try:
            os.unlink(xml_path)
        except OSError:
            pass
        raise RuntimeError(f"nmap exited with code {proc.returncode}")

    try:
        with open(xml_path) as f:
            xml = f.read()
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass
    return xml


# ---------- enrichment pipeline ----------

def _enrich_after_scan(scanned_ips: list[str], gw: str | None):
    log.info("Enriching %d hosts", len(scanned_ips))

    # mDNS (~5s) — phase 2 of 5
    progress.update(phase="mdns", percent=0.0,
                    message=f"mDNS browse ({len(scanned_ips)} hosts known)")
    try:
        mdns_by_ip = discovery.discover_mdns(duration=5.0)
        progress.update(percent=100.0)
    except Exception as e:  # noqa: BLE001
        log.warning("mDNS discovery failed: %s", e)
        mdns_by_ip = {}

    # SSDP (~4s) — phase 3
    progress.update(phase="ssdp", percent=0.0, message="SSDP / UPnP M-SEARCH")
    try:
        ssdp_by_ip = discovery.discover_ssdp(duration=4.0)
        progress.update(percent=100.0)
    except Exception as e:  # noqa: BLE001
        log.warning("SSDP discovery failed: %s", e)
        ssdp_by_ip = {}

    # NetBIOS — per-host loop with progress
    nb_by_ip: dict[str, str] = {}
    total = len(scanned_ips)
    progress.update(phase="netbios", percent=0.0,
                    message=f"NetBIOS lookups (0/{total})")
    for i, ip in enumerate(scanned_ips, start=1):
        try:
            name = discovery.netbios_name(ip)
            if name:
                nb_by_ip[ip] = name
        except Exception as e:  # noqa: BLE001
            log.debug("NetBIOS lookup failed for %s: %s", ip, e)
        progress.update(
            percent=(i / total) * 100 if total else 100,
            message=f"NetBIOS lookups ({i}/{total}) → {ip}",
        )

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

    # Traceroute — per-host loop
    progress.update(phase="traceroute", percent=0.0,
                    message=f"Tracing routes (0/{total})")
    for i, ip in enumerate(scanned_ips, start=1):
        try:
            topology.traceroute_and_store(ip)
        except Exception as e:  # noqa: BLE001
            log.debug("Traceroute failed for %s: %s", ip, e)
        progress.update(
            percent=(i / total) * 100 if total else 100,
            message=f"Tracing routes ({i}/{total}) → {ip}",
        )

    # SNMP (only if community configured)
    if os.environ.get("NETSCAN_SNMP_COMMUNITY"):
        progress.update(phase="snmp", percent=0.0,
                        message=f"SNMP LLDP/CDP walk (0/{total})")
        for i, ip in enumerate(scanned_ips, start=1):
            try:
                topology.snmp_walk_and_store(ip)
            except Exception as e:  # noqa: BLE001
                log.debug("SNMP walk failed for %s: %s", ip, e)
            progress.update(
                percent=(i / total) * 100 if total else 100,
                message=f"SNMP LLDP/CDP walk ({i}/{total}) → {ip}",
            )


def run_scan(target, profile="standard", enrich=True):
    progress.reset(target=target)
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

        xml = _run_nmap_with_progress(target, profile)
        nm = nmap.PortScanner()
        nm.analyse_nmap_xml_scan(xml)

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

        progress.update(hosts_found=found)

        if enrich and scanned_ips:
            _enrich_after_scan(scanned_ips, gateway_ip())

        progress.finish(f"Complete · {found} host(s) up")
        db.finish_scan(scan_id, "complete", f"{found} host(s) up", _now())
        return scan_id, {"hosts_found": found}

    except Exception as e:  # noqa: BLE001
        progress.finish(str(e), error=True)
        db.finish_scan(scan_id, "error", str(e), _now())
        raise


def run_discovery_only():
    progress.reset(target="(passive discovery)")
    ips = db.all_host_ips()
    try:
        _enrich_after_scan(ips, gateway_ip())
        progress.finish(f"Discovery complete · {len(ips)} host(s)")
        return {"enriched": len(ips)}
    except Exception as e:  # noqa: BLE001
        progress.finish(str(e), error=True)
        raise
