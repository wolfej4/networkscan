"""Heuristic device-type classifier.

Combines OUI vendor, open ports, mDNS service types, SSDP server strings,
and NetBIOS presence into a single category label used by the UI for icons
and filtering.
"""

CATEGORIES = [
    "router", "switch", "firewall", "server", "nas",
    "workstation", "laptop", "phone", "tablet",
    "tv", "speaker", "streaming", "printer", "camera",
    "gaming", "iot", "voip", "ap", "unknown",
]

# Vendor substring -> default category (lowercased compare).
VENDOR_HINTS = {
    "apple": "workstation",
    "raspberry": "iot",
    "espressif": "iot",
    "tuya": "iot",
    "shelly": "iot",
    "sonos": "speaker",
    "roku": "streaming",
    "amazon": "iot",
    "google": "iot",
    "nest": "iot",
    "ring": "camera",
    "hikvision": "camera",
    "dahua": "camera",
    "ubiquiti": "ap",
    "tp-link": "router",
    "netgear": "router",
    "asus": "router",
    "linksys": "router",
    "mikrotik": "router",
    "cisco": "switch",
    "juniper": "switch",
    "synology": "nas",
    "qnap": "nas",
    "western digital": "nas",
    "samsung": "phone",
    "huawei": "phone",
    "xiaomi": "phone",
    "oneplus": "phone",
    "lg ": "tv",
    "sony": "tv",
    "vizio": "tv",
    "tcl": "tv",
    "hewlett packard": "printer",
    "brother": "printer",
    "canon": "printer",
    "epson": "printer",
    "lexmark": "printer",
    "nintendo": "gaming",
    "microsoft": "workstation",
    "valve": "gaming",
    "sonyinte": "gaming",
    "polycom": "voip",
    "yealink": "voip",
}

PORT_HINTS = {
    9100: "printer",
    631: "printer",
    554: "camera",
    1883: "iot",
    8883: "iot",
    5060: "voip",
    5061: "voip",
    548: "nas",
    2049: "nas",
    445: "workstation",
    3389: "workstation",
    5900: "workstation",
    32400: "streaming",
    8123: "iot",
}

MDNS_HINTS = {
    "_airplay._tcp": "streaming",
    "_raop._tcp": "speaker",
    "_googlecast._tcp": "streaming",
    "_spotify-connect._tcp": "speaker",
    "_sonos._tcp": "speaker",
    "_ipp._tcp": "printer",
    "_ipps._tcp": "printer",
    "_pdl-datastream._tcp": "printer",
    "_printer._tcp": "printer",
    "_hap._tcp": "iot",
    "_homekit._tcp": "iot",
    "_hue._tcp": "iot",
    "_smb._tcp": "nas",
    "_afpovertcp._tcp": "nas",
    "_workstation._tcp": "workstation",
    "_companion-link._tcp": "workstation",
    "_rdlink._tcp": "phone",
}


def _from_vendor(vendor: str | None) -> str | None:
    if not vendor:
        return None
    v = vendor.lower()
    for needle, cat in VENDOR_HINTS.items():
        if needle in v:
            return cat
    return None


def _from_ports(ports: list[dict]) -> str | None:
    open_ports = {p["port"] for p in ports if p.get("state") == "open"}
    for port, cat in PORT_HINTS.items():
        if port in open_ports:
            return cat
    if 53 in open_ports and 67 in open_ports:
        return "router"
    if {80, 22} <= open_ports or {443, 22} <= open_ports:
        return "server"
    return None


def _from_mdns(services: list[dict]) -> str | None:
    types = {s.get("type", "") for s in services or []}
    for needle, cat in MDNS_HINTS.items():
        if any(needle in t for t in types):
            return cat
    return None


def _from_ssdp(ssdp: list[dict]) -> str | None:
    blob = " ".join((s.get("server") or "") + " " + (s.get("model") or "") for s in ssdp or [])
    b = blob.lower()
    if "roku" in b: return "streaming"
    if "sonos" in b: return "speaker"
    if "directv" in b or "smarttv" in b or "samsungtv" in b: return "tv"
    if "router" in b or "gateway" in b: return "router"
    if "printer" in b: return "printer"
    if "ipcamera" in b or "camera" in b: return "camera"
    return None


def classify(*, vendor=None, ports=None, mdns=None, ssdp=None,
             netbios=None, is_gateway=False) -> str:
    if is_gateway:
        return "router"
    return (
        _from_mdns(mdns)
        or _from_ssdp(ssdp)
        or _from_ports(ports or [])
        or _from_vendor(vendor)
        or ("workstation" if netbios else None)
        or "unknown"
    )
