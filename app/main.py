import logging
import os
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request, send_from_directory

from . import db, scanner, uptime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = Flask(__name__, static_folder="static", static_url_path="")

db.init_db()
uptime.start()

_scan_lock = threading.Lock()
_current_scan = {"running": False, "target": None, "scan_id": None, "kind": None}


def _background(target, profile, kind):
    try:
        if kind == "discover":
            scanner.run_discovery_only()
        else:
            sid, _ = scanner.run_scan(target, profile)
            _current_scan["scan_id"] = sid
    finally:
        _current_scan["running"] = False
        _current_scan["target"] = None
        _current_scan["kind"] = None


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/hosts")
def api_hosts():
    hosts = db.list_hosts()
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    for h in hosts:
        pct, samples, avg_rtt = db.uptime_summary(h["id"], since)
        h["uptime_24h"] = pct
        h["uptime_samples"] = samples
        h["avg_rtt_ms"] = avg_rtt
    return jsonify(hosts)


@app.route("/api/hosts/<int:host_id>/uptime")
def api_host_uptime(host_id):
    hours = int(request.args.get("hours", 24))
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    return jsonify(db.status_series(host_id, since))


@app.route("/api/topology")
def api_topology():
    return jsonify(db.list_links())


@app.route("/api/scans")
def api_scans():
    return jsonify(db.list_scans())


@app.route("/api/status")
def api_status():
    return jsonify(
        {
            "running": _current_scan["running"],
            "target": _current_scan["target"],
            "kind": _current_scan["kind"],
            "default_target": os.environ.get("NETSCAN_DEFAULT_TARGET")
            or scanner.detect_local_cidr()
            or "192.168.1.0/24",
            "gateway": scanner.gateway_ip(),
            "snmp_enabled": bool(os.environ.get("NETSCAN_SNMP_COMMUNITY")),
        }
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (
        data.get("target")
        or os.environ.get("NETSCAN_DEFAULT_TARGET")
        or scanner.detect_local_cidr()
    )
    profile = data.get("profile", "standard")
    if not target:
        return jsonify({"error": "no target provided and could not detect one"}), 400
    if profile not in ("quick", "standard", "deep"):
        return jsonify({"error": "invalid profile"}), 400

    with _scan_lock:
        if _current_scan["running"]:
            return jsonify({"error": "scan already running",
                            "target": _current_scan["target"]}), 409
        _current_scan["running"] = True
        _current_scan["target"] = target
        _current_scan["kind"] = "scan"

    threading.Thread(target=_background, args=(target, profile, "scan"),
                     daemon=True).start()
    return jsonify({"started": True, "target": target, "profile": profile})


@app.route("/api/discover", methods=["POST"])
def api_discover():
    """Re-run mDNS/SSDP/NetBIOS + topology against existing hosts."""
    with _scan_lock:
        if _current_scan["running"]:
            return jsonify({"error": "scan already running"}), 409
        _current_scan["running"] = True
        _current_scan["target"] = "(passive discovery)"
        _current_scan["kind"] = "discover"

    threading.Thread(target=_background, args=(None, None, "discover"),
                     daemon=True).start()
    return jsonify({"started": True})


@app.route("/api/hosts/<int:host_id>", methods=["DELETE"])
def api_delete_host(host_id):
    db.delete_host(host_id)
    return jsonify({"deleted": host_id})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    db.clear_all()
    return jsonify({"cleared": True})


if __name__ == "__main__":
    port = int(os.environ.get("NETSCAN_PORT", "8081"))
    app.run(host="0.0.0.0", port=port, debug=False)
