import os
import threading

from flask import Flask, jsonify, request, send_from_directory

from . import db, scanner

app = Flask(__name__, static_folder="static", static_url_path="")

db.init_db()

_scan_lock = threading.Lock()
_current_scan = {"running": False, "target": None, "scan_id": None}


def _background_scan(target, profile):
    try:
        scan_id, _ = scanner.run_scan(target, profile)
        _current_scan["scan_id"] = scan_id
    finally:
        _current_scan["running"] = False
        _current_scan["target"] = None


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/hosts")
def api_hosts():
    return jsonify(db.list_hosts())


@app.route("/api/scans")
def api_scans():
    return jsonify(db.list_scans())


@app.route("/api/status")
def api_status():
    return jsonify(
        {
            "running": _current_scan["running"],
            "target": _current_scan["target"],
            "default_target": os.environ.get("NETSCAN_DEFAULT_TARGET")
            or scanner.detect_local_cidr()
            or "192.168.1.0/24",
            "gateway": scanner.gateway_ip(),
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
            return jsonify({"error": "scan already running", "target": _current_scan["target"]}), 409
        _current_scan["running"] = True
        _current_scan["target"] = target

    t = threading.Thread(target=_background_scan, args=(target, profile), daemon=True)
    t.start()
    return jsonify({"started": True, "target": target, "profile": profile})


@app.route("/api/hosts/<int:host_id>", methods=["DELETE"])
def api_delete_host(host_id):
    db.delete_host(host_id)
    return jsonify({"deleted": host_id})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    db.clear_all()
    return jsonify({"cleared": True})


if __name__ == "__main__":
    port = int(os.environ.get("NETSCAN_PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
