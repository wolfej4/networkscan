import json
import os
import sqlite3
import threading
from contextlib import contextmanager

DB_PATH = os.environ.get("NETSCAN_DB", "/data/netscan.db")
_lock = threading.Lock()


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def _columns(conn, table):
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def init_db():
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                message TEXT
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                mac TEXT,
                vendor TEXT,
                hostname TEXT,
                os TEXT,
                state TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT,
                service TEXT,
                product TEXT,
                version TEXT,
                last_seen TEXT NOT NULL,
                UNIQUE(host_id, port, protocol),
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);

            CREATE TABLE IF NOT EXISTS host_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                is_up INTEGER NOT NULL,
                rtt_ms REAL,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_status_host_time
                ON host_status(host_id, checked_at);

            CREATE TABLE IF NOT EXISTS topology_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                discovery TEXT NOT NULL,
                hop_index INTEGER,
                last_seen TEXT NOT NULL,
                UNIQUE(src, dst, discovery)
            );
            """
        )

        # Idempotent ALTERs for added columns.
        cols = _columns(conn, "hosts")
        for col, ddl in [
            ("device_type", "ALTER TABLE hosts ADD COLUMN device_type TEXT"),
            ("mdns_services", "ALTER TABLE hosts ADD COLUMN mdns_services TEXT"),
            ("ssdp_info", "ALTER TABLE hosts ADD COLUMN ssdp_info TEXT"),
            ("netbios_name", "ALTER TABLE hosts ADD COLUMN netbios_name TEXT"),
            ("notes", "ALTER TABLE hosts ADD COLUMN notes TEXT"),
        ]:
            if col not in cols:
                conn.execute(ddl)


def upsert_host(conn, ip, mac, vendor, hostname, os_name, state, ts):
    cur = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
    row = cur.fetchone()
    if row:
        conn.execute(
            """UPDATE hosts SET mac=COALESCE(?, mac),
                                vendor=COALESCE(?, vendor),
                                hostname=COALESCE(?, hostname),
                                os=COALESCE(?, os),
                                state=?,
                                last_seen=?
               WHERE id=?""",
            (mac or None, vendor or None, hostname or None, os_name or None, state, ts, row["id"]),
        )
        return row["id"]
    cur = conn.execute(
        """INSERT INTO hosts (ip, mac, vendor, hostname, os, state, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ip, mac or None, vendor or None, hostname or None, os_name or None, state, ts, ts),
    )
    return cur.lastrowid


def upsert_port(conn, host_id, port, protocol, state, service, product, version, ts):
    conn.execute(
        """INSERT INTO ports (host_id, port, protocol, state, service, product, version, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(host_id, port, protocol) DO UPDATE SET
             state=excluded.state,
             service=excluded.service,
             product=excluded.product,
             version=excluded.version,
             last_seen=excluded.last_seen""",
        (host_id, port, protocol, state, service or None, product or None, version or None, ts),
    )


def update_host_enrichment(conn, host_id, *, vendor=None, device_type=None,
                           mdns=None, ssdp=None, netbios=None):
    sets, args = [], []
    if vendor is not None:
        sets.append("vendor=COALESCE(?, vendor)"); args.append(vendor)
    if device_type is not None:
        sets.append("device_type=?"); args.append(device_type)
    if mdns is not None:
        sets.append("mdns_services=?"); args.append(json.dumps(mdns))
    if ssdp is not None:
        sets.append("ssdp_info=?"); args.append(json.dumps(ssdp))
    if netbios is not None:
        sets.append("netbios_name=?"); args.append(netbios)
    if not sets:
        return
    args.append(host_id)
    conn.execute(f"UPDATE hosts SET {', '.join(sets)} WHERE id=?", args)


def host_id_for_ip(conn, ip):
    row = conn.execute("SELECT id FROM hosts WHERE ip=?", (ip,)).fetchone()
    return row["id"] if row else None


def list_hosts():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM hosts ORDER BY "
            "CAST(SUBSTR(ip, 1, INSTR(ip,'.')-1) AS INTEGER), "
            "CAST(SUBSTR(SUBSTR(ip, INSTR(ip,'.')+1), 1, "
            "INSTR(SUBSTR(ip, INSTR(ip,'.')+1),'.')-1) AS INTEGER), ip"
        ).fetchall()
        hosts = []
        for r in rows:
            h = dict(r)
            h["ports"] = [dict(p) for p in conn.execute(
                "SELECT port, protocol, state, service, product, version "
                "FROM ports WHERE host_id=? ORDER BY port", (r["id"],)
            ).fetchall()]
            h["mdns_services"] = json.loads(h["mdns_services"]) if h.get("mdns_services") else []
            h["ssdp_info"] = json.loads(h["ssdp_info"]) if h.get("ssdp_info") else []
            hosts.append(h)
        return hosts


def list_scans(limit=25):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def create_scan(target, ts):
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, started_at, status) VALUES (?, ?, 'running')",
            (target, ts),
        )
        return cur.lastrowid


def finish_scan(scan_id, status, message, ts):
    with get_db() as conn:
        conn.execute(
            "UPDATE scans SET status=?, message=?, finished_at=? WHERE id=?",
            (status, message, ts, scan_id),
        )


def delete_host(host_id):
    with get_db() as conn:
        conn.execute("DELETE FROM hosts WHERE id=?", (host_id,))


def clear_all():
    with get_db() as conn:
        conn.execute("DELETE FROM ports")
        conn.execute("DELETE FROM host_status")
        conn.execute("DELETE FROM topology_links")
        conn.execute("DELETE FROM hosts")
        conn.execute("DELETE FROM scans")


def record_status(host_id, is_up, rtt_ms, ts):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO host_status (host_id, checked_at, is_up, rtt_ms) VALUES (?, ?, ?, ?)",
            (host_id, ts, 1 if is_up else 0, rtt_ms),
        )


def prune_status(older_than_iso):
    with get_db() as conn:
        conn.execute("DELETE FROM host_status WHERE checked_at < ?", (older_than_iso,))


def uptime_summary(host_id, since_iso):
    """Return (uptime_pct, samples, avg_rtt) since the given ISO timestamp."""
    with get_db() as conn:
        row = conn.execute(
            """SELECT
                 COUNT(*) AS n,
                 SUM(is_up) AS ups,
                 AVG(CASE WHEN is_up=1 THEN rtt_ms END) AS avg_rtt
               FROM host_status
               WHERE host_id=? AND checked_at >= ?""",
            (host_id, since_iso),
        ).fetchone()
        if not row or not row["n"]:
            return None, 0, None
        return (row["ups"] or 0) / row["n"], row["n"], row["avg_rtt"]


def status_series(host_id, since_iso, limit=288):
    """Return raw status samples for sparkline rendering."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT checked_at, is_up, rtt_ms FROM host_status
               WHERE host_id=? AND checked_at >= ?
               ORDER BY checked_at ASC LIMIT ?""",
            (host_id, since_iso, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def upsert_link(src, dst, discovery, hop_index, ts):
    if src == dst:
        return
    with get_db() as conn:
        conn.execute(
            """INSERT INTO topology_links (src, dst, discovery, hop_index, last_seen)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(src, dst, discovery) DO UPDATE SET
                 hop_index=excluded.hop_index,
                 last_seen=excluded.last_seen""",
            (src, dst, discovery, hop_index, ts),
        )


def list_links():
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT src, dst, discovery, hop_index FROM topology_links"
        ).fetchall()]


def all_host_ips():
    with get_db() as conn:
        return [r["ip"] for r in conn.execute("SELECT ip FROM hosts").fetchall()]
