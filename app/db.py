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
            """
        )


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


def list_hosts():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM hosts ORDER BY CAST(SUBSTR(ip, 1, INSTR(ip,'.')-1) AS INTEGER), ip"
        ).fetchall()
        hosts = []
        for r in rows:
            ports = conn.execute(
                "SELECT port, protocol, state, service, product, version FROM ports WHERE host_id=? ORDER BY port",
                (r["id"],),
            ).fetchall()
            h = dict(r)
            h["ports"] = [dict(p) for p in ports]
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
        conn.execute("DELETE FROM hosts")
        conn.execute("DELETE FROM scans")
