"""Record honeypot events to a JSONL file and a SQLite database, and query them."""
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, data_dir=DATA):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.dir / "events.jsonl"
        self.db_path = self.dir / "events.db"
        self._init_db()

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def _init_db(self):
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, service TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER,
                username TEXT, password TEXT, detail TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_ip ON events(ip)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(ts)")

    def record(self, service, ip, port=None, username=None, password=None, detail=None):
        ev = {"ts": _now(), "service": service, "ip": ip, "port": port,
              "username": username, "password": password, "detail": detail}
        with _lock:
            with open(self.jsonl, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
            with self._conn() as c:
                c.execute("INSERT INTO events(ts,service,ip,port,username,password,detail) "
                          "VALUES(?,?,?,?,?,?,?)",
                          (ev["ts"], service, ip, port, username, password, detail))
        return ev

    # ---- queries for the dashboard ----
    def summary(self):
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
            ips = c.execute("SELECT COUNT(DISTINCT ip) n FROM events").fetchone()["n"]
            creds = c.execute("SELECT COUNT(*) n FROM events WHERE username IS NOT NULL").fetchone()["n"]
            since = c.execute("SELECT MIN(ts) t FROM events").fetchone()["t"]
            return {"total": total, "unique_ips": ips, "cred_attempts": creds, "since": since}

    def recent(self, limit=100):
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def top(self, column, limit=10, where=""):
        with self._conn() as c:
            q = (f"SELECT {column} v, COUNT(*) n FROM events "
                 f"WHERE {column} IS NOT NULL AND {column} != '' {where} "
                 f"GROUP BY {column} ORDER BY n DESC LIMIT ?")
            return [(r["v"], r["n"]) for r in c.execute(q, (limit,)).fetchall()]

    def by_service(self):
        with self._conn() as c:
            return [(r["service"], r["n"]) for r in c.execute(
                "SELECT service, COUNT(*) n FROM events GROUP BY service ORDER BY n DESC").fetchall()]

    def per_hour(self, hours=24):
        with self._conn() as c:
            rows = c.execute(
                "SELECT substr(ts,1,13) h, COUNT(*) n FROM events GROUP BY h ORDER BY h DESC LIMIT ?",
                (hours,)).fetchall()
            return [(r["h"], r["n"]) for r in reversed(rows)]
