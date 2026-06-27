"""SQLite store — gamekeeper's memory of the territory.

One file holds the device inventory (with your labels), the event timeline, the
honeypot probe log, and the ban ledger. Modules share it so the UI can render
everything from one place. Stdlib only.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  mac TEXT PRIMARY KEY, ip TEXT, iface TEXT, vendor TEXT, hostname TEXT,
  dtype TEXT, label TEXT, notes TEXT, ports TEXT, os TEXT,
  randomized INTEGER DEFAULT 0, present INTEGER DEFAULT 1,
  trust TEXT DEFAULT 'unknown',          -- known | guest | unknown | blocked
  first_seen TEXT, last_seen TEXT, times_seen INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts TEXT, mac TEXT, ip TEXT,
  kind TEXT,                              -- new_device | returned | departed | ip_change | probe | ban | anomaly
  severity TEXT DEFAULT 'info', detail TEXT
);
CREATE TABLE IF NOT EXISTS probes (
  id INTEGER PRIMARY KEY, ts TEXT, src_ip TEXT, src_mac TEXT,
  dst_port INTEGER, proto TEXT, service TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS bans (
  id INTEGER PRIMARY KEY, ts TEXT, ip TEXT, mac TEXT, reason TEXT,
  rule TEXT, applied INTEGER DEFAULT 0, released INTEGER DEFAULT 0, decided_by TEXT
);
CREATE TABLE IF NOT EXISTS llm_calls (
  id INTEGER PRIMARY KEY, ts TEXT, purpose TEXT, model TEXT, source TEXT,
  prompt TEXT, response TEXT, ok INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS captures (
  id INTEGER PRIMARY KEY, ts TEXT, iface TEXT, seconds INTEGER, pcap TEXT,
  bytes INTEGER, summary TEXT, analysis TEXT
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY, ts TEXT, role TEXT, nick TEXT, text TEXT
);
"""

# Columns added after the first release — applied idempotently for existing DBs.
_MIGRATIONS = [
    "ALTER TABLE devices ADD COLUMN ports TEXT",
    "ALTER TABLE devices ADD COLUMN os TEXT",
    "ALTER TABLE captures ADD COLUMN analysis TEXT",
]


class Store:
    def __init__(self, path: str | None = None):
        self.path = path or config.DB_PATH
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with self._con() as c:
            c.executescript(_SCHEMA)
            for stmt in _MIGRATIONS:
                try:
                    c.execute(stmt)
                except sqlite3.OperationalError:
                    pass  # column already exists

    @contextmanager
    def _con(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    # --- devices ---------------------------------------------------------------
    def upsert_device(self, d: dict, now: str) -> str:
        """Insert or refresh a device by MAC. Returns 'new' | 'returned' | 'seen' |
        'ip_change' so the caller can log a timeline event."""
        with self._con() as c:
            row = c.execute("SELECT ip, present FROM devices WHERE mac=?", (d["mac"],)).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO devices(mac,ip,iface,vendor,hostname,dtype,randomized,"
                    "present,first_seen,last_seen,times_seen) VALUES (?,?,?,?,?,?,?,1,?,?,1)",
                    (d["mac"], d.get("ip"), d.get("iface"), d.get("vendor"), d.get("hostname"),
                     d.get("dtype"), int(d.get("randomized", 0)), now, now))
                return "new"
            outcome = "seen"
            if not row["present"]:
                outcome = "returned"
            elif row["ip"] and d.get("ip") and row["ip"] != d["ip"]:
                outcome = "ip_change"
            c.execute(
                "UPDATE devices SET ip=?, iface=COALESCE(?,iface), vendor=COALESCE(?,vendor),"
                " hostname=COALESCE(?,hostname), dtype=COALESCE(?,dtype), present=1,"
                " last_seen=?, times_seen=times_seen+1 WHERE mac=?",
                (d.get("ip"), d.get("iface"), d.get("vendor"), d.get("hostname"),
                 d.get("dtype"), now, d["mac"]))
            return outcome

    def mark_absent(self, seen_macs: list[str], now: str) -> list[str]:
        """Flag devices not seen this sweep as departed. Returns the MACs that just left."""
        with self._con() as c:
            rows = c.execute("SELECT mac FROM devices WHERE present=1").fetchall()
            gone = [r["mac"] for r in rows if r["mac"] not in set(seen_macs)]
            for m in gone:
                c.execute("UPDATE devices SET present=0, last_seen=? WHERE mac=?", (now, m))
            return gone

    def set_label(self, mac: str, label: str = None, trust: str = None, notes: str = None,
                  dtype: str = None, vendor: str = None):
        sets, args = [], []
        for col, val in (("label", label), ("trust", trust), ("notes", notes),
                         ("dtype", dtype), ("vendor", vendor)):
            if val is not None:
                sets.append(f"{col}=?"); args.append(val)
        if not sets:
            return
        args.append(mac)
        with self._con() as c:
            c.execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac=?", args)

    def set_ports(self, mac: str, ports_json: str, os_guess: str = None):
        with self._con() as c:
            c.execute("UPDATE devices SET ports=?, os=COALESCE(?,os) WHERE mac=?",
                      (ports_json, os_guess, mac))

    def device_by_ip(self, ip: str) -> dict | None:
        with self._con() as c:
            r = c.execute("SELECT * FROM devices WHERE ip=? ORDER BY present DESC, last_seen DESC LIMIT 1",
                          (ip,)).fetchone()
            return dict(r) if r else None

    def set_capture_analysis(self, pcap: str, text: str):
        with self._con() as c:
            c.execute("UPDATE captures SET analysis=? WHERE pcap=?", (text, pcap))

    def devices(self) -> list[dict]:
        with self._con() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM devices ORDER BY present DESC, last_seen DESC")]

    def device(self, mac: str) -> dict | None:
        with self._con() as c:
            r = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
            return dict(r) if r else None

    # --- events / probes / bans ------------------------------------------------
    def add_event(self, mac, ip, kind, detail, now, severity="info"):
        with self._con() as c:
            c.execute("INSERT INTO events(ts,mac,ip,kind,severity,detail) VALUES (?,?,?,?,?,?)",
                      (now, mac, ip, kind, severity, detail))

    def events(self, limit=200) -> list[dict]:
        with self._con() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    def add_probe(self, src_ip, src_mac, dst_port, proto, service, detail, now):
        with self._con() as c:
            c.execute("INSERT INTO probes(ts,src_ip,src_mac,dst_port,proto,service,detail)"
                      " VALUES (?,?,?,?,?,?,?)", (now, src_ip, src_mac, dst_port, proto, service, detail))

    def probes(self, limit=200) -> list[dict]:
        with self._con() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM probes ORDER BY id DESC LIMIT ?", (limit,))]

    def probe_counts(self) -> dict:
        with self._con() as c:
            return {r["src_ip"]: r["n"] for r in c.execute(
                "SELECT src_ip, count(*) n FROM probes GROUP BY src_ip ORDER BY n DESC")}

    def add_ban(self, ip, mac, reason, rule, applied, now, decided_by="human") -> int:
        with self._con() as c:
            cur = c.execute("INSERT INTO bans(ts,ip,mac,reason,rule,applied,decided_by)"
                            " VALUES (?,?,?,?,?,?,?)", (now, ip, mac, reason, rule, int(applied), decided_by))
            return cur.lastrowid

    def bans(self, active_only=False) -> list[dict]:
        q = "SELECT * FROM bans" + (" WHERE released=0" if active_only else "") + " ORDER BY id DESC"
        with self._con() as c:
            return [dict(r) for r in c.execute(q)]

    # --- LLM call log (every prompt + response is recorded for transparency) -----
    def add_llm_call(self, purpose, model, source, prompt, response, ok, now):
        with self._con() as c:
            c.execute("INSERT INTO llm_calls(ts,purpose,model,source,prompt,response,ok)"
                      " VALUES (?,?,?,?,?,?,?)",
                      (now, purpose, model, source, prompt, response, int(ok)))

    def llm_calls(self, limit=40) -> list[dict]:
        with self._con() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM llm_calls ORDER BY id DESC LIMIT ?", (limit,))]

    # --- packet captures ---------------------------------------------------------
    def add_capture(self, iface, seconds, pcap, nbytes, summary, now):
        with self._con() as c:
            c.execute("INSERT INTO captures(ts,iface,seconds,pcap,bytes,summary)"
                      " VALUES (?,?,?,?,?,?)", (now, iface, seconds, pcap, nbytes, summary))

    def captures(self, limit=20) -> list[dict]:
        with self._con() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM captures ORDER BY id DESC LIMIT ?", (limit,))]

    # --- chat ------------------------------------------------------------------
    def add_message(self, role, text, now, nick=""):
        with self._con() as c:
            c.execute("INSERT INTO messages(ts,role,nick,text) VALUES (?,?,?,?)",
                      (now, role, nick, text))

    def messages(self, limit=60) -> list[dict]:
        with self._con() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,))]
            return list(reversed(rows))

    def counts(self) -> dict:
        with self._con() as c:
            present = c.execute("SELECT count(*) FROM devices WHERE present=1").fetchone()[0]
            total = c.execute("SELECT count(*) FROM devices").fetchone()[0]
            unknown = c.execute("SELECT count(*) FROM devices WHERE trust='unknown'").fetchone()[0]
            return {"present": present, "total": total, "unknown": unknown,
                    "probes": c.execute("SELECT count(*) FROM probes").fetchone()[0],
                    "bans": c.execute("SELECT count(*) FROM bans WHERE released=0").fetchone()[0]}
