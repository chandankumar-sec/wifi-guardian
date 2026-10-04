"""Forensic record: who connected, when, with which MAC/IP/hostname, what they asked and talked to.

SQLite (stdlib). Everything that matters for an investigation is written here, and every alert,
action and first-seen record is also appended to a hash-chained audit log, so later tampering with
the log (edited, deleted or re-ordered rows) is detectable with `verify`.
"""
import csv
import hashlib
import io
import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  mac TEXT PRIMARY KEY, vendor TEXT, randomized INTEGER, hostname TEXT, label TEXT,
  status TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS ip_history(
  mac TEXT, ip TEXT, first_seen REAL, last_seen REAL, source TEXT, PRIMARY KEY(mac, ip));
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT, bssid TEXT, ssid TEXT, rssi INTEGER,
  join_ts REAL, leave_ts REAL, source TEXT);
CREATE TABLE IF NOT EXISTS dns_log(ts REAL, mac TEXT, src_ip TEXT, query TEXT, qtype TEXT);
CREATE TABLE IF NOT EXISTS flow_summary(
  mac TEXT, src_ip TEXT, dst_ip TEXT, dport INTEGER, proto TEXT, sni TEXT,
  first_seen REAL, last_seen REAL, flows INTEGER, bytes INTEGER, PRIMARY KEY(src_ip, dst_ip, dport, proto));
CREATE TABLE IF NOT EXISTS alerts(
  id TEXT PRIMARY KEY, ts REAL, rule TEXT, severity TEXT, mac TEXT, src_ip TEXT, summary TEXT,
  evidence TEXT, mitre TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS actions(
  id TEXT PRIMARY KEY, ts REAL, alert_id TEXT, kind TEXT, target TEXT, state TEXT, commands TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, payload TEXT, prev_hash TEXT, hash TEXT);
"""

GENESIS = "0" * 64


def _digest(prev, ts, kind, payload):
    blob = json.dumps([ts, kind, payload], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + blob).encode()).hexdigest()


class Forensics:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)  # server guards access with a lock
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        self._head = row["hash"] if row else GENESIS

    # ---- audit chain --------------------------------------------------------
    def audit(self, ts, kind, payload):
        ts = float(ts)
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        h = _digest(self._head, ts, kind, text)
        self.db.execute("INSERT INTO audit(ts,kind,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
                        (ts, kind, text, self._head, h))
        self._head = h
        self.db.commit()
        return h

    def verify(self):
        """Return (ok, first_bad_seq or None, rows_checked)."""
        prev, n = GENESIS, 0
        for r in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            n += 1
            if r["prev_hash"] != prev or _digest(prev, r["ts"], r["kind"], r["payload"]) != r["hash"]:
                return False, r["seq"], n
            prev = r["hash"]
        return True, None, n

    # ---- writes -------------------------------------------------------------
    def upsert_device(self, d):
        self.db.execute(
            """INSERT INTO devices(mac,vendor,randomized,hostname,label,status,first_seen,last_seen)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(mac) DO UPDATE SET hostname=COALESCE(excluded.hostname,hostname),
                 label=COALESCE(excluded.label,label), status=excluded.status, last_seen=excluded.last_seen""",
            (d["mac"], d["vendor"], int(d["randomized"]), d.get("hostname"), d.get("label"),
             d["status"], d["first_seen"], d["last_seen"]))

    def ip_seen(self, mac, ip, ts, source):
        self.db.execute(
            """INSERT INTO ip_history VALUES(?,?,?,?,?)
               ON CONFLICT(mac,ip) DO UPDATE SET last_seen=excluded.last_seen""", (mac, ip, ts, ts, source))

    def session_open(self, mac, ip, ts, bssid=None, ssid=None, rssi=None, source="assoc"):
        self.db.execute("INSERT INTO sessions(mac,ip,bssid,ssid,rssi,join_ts,source) VALUES(?,?,?,?,?,?,?)",
                        (mac, ip, bssid, ssid, rssi, ts, source))

    def session_set_ip(self, mac, ip):
        self.db.execute("UPDATE sessions SET ip=? WHERE id=(SELECT id FROM sessions "
                        "WHERE mac=? AND leave_ts IS NULL ORDER BY id DESC LIMIT 1) AND ip IS NULL", (ip, mac))

    def session_close(self, mac, ts):
        self.db.execute("UPDATE sessions SET leave_ts=? WHERE id=(SELECT id FROM sessions "
                        "WHERE mac=? AND leave_ts IS NULL ORDER BY id DESC LIMIT 1)", (ts, mac))

    def dns(self, ts, mac, ip, q, qtype):
        self.db.execute("INSERT INTO dns_log VALUES(?,?,?,?,?)", (ts, mac, ip, q, qtype))

    def flow(self, ts, mac, ev):
        self.db.execute(
            """INSERT INTO flow_summary VALUES(?,?,?,?,?,?,?,?,1,?)
               ON CONFLICT(src_ip,dst_ip,dport,proto) DO UPDATE SET last_seen=excluded.last_seen,
                 flows=flows+1, bytes=bytes+excluded.bytes, sni=COALESCE(excluded.sni,sni)""",
            (mac, ev["src_ip"], ev["dst_ip"], ev.get("dport", 0), ev.get("proto", "tcp"), ev.get("sni"),
             ts, ts, ev.get("bytes", 0)))

    def alert(self, a):
        self.db.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (a["id"], a["ts"], a["rule"], a["severity"], a.get("src_mac"), a.get("src_ip"),
                         a["summary"], json.dumps(a["evidence"]), ",".join(a["mitre"]), a["status"]))
        self.audit(a["ts"], "alert", {"id": a["id"], "rule": a["rule"], "mac": a.get("src_mac"),
                                      "ip": a.get("src_ip"), "summary": a["summary"]})

    def action(self, x):
        self.db.execute("INSERT OR REPLACE INTO actions VALUES(?,?,?,?,?,?,?,?)",
                        (x["id"], x["ts"], x["alert_id"], x["kind"], x["target"], x["state"],
                         json.dumps(x["commands"]), x["reason"]))
        self.audit(x["ts"], "action", {"id": x["id"], "kind": x["kind"], "target": x["target"], "state": x["state"]})

    def commit(self):
        self.db.commit()

    # ---- reads / export -----------------------------------------------------
    def rows(self, sql, args=()):
        return [dict(r) for r in self.db.execute(sql, args)]

    def devices(self):
        return self.rows("SELECT * FROM devices ORDER BY first_seen")

    def connection_log(self):
        """Chronological who-joined-when register, the main forensic table."""
        return self.rows(
            """SELECT s.join_ts, s.leave_ts, s.mac, d.vendor, d.randomized, d.hostname, s.ip, s.bssid, s.ssid,
                      s.rssi, d.status
               FROM sessions s JOIN devices d ON d.mac=s.mac ORDER BY s.join_ts""")

    def timeline(self, mac):
        mac = mac.lower()
        return {
            "device": self.rows("SELECT * FROM devices WHERE mac=?", (mac,)),
            "ips": self.rows("SELECT * FROM ip_history WHERE mac=? ORDER BY first_seen", (mac,)),
            "sessions": self.rows("SELECT * FROM sessions WHERE mac=? ORDER BY join_ts", (mac,)),
            "dns": self.rows("SELECT * FROM dns_log WHERE mac=? ORDER BY ts", (mac,)),
            "flows": self.rows("SELECT * FROM flow_summary WHERE mac=? ORDER BY bytes DESC", (mac,)),
            "alerts": self.rows("SELECT * FROM alerts WHERE mac=? ORDER BY ts", (mac,)),
        }

    def connection_log_csv(self):
        buf = io.StringIO()
        rows = self.connection_log()
        cols = ["join_ts", "leave_ts", "mac", "vendor", "randomized", "hostname", "ip", "bssid", "ssid", "rssi", "status"]
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for r in rows:
            r = {k: _csv_safe(v) for k, v in r.items()}
            for k in ("join_ts", "leave_ts"):
                r[k] = iso(r[k]) if r[k] is not None else ""
            w.writerow(r)
        return buf.getvalue()

    def export_case(self, outdir, mac=None):
        """Write JSON/CSV evidence files plus a SHA-256 manifest. Returns the manifest dict."""
        os.makedirs(outdir, exist_ok=True)
        files = {"connection_log.csv": self.connection_log_csv()}
        if mac:
            files[f"timeline_{mac.replace(':', '')}.json"] = json.dumps(self.timeline(mac), indent=2)
        else:
            files["devices.json"] = json.dumps(self.devices(), indent=2)
            files["alerts.json"] = json.dumps(self.rows("SELECT * FROM alerts ORDER BY ts"), indent=2)
            files["actions.json"] = json.dumps(self.rows("SELECT * FROM actions ORDER BY ts"), indent=2)
        files["audit_chain.json"] = json.dumps(self.rows("SELECT * FROM audit ORDER BY seq"), indent=2)
        manifest = {"created": iso(time.time()), "chain_head": self._head, "files": {}}
        for name, text in files.items():
            with open(os.path.join(outdir, name), "w", encoding="utf-8") as fh:
                fh.write(text)
            manifest["files"][name] = hashlib.sha256(text.encode()).hexdigest()
        with open(os.path.join(outdir, "MANIFEST.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        return manifest


def _csv_safe(v):
    """Hostnames come from DHCP and are attacker-controlled: stop spreadsheets treating them as formulas."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
