"""Engine: feeds events through the detectors, keeps the device register, writes the forensic record,
asks the enforcer what to do, and emits a uniform "feed" the dashboard (live or replay) consumes.

Feed item kinds (key "k"):
  device  a device snapshot plus what happened: first_seen | join | leave | ip_change | status
  flow    one aggregated connection record
  dns     one DNS lookup
  alert   a full alert (rule text, MITRE, playbook, evidence)
  action  what the response layer decided or did
"""
import time

from .detectors import Detectors
from .events import EventError, clean
from .enforcement import Enforcer
from .forensics import Forensics
from .oui import is_randomized, norm_mac, vendor as vendor_of
from .rules import MITRE_NAMES, RULES


class Engine:
    def __init__(self, cfg, store=None, apply=False, oui=None):
        self.cfg = cfg
        self.store = store or Forensics()
        self.enforcer = Enforcer(cfg, apply=apply)
        self.oui = oui
        self.devices = {}
        self.ip_to_mac = {cfg["gateway"]["ip"]: cfg["gateway"]["mac"]}
        self.alerts, self.actions = {}, {}
        self.det = Detectors(self)
        self.feed = []
        self.rejected, self.errors = 0, []
        self._n = 0
        self._last_commit = 0.0
        self._resume()
        gw = cfg["gateway"]["mac"]
        self._device(gw, 0, label="Gateway / AP", status="known")

    def _resume(self):
        """Continue an existing database: keep ids unique, remember approved devices, close stale sessions."""
        db = self.store.db
        for table, prefix, attr in (("alerts", "WG-", None), ("actions", "ACT-", None)):
            top = 0
            for (i,) in db.execute(f"SELECT id FROM {table}"):
                try:
                    top = max(top, int(i[len(prefix):]))
                except ValueError:
                    pass
            if table == "alerts":
                self._n = top
            else:
                self.enforcer.n = top
        for d in self.store.devices():
            if d["status"] == "known" and d["mac"] not in self.cfg["allowlist"]:
                self.cfg["allowlist"][d["mac"]] = d["label"] or "approved earlier"
        db.execute("UPDATE sessions SET leave_ts=(SELECT last_seen FROM devices WHERE devices.mac=sessions.mac) "
                   "WHERE leave_ts IS NULL")
        db.commit()

    # ---- helpers used by detectors -----------------------------------------
    def is_known(self, mac):
        return mac in self.cfg["allowlist"] or mac in self.cfg["protected"] or \
            self.devices.get(mac, {}).get("status") == "known"

    def mac_of(self, ip):
        return self.ip_to_mac.get(ip)

    def vendor(self, mac):
        return vendor_of(mac, self.oui)

    # ---- device register ----------------------------------------------------
    def _device(self, mac, ts, hostname=None, ip=None, label=None, status=None):
        d = self.devices.get(mac)
        is_new = d is None
        if is_new:
            known = self.is_known(mac)
            d = self.devices[mac] = {
                "mac": mac, "vendor": self.vendor(mac), "randomized": is_randomized(mac), "hostname": None,
                "label": self.cfg["allowlist"].get(mac), "ips": [], "status": "known" if known else "unknown",
                "first_seen": ts, "last_seen": ts, "online": False, "sessions": 0}
        if hostname:
            d["hostname"] = hostname
        if label:
            d["label"] = label
        if status:
            d["status"] = status
        d["last_seen"] = max(d["last_seen"], ts)
        changed_ip = False
        if ip and ip not in d["ips"]:
            d["ips"].append(ip)
            changed_ip = not is_new
            self.store.ip_seen(mac, ip, ts, "dhcp/arp")
        elif ip:
            self.store.ip_seen(mac, ip, ts, "dhcp/arp")
        if ip and ip != self.cfg["gateway"]["ip"]:
            self.ip_to_mac[ip] = mac
        self.store.upsert_device(d)
        if is_new:
            self.store.audit(ts, "device_first_seen", {"mac": mac, "vendor": d["vendor"], "status": d["status"]})
        return d, is_new, changed_ip

    def _emit_device(self, d, ts, event):
        self.feed.append({"k": "device", "t": ts, "ev": event, **{k: d[k] for k in (
            "mac", "vendor", "randomized", "hostname", "label", "status", "first_seen", "last_seen",
            "online", "sessions")}, "ips": list(d["ips"])})

    # ---- main entry ---------------------------------------------------------
    def process(self, ev, strict=False):
        """Validate and handle one event. Bad events are counted and skipped (strict=True raises instead)."""
        try:
            ev = clean(ev)
        except EventError as exc:
            if strict:
                raise
            self.rejected += 1
            if len(self.errors) < 50:
                self.errors.append(str(exc))
            return []
        before = len(self.feed)
        t, ts = ev["type"], ev["ts"]

        if t == "assoc":
            self._assoc(ev)
        elif t == "dhcp":
            self._dhcp(ev)
        elif t == "flow":
            mac = self.mac_of(ev["src_ip"])
            self.store.flow(ts, mac, ev)
            self.feed.append({"k": "flow", "t": ts, "src_ip": ev["src_ip"], "src_mac": mac, "dst_ip": ev["dst_ip"],
                              "dport": ev.get("dport", 0), "proto": ev.get("proto", "tcp"),
                              "bytes": ev.get("bytes", 0), "sni": ev.get("sni")})
        elif t == "dns":
            mac = self.mac_of(ev["src_ip"])
            self.store.dns(ts, mac, ev["src_ip"], ev["query"], ev.get("qtype", "A"))
            self.feed.append({"k": "dns", "t": ts, "src_ip": ev["src_ip"], "src_mac": mac, "query": ev["query"]})
        elif t == "arp":
            pass

        for finding in self.det.inspect(ev):
            self._raise(finding)
        now = time.monotonic()
        if t not in ("flow", "dns") or now - self._last_commit > 1.0:   # batch the high-volume event types
            self.store.commit()
            self._last_commit = now
        return self.feed[before:]

    def _assoc(self, ev):
        ts, mac = ev["ts"], ev["mac"]
        d, is_new, _ = self._device(mac, ts)
        if ev["action"] == "join":
            d["online"] = True
            d["sessions"] += 1
            known_ip = ev.get("ip") or (d["ips"][-1] if d["ips"] else None)   # rejoin without a new lease
            self.store.session_open(mac, known_ip, ts, ev.get("bssid"), ev.get("ssid") or self.cfg["ssid"],
                                    ev.get("rssi"))
            if is_new:
                self._emit_device(d, ts, "first_seen")
            self._emit_device(d, ts, "join")
        else:
            d["online"] = False
            self.store.session_close(mac, ts)
            self._emit_device(d, ts, "leave")
        self.store.upsert_device(d)

    def _dhcp(self, ev):
        if ev.get("action") != "lease":
            return
        ts, mac = ev["ts"], ev["mac"]
        had_ip = bool(self.devices[mac]["ips"]) if mac in self.devices else False
        d, is_new, changed = self._device(mac, ts, hostname=ev.get("hostname"), ip=ev["ip"])
        self.store.session_set_ip(mac, ev["ip"])
        if is_new:
            self._emit_device(d, ts, "first_seen")
        if is_new or (changed and not had_ip):
            self._emit_device(d, ts, "lease")          # first address handed out
        elif changed:
            self._emit_device(d, ts, "ip_change")      # address changed: worth a forensic note

    # ---- alerts / actions ---------------------------------------------------
    def _raise(self, f):
        self._n += 1
        meta = RULES[f["rule"]]
        mac = f.get("src_mac") or self.mac_of(f.get("src_ip", ""))
        ip = f.get("src_ip") or (self.devices[mac]["ips"][-1] if mac in self.devices and self.devices[mac]["ips"] else None)
        who = mac or f.get("victim_mac")
        alert = {
            "id": f"WG-{self._n:04d}", "ts": f["ts"], "rule": f["rule"], "title": meta["title"],
            "severity": "critical" if f["rule"] == "arp_spoof" else meta["severity"],
            "src_ip": ip, "src_mac": mac, "victim_mac": f.get("victim_mac"), "target": f.get("target") or f.get("victim_mac"),
            "device": self.devices.get(who, {}).get("label") or self.devices.get(who, {}).get("hostname"),
            "summary": f["summary"], "evidence": f["evidence"],
            "mitre": [{"id": i, "name": MITRE_NAMES.get(i, "")} for i in meta["mitre"]],
            "playbook": meta["playbook"], "status": "new",
        }
        self.alerts[alert["id"]] = alert
        self.store.alert({**alert, "src_mac": who, "mitre": [m["id"] for m in alert["mitre"]]})
        self.feed.append({"k": "alert", "t": f["ts"], **alert})

        act = self.enforcer.decide(alert, mac, ip)
        self.actions[act["id"]] = act
        self.store.action(act)
        self.feed.append({"k": "action", "t": f["ts"], **act})
        if act["state"] in ("applied",) and act["kind"] == "quarantine_mac" and mac in self.devices:
            d = self.devices[mac]
            d["status"] = "quarantined"
            self._emit_device(d, f["ts"], "status")

    def approve_device(self, mac, ts, name=None):
        """Analyst says: this device is mine. Adds it to the allowlist for this run."""
        mac = norm_mac(mac)
        self.cfg["allowlist"][mac] = name or self.cfg["allowlist"].get(mac, "approved")
        d, _, _ = self._device(mac, ts, label=name, status="known")
        self.store.audit(ts, "device_approved", {"mac": mac, "name": name})
        self._emit_device(d, ts, "status")
        self.store.commit()
        return d

    def approve_action(self, action_id, ts):
        """Analyst approves a pending response (semi mode). Returns the updated action or None."""
        act = self.actions.get(action_id)
        if not act or act["state"] != "pending_approval":
            return None
        self.enforcer.approve(act)
        act["ts_decided"] = ts
        self.store.action(act)
        self.feed.append({"k": "action", "t": ts, **act})
        if act["state"] == "applied" and act["kind"] == "quarantine_mac" and act["target"] in self.devices:
            d = self.devices[act["target"]]
            d["status"] = "quarantined"
            self._emit_device(d, ts, "status")
        self.store.commit()
        return act

    def finish(self):
        """Flush batched writes. Call before reading the database from another connection or exiting."""
        self.store.commit()
