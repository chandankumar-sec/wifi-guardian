"""Streaming detectors. Each event goes in once; zero or more raw findings come out.

A finding is a dict: rule, ts, src_ip, src_mac, summary, evidence[list of str], target (optional).
The engine adds the id, severity, MITRE tags and the playbook from rules.py.
"""
import ipaddress
import math
import statistics
from collections import Counter, defaultdict, deque


def entropy(s):
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0


def parent_domain(q):
    parts = q.rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else q.lower()


_LAN = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                           "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32")]


def is_private(ip):
    """True for LAN/loopback/multicast. Not ipaddress.is_private: that also covers the documentation ranges
    (RFC 5737) which this lab uses as stand-ins for internet hosts."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _LAN)


class Window:
    """Sliding-time sum of (ts, value)."""

    def __init__(self, span):
        self.span, self.items, self.total = span, deque(), 0

    def add(self, ts, v):
        self.items.append((ts, v))
        self.total += v
        while self.items and self.items[0][0] < ts - self.span:
            self.total -= self.items.popleft()[1]
        return self.total


class Detectors:
    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.th = ctx.cfg["thresholds"]
        self.last = {}                      # (rule, key) -> ts of last finding
        self.syn = defaultdict(lambda: Window(self.th["syn_window_s"]))
        self.udp = defaultdict(lambda: Window(self.th["udp_window_s"]))
        self.icmp = defaultdict(lambda: Window(self.th["icmp_window_s"]))
        self.exfil = defaultdict(lambda: Window(self.th["exfil_window_s"]))
        self.scan = defaultdict(deque)      # src_ip -> deque[(ts, dst, port)]
        self.conn_ts = defaultdict(list)    # (src, dst, port) -> [ts]
        self.dns_subs = defaultdict(set)    # (src, parent) -> {suspicious subdomain}
        self.deauth = defaultdict(lambda: Window(self.th["deauth_window_s"]))
        self.beacon_done = set()
        self.unknown_seen = set()

    def _fire(self, rule, key, ts, **kw):
        k = (rule, key)
        if k in self.last and ts - self.last[k] < self.cfg["cooldown_s"]:
            return []
        self.last[k] = ts
        kw.setdefault("evidence", [])
        return [dict(rule=rule, ts=ts, **kw)]

    def inspect(self, ev):
        fn = getattr(self, "on_" + ev["type"], None)
        return fn(ev) if fn else []

    # ---- identity / L2 ------------------------------------------------------
    def on_assoc(self, ev):
        if ev.get("action") != "join":
            return []
        return self._unknown(ev["ts"], ev["mac"], ev.get("ip"), "WiFi association")

    def on_dhcp(self, ev):
        if ev.get("action") != "lease":
            return []
        return self._unknown(ev["ts"], ev["mac"], ev.get("ip"), "DHCP lease")

    def _unknown(self, ts, mac, ip, via):
        if self.ctx.is_known(mac) or mac in self.unknown_seen:
            return []
        self.unknown_seen.add(mac)
        return self._fire("unknown_device", mac, ts, src_mac=mac, src_ip=ip,
                          summary=f"{mac} is not on the allowlist (seen via {via})",
                          evidence=[f"mac={mac}", f"vendor={self.ctx.vendor(mac)}", f"first seen via {via}"])

    def on_dhcp_offer(self, ev):
        if ev["server_mac"] == self.cfg["dhcp_server_mac"]:
            return []
        return self._fire("rogue_dhcp", ev["server_mac"], ev["ts"], src_mac=ev["server_mac"],
                          src_ip=ev.get("server_ip"),
                          summary=f"DHCP offer from {ev['server_mac']}, expected {self.cfg['dhcp_server_mac']}",
                          evidence=[f"offered gateway={ev.get('gateway')}", f"offered dns={ev.get('dns')}"])

    def on_arp(self, ev):
        owner = self.ctx.mac_of(ev["src_ip"])
        gw = self.cfg["gateway"]
        claimed_gw = ev["src_ip"] == gw["ip"] and ev["src_mac"] != gw["mac"]
        if not claimed_gw and (owner is None or owner == ev["src_mac"]):
            return []
        real = gw["mac"] if ev["src_ip"] == gw["ip"] else owner
        return self._fire("arp_spoof", ev["src_mac"], ev["ts"], src_mac=ev["src_mac"],
                          summary=f"{ev['src_mac']} claims {ev['src_ip']} which belongs to {real}",
                          evidence=[f"arp reply: {ev['src_ip']} is-at {ev['src_mac']}",
                                    f"expected owner: {real}",
                                    "target is the gateway" if claimed_gw else "target is a LAN host"])

    def on_deauth(self, ev):
        key = ev["dst_mac"]
        total = self.deauth[key].add(ev["ts"], ev.get("count", 1))
        if total < self.th["deauth_frames"]:
            return []
        return self._fire("deauth_flood", key, ev["ts"], src_mac=None, victim_mac=key,
                          summary=f"{total} deauth frames in {self.th['deauth_window_s']}s aimed at {key}",
                          evidence=[f"frames={total}", f"spoofed sender (BSSID)={ev.get('src_mac')}", f"target={key}"])

    # ---- IP layer -----------------------------------------------------------
    def on_flow(self, ev):
        out, ts, src, dst = [], ev["ts"], ev["src_ip"], ev["dst_ip"]
        port, proto = ev.get("dport", 0), ev.get("proto", "tcp")
        pk, by = ev.get("packets", 1), ev.get("bytes", 0)
        th = self.th

        if ev.get("syns"):
            n = self.syn[src].add(ts, ev["syns"])
            if n >= th["syn_count"]:
                out += self._fire("syn_flood", src, ts, src_ip=src,
                                  summary=f"{n} SYNs in {th['syn_window_s']}s from {src} toward {dst}:{port}",
                                  evidence=[f"syns={n}", f"target={dst}:{port}"])
        if proto == "udp" and pk > 1:
            n = self.udp[src].add(ts, pk)
            if n >= th["udp_packets"]:
                out += self._fire("udp_flood", src, ts, src_ip=src,
                                  summary=f"{n} UDP packets in {th['udp_window_s']}s from {src} toward {dst}:{port}",
                                  evidence=[f"packets={n}", f"target={dst}:{port}"])
        if proto == "icmp":
            n = self.icmp[src].add(ts, pk)
            if n >= th["icmp_packets"]:
                out += self._fire("icmp_flood", src, ts, src_ip=src,
                                  summary=f"{n} ICMP packets in {th['icmp_window_s']}s from {src} toward {dst}",
                                  evidence=[f"packets={n}", f"target={dst}"])

        if ev.get("syns") and by <= th["scan_max_bytes"]:
            dq = self.scan[src]
            dq.append((ts, dst, port))
            while dq and dq[0][0] < ts - th["scan_window_s"]:
                dq.popleft()
            targets = {(d, p) for _, d, p in dq}
            if len(targets) >= th["scan_targets"]:
                ports = sorted({p for _, p in targets})
                out += self._fire("port_scan", src, ts, src_ip=src,
                                  summary=f"{src} probed {len(targets)} host:port pairs in {th['scan_window_s']}s",
                                  evidence=[f"hosts={len({d for d, _ in targets})}", f"ports={ports[:20]}"])

        external = not is_private(dst)
        if external and by:
            n = self.exfil[src].add(ts, ev.get("bytes_out", by))
            if n >= th["exfil_bytes"]:
                out += self._fire("exfil_volume", src, ts, src_ip=src, target=dst,
                                  summary=f"{n/1e6:.0f} MB sent from {src} in {th['exfil_window_s']}s, latest to {dst}",
                                  evidence=[f"bytes_out={n}", f"destination={dst}:{port}"])

        if dst in self.cfg["blocklist_ips"]:
            out += self._fire("bad_destination", (src, dst), ts, src_ip=src, target=dst,
                              summary=f"{src} contacted blocklisted {dst}:{port}",
                              evidence=[f"destination={dst}", f"sni={ev.get('sni')}"])
        if external and port in self.cfg["risky_ports"] and ev.get("syns"):
            out += self._fire("suspicious_port", (src, dst, port), ts, src_ip=src, target=dst,
                              summary=f"{src} opened a connection to {dst}:{port}",
                              evidence=[f"port={port}"])

        if external and port not in th["beacon_ignore_ports"] and ev.get("syns"):
            key = (src, dst, port)
            if key not in self.beacon_done:
                tl = self.conn_ts[key]
                tl.append(ts)
                del tl[:-60]                       # bounded memory for long-running capture
                if len(tl) >= th["beacon_min_conn"]:
                    gaps = [b - a for a, b in zip(tl, tl[1:])]
                    mean = statistics.mean(gaps)
                    cv = statistics.pstdev(gaps) / mean if mean else 9
                    if mean >= th["beacon_min_period_s"] and cv < th["beacon_cv_max"]:
                        self.beacon_done.add(key)
                        out += self._fire("beaconing", key, ts, src_ip=src, target=dst,
                                          summary=f"{src} -> {dst}:{port} every {mean:.0f}s ({len(tl)} connections, jitter {cv:.2f})",
                                          evidence=[f"connections={len(tl)}", f"mean_interval={mean:.1f}s", f"cv={cv:.3f}"])
        return out

    def on_dns(self, ev):
        out, ts, src, q = [], ev["ts"], ev["src_ip"], ev["query"].lower().rstrip(".")
        th = self.th
        if parent_domain(q) in self.cfg["blocklist_domains"] or q in self.cfg["blocklist_domains"]:
            out += self._fire("bad_destination", (src, q), ts, src_ip=src, target=q,
                              summary=f"{src} resolved blocklisted domain {q}", evidence=[f"query={q}"])
        labels = q.split(".")
        if len(labels) >= 3:
            sub = labels[0]
            if len(sub) >= th["dns_label_len"] and entropy(sub) >= th["dns_entropy"]:
                key = (src, parent_domain(q))
                if len(self.dns_subs[key]) < 500:
                    self.dns_subs[key].add(sub)
                n = len(self.dns_subs[key])
                if n >= th["dns_min_unique"]:
                    out += self._fire("dns_tunnel", key, ts, src_ip=src, target=key[1],
                                      summary=f"{src} sent {n} long random sub-domains of {key[1]}",
                                      evidence=[f"unique_subdomains={n}", f"example={q}"])
        return out
