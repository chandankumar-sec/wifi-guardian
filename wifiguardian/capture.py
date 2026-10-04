"""Live sources. Both are optional; the simulator needs neither.

parse_dnsmasq_leases  turns a dnsmasq lease file into dhcp events (tested).
sniff                 turns packets from an interface into events using scapy (experimental: written for the
                      VirtualBox lab gateway, not tested on live hardware yet). Deauth frames need an adapter in
                      monitor mode, pass it as monitor_iface.
"""
import threading
import time


def parse_dnsmasq_leases(path):
    """Line format: <expiry-epoch> <mac> <ip> <hostname|*> <client-id|*>"""
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 4:
                continue
            expiry, mac, ip, host = parts[:4]
            events.append({"type": "dhcp", "ts": float(expiry) - 43200, "mac": mac, "ip": ip,
                           "hostname": None if host == "*" else host, "action": "lease"})
    return events


class FlowAggregator:
    """Packets arrive thousands per second; the engine wants one record per flow per second.
    add_event() takes sniffer events (flows are merged, everything else passes straight through)."""

    def __init__(self, sink, interval=1.0):
        self.sink, self.interval = sink, interval
        self.buf, self.lock, self.stopped = {}, threading.Lock(), False

    def add_event(self, ev):
        if ev["type"] != "flow":
            return self.sink(ev)
        key = (ev["src_ip"], ev["dst_ip"], ev.get("dport", 0), ev.get("proto", "tcp"))
        with self.lock:
            cur = self.buf.get(key)
            if cur is None:
                self.buf[key] = dict(ev)
            else:
                for f in ("bytes", "packets", "syns"):
                    cur[f] = cur.get(f, 0) + ev.get(f, 0)
                cur["bytes_out"] = cur.get("bytes_out", 0) + ev.get("bytes", 0)

    def flush(self):
        with self.lock:
            out, self.buf = list(self.buf.values()), {}
        for ev in out:
            self.sink(ev)
        return len(out)

    def run(self):
        while not self.stopped:
            time.sleep(self.interval)
            self.flush()


def sniff(iface, on_event, monitor_iface=None, stop=lambda: False):
    try:
        from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Dot11Deauth, sniff as _sniff
    except ImportError as exc:
        raise SystemExit("live capture needs scapy: pip install scapy (and run as root)") from exc

    def handle(p):
        now = time.time()
        if p.haslayer(ARP) and p[ARP].op == 2:
            on_event({"type": "arp", "ts": now, "op": "reply", "src_mac": p[ARP].hwsrc,
                      "src_ip": p[ARP].psrc, "dst_ip": p[ARP].pdst})
        elif p.haslayer(Dot11Deauth):
            on_event({"type": "deauth", "ts": now, "src_mac": p.addr2, "dst_mac": p.addr1, "count": 1})
        elif p.haslayer(IP):
            ip = p[IP]
            if p.haslayer(DNS) and p.haslayer(DNSQR) and p[DNS].qr == 0:
                on_event({"type": "dns", "ts": now, "src_ip": ip.src,
                          "query": p[DNSQR].qname.decode(errors="replace").rstrip("."), "qtype": "A"})
            proto = "tcp" if p.haslayer(TCP) else "udp" if p.haslayer(UDP) else "icmp" if p.haslayer(ICMP) else None
            if proto:
                syn = int(p.haslayer(TCP) and (int(p[TCP].flags) & 0x12) == 0x02)
                dport = p[TCP].dport if proto == "tcp" else p[UDP].dport if proto == "udp" else 0
                on_event({"type": "flow", "ts": now, "src_ip": ip.src, "dst_ip": ip.dst, "dport": dport,
                          "proto": proto, "bytes": len(p), "packets": 1, "syns": syn})

    _sniff(iface=iface, prn=handle, store=False, stop_filter=lambda _p: stop())
