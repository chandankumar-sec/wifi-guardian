"""Synthetic lab traffic so the whole tool runs on any laptop with no hardware and no real network.

The scenario mirrors a VirtualBox lab: five known devices, one Kali VM attacker, one unknown guest phone.
All IPs are private or RFC 5737 documentation ranges, all domains end in .example.
"""
import random

from .config import build

BASE_TS = 1791057600  # 2026-10-03 20:00:00 UTC, so the forensic log shows real-looking dates
GW_IP, GW_MAC = "192.168.50.1", "50:c7:bf:11:22:33"

KNOWN = [  # mac, ip, hostname, friendly name
    ("00:14:22:a1:b2:01", "192.168.50.20", "chandan-laptop", "Chandan laptop"),
    ("00:12:47:c3:d4:02", "192.168.50.31", "galaxy-chandan", "Chandan phone"),
    ("00:12:47:e5:f6:03", "192.168.50.40", "livingroom-tv", "Living room TV"),
    ("b8:27:eb:07:08:04", "192.168.50.50", "pi-nas", "Raspberry Pi NAS"),
    ("3c:d9:2b:19:2a:05", "192.168.50.60", "hp-printer", "HP printer"),
]
GUEST = ("da:a1:19:5c:3e:77", "192.168.50.77", "iPhone", None)        # private (randomized) address
ATTACKER = ("08:00:27:de:ad:99", "192.168.50.99", "kali", None)       # Kali VM in VirtualBox

C2 = "203.0.113.77"
BAD_IP = "198.51.100.66"
SITES = [("142.250.0.10", "search.example"), ("151.101.0.20", "video.example"), ("104.16.0.30", "news.example"),
         ("13.107.0.40", "mail.example"), ("93.184.0.50", "shop.example")]
NTP = "129.6.15.28"

DEMO_OVERRIDES = {
    "ssid": "HomeLab-WiFi",
    "gateway": {"ip": GW_IP, "mac": GW_MAC},
    "allowlist": {m: n for m, _, _, n in KNOWN},
    "blocklist_ips": [BAD_IP],
    "blocklist_domains": ["c2-update.example"],
    "protected": [KNOWN[0][0]],   # the admin laptop can never be blocked
}


def demo_config(mode="monitor"):
    return build({**DEMO_OVERRIDES, "mode": mode})


def _flow(ts, src, dst, port, nbytes, sni=None, syns=1, proto="tcp", packets=None, bytes_out=None):
    ev = {"type": "flow", "ts": ts, "src_ip": src, "dst_ip": dst, "dport": port, "proto": proto,
          "bytes": nbytes, "syns": syns, "packets": packets or max(2, nbytes // 900)}
    if sni:
        ev["sni"] = sni
    if bytes_out is not None:
        ev["bytes_out"] = bytes_out
    return ev


def scenario(seed=7, duration=560):
    rnd = random.Random(seed)
    ev = []

    # known devices join and get leases
    for i, (mac, ip, host, _) in enumerate(KNOWN):
        t = 1 + i * 2
        ev.append({"type": "assoc", "ts": t, "mac": mac, "action": "join", "bssid": GW_MAC,
                   "ssid": "HomeLab-WiFi", "rssi": -rnd.randint(40, 68)})
        ev.append({"type": "dhcp", "ts": t + 0.5, "mac": mac, "ip": ip, "hostname": host, "action": "lease"})

    # benign background: browsing, DNS, and a perfectly regular NTP poll (must NOT trigger beaconing)
    for mac, ip, host, _ in KNOWN:
        t = 12 + rnd.random() * 5
        while t < duration:
            dst, sni = rnd.choice(SITES)
            ev.append({"type": "dns", "ts": t, "src_ip": ip, "query": sni, "qtype": "A"})
            ev.append(_flow(t + 0.2, ip, dst, 443, rnd.randint(8_000, 900_000), sni=sni, syns=rnd.randint(1, 3)))
            t += rnd.uniform(6, 22)
        for t in range(20, duration, 64):
            ev.append(_flow(t + 0.1, ip, NTP, 123, 90, proto="udp", syns=0, packets=2))

    # guest phone with a randomized MAC: unknown device, browses normally
    g_mac, g_ip, g_host, _ = GUEST
    ev.append({"type": "assoc", "ts": 120, "mac": g_mac, "action": "join", "bssid": GW_MAC, "ssid": "HomeLab-WiFi", "rssi": -61})
    ev.append({"type": "dhcp", "ts": 120.6, "mac": g_mac, "ip": g_ip, "hostname": g_host, "action": "lease"})
    for t in range(130, 260, 14):
        dst, sni = rnd.choice(SITES)
        ev.append({"type": "dns", "ts": t, "src_ip": g_ip, "query": sni, "qtype": "A"})
        ev.append(_flow(t + 0.2, g_ip, dst, 443, rnd.randint(20_000, 400_000), sni=sni))
    ev.append({"type": "assoc", "ts": 270, "mac": g_mac, "action": "leave"})

    # compromised Raspberry Pi: beacons to a C2 every 30 s from t=100
    pi_ip = KNOWN[3][1]
    for k in range(16):
        ev.append(_flow(100 + k * 30 + rnd.uniform(-1, 1), pi_ip, C2, 443, 640, syns=1))

    # attacker Kali VM joins at 150
    a_mac, a_ip, a_host, _ = ATTACKER
    ev.append({"type": "assoc", "ts": 150, "mac": a_mac, "action": "join", "bssid": GW_MAC, "ssid": "HomeLab-WiFi", "rssi": -48})
    ev.append({"type": "dhcp", "ts": 150.6, "mac": a_mac, "ip": a_ip, "hostname": a_host, "action": "lease"})

    # port scan of the laptop and printer (t=170..176)
    for i in range(40):
        tgt = KNOWN[0][1] if i % 2 else KNOWN[4][1]
        ev.append(_flow(170 + i * 0.15, a_ip, tgt, 20 + i * 11, 60, syns=1))

    # SYN flood against the printer (t=210..219)
    for i in range(10):
        ev.append(_flow(210 + i, a_ip, KNOWN[4][1], 80, 40_000, syns=60, packets=60))

    # ARP spoof: attacker claims the gateway IP (t=260) and a host IP (t=262)
    ev.append({"type": "arp", "ts": 260, "op": "reply", "src_mac": a_mac, "src_ip": GW_IP, "dst_ip": KNOWN[0][1]})
    ev.append({"type": "arp", "ts": 262, "op": "reply", "src_mac": a_mac, "src_ip": KNOWN[2][1], "dst_ip": GW_IP})

    # rogue DHCP offer (t=300)
    ev.append({"type": "dhcp_offer", "ts": 300, "server_mac": a_mac, "server_ip": a_ip,
               "gateway": a_ip, "dns": "203.0.113.53"})

    # deauth flood against the phone (t=330..339)
    for i in range(10):
        ev.append({"type": "deauth", "ts": 330 + i, "src_mac": GW_MAC, "dst_mac": KNOWN[1][0], "count": 12})

    # DNS tunneling from the laptop?  no: from the Pi, after C2 contact (t=380..)
    for i in range(14):
        sub = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(32))
        ev.append({"type": "dns", "ts": 380 + i * 1.5, "src_ip": pi_ip, "query": f"{sub}.tunnel.example", "qtype": "TXT"})

    # exfiltration: Pi uploads 80 MB in one minute (t=430..)
    for i in range(8):
        ev.append(_flow(430 + i * 6, pi_ip, "203.0.113.90", 443, 10_000_000, syns=1, bytes_out=10_000_000))

    # smart TV contacts a blocklisted IP (t=480)
    ev.append({"type": "dns", "ts": 479, "src_ip": KNOWN[2][1], "query": "c2-update.example", "qtype": "A"})
    ev.append(_flow(480, KNOWN[2][1], BAD_IP, 8443, 1200, sni="c2-update.example"))

    # risky outbound port from the printer (t=500)
    ev.append(_flow(500, KNOWN[4][1], "203.0.113.200", 23, 200))

    # phone briefly disconnects (deauth effect) and rejoins
    ev.append({"type": "assoc", "ts": 341, "mac": KNOWN[1][0], "action": "leave"})
    ev.append({"type": "assoc", "ts": 346, "mac": KNOWN[1][0], "action": "join", "bssid": GW_MAC,
               "ssid": "HomeLab-WiFi", "rssi": -55})

    ev.sort(key=lambda e: e["ts"])
    for e in ev:
        e["ts"] = round(BASE_TS + e["ts"], 3)
    return ev
