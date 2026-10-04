"""Configuration: thresholds, allowlist, protected devices. Plain JSON, all keys optional."""
import copy
import json

from .oui import norm_mac

DEFAULTS = {
    "ssid": "HomeLab-WiFi",
    "mode": "monitor",             # monitor | semi | auto
    "gateway": {"ip": "192.168.50.1", "mac": "50:c7:bf:11:22:33"},
    "dhcp_server_mac": None,       # defaults to gateway mac
    "lan_prefix": "192.168.",
    "allowlist": {},               # mac -> friendly name
    "protected": [],               # macs / ips that can never be blocked (gateway and admin are added automatically)
    "admin_macs": [],
    "cooldown_s": 300,             # same rule + same source is not re-alerted inside this window
    "thresholds": {
        "syn_window_s": 10, "syn_count": 200,
        "udp_window_s": 10, "udp_packets": 2000,
        "icmp_window_s": 10, "icmp_packets": 300,
        "scan_window_s": 30, "scan_targets": 15, "scan_max_bytes": 1500,
        "beacon_min_conn": 10, "beacon_cv_max": 0.2, "beacon_min_period_s": 5,
        "beacon_ignore_ports": [53, 123],
        "dns_min_unique": 10, "dns_label_len": 20, "dns_entropy": 3.3,
        "exfil_window_s": 60, "exfil_bytes": 50_000_000,
        "deauth_window_s": 10, "deauth_frames": 30,
    },
    "risky_ports": [23, 445, 3389, 4444, 5900, 31337],
    "blocklist_ips": [],
    "blocklist_domains": [],
}


def _merge(base, extra):
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def build(overrides=None):
    cfg = _merge(copy.deepcopy(DEFAULTS), overrides or {})
    cfg["gateway"]["mac"] = norm_mac(cfg["gateway"]["mac"])
    cfg["allowlist"] = {norm_mac(m): n for m, n in cfg["allowlist"].items()}
    cfg["dhcp_server_mac"] = norm_mac(cfg["dhcp_server_mac"] or cfg["gateway"]["mac"])
    prot = {cfg["gateway"]["mac"], cfg["gateway"]["ip"]}
    prot.update(norm_mac(m) for m in cfg["admin_macs"])
    prot.update(norm_mac(p) if ":" in p else p for p in cfg["protected"])
    cfg["protected"] = sorted(prot)
    if cfg["mode"] not in ("monitor", "semi", "auto"):
        raise ValueError("mode must be monitor, semi or auto")
    return cfg


def load(path=None):
    if not path:
        return build()
    with open(path, encoding="utf-8") as fh:
        return build(json.load(fh))
