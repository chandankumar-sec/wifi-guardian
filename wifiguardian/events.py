"""Event validation. Everything that enters the engine passes through `clean`, so one malformed line
(from a file, a lease parser or a packet handler) is rejected with a clear reason instead of crashing the run.
"""
import ipaddress
import math

from .oui import norm_mac

REQUIRED = {
    "assoc": ("mac", "action"),
    "dhcp": ("mac", "ip", "action"),
    "flow": ("src_ip", "dst_ip"),
    "dns": ("src_ip", "query"),
    "arp": ("src_mac", "src_ip"),
    "dhcp_offer": ("server_mac",),
    "deauth": ("dst_mac",),
}
MACS = ("mac", "src_mac", "dst_mac", "server_mac")
IPS = ("ip", "src_ip", "dst_ip", "server_ip")
INTS = ("dport", "bytes", "packets", "syns", "count", "bytes_out", "rssi")
ACTIONS = {"assoc": ("join", "leave"), "dhcp": ("lease", "release", "offer")}


class EventError(ValueError):
    pass


def clean(ev):
    """Return a validated copy of the event (MACs lower-cased, numbers coerced) or raise EventError."""
    if not isinstance(ev, dict):
        raise EventError("event is not a JSON object")
    t = ev.get("type")
    if t not in REQUIRED:
        raise EventError(f"unknown event type {t!r}")
    out = dict(ev)
    try:
        ts = float(ev["ts"])
    except (KeyError, TypeError, ValueError):
        raise EventError("missing or non-numeric 'ts'") from None
    if not math.isfinite(ts) or ts < 0:
        raise EventError("'ts' must be a finite, non-negative number")
    out["ts"] = ts
    for k in REQUIRED[t]:
        if ev.get(k) in (None, ""):
            raise EventError(f"{t} event missing '{k}'")
    for k in MACS:
        if ev.get(k) is not None:
            try:
                out[k] = norm_mac(ev[k])
            except ValueError as exc:
                raise EventError(str(exc)) from None
    for k in IPS:
        if ev.get(k) is not None:
            try:
                out[k] = str(ipaddress.ip_address(str(ev[k]).strip()))
            except ValueError:
                raise EventError(f"bad IP address in '{k}': {ev[k]!r}") from None
    for k in INTS:
        if ev.get(k) is not None:
            try:
                out[k] = int(ev[k])
            except (TypeError, ValueError):
                raise EventError(f"'{k}' must be an integer") from None
            if k != "rssi" and out[k] < 0:
                raise EventError(f"'{k}' must not be negative")
    if t in ACTIONS and out["action"] not in ACTIONS[t]:
        raise EventError(f"{t} action must be one of {ACTIONS[t]}")
    if t == "dns":
        out["query"] = str(ev["query"])[:255]
    for k in ("hostname", "sni", "ssid"):
        if isinstance(out.get(k), str):
            out[k] = out[k][:128]
    if t == "flow":
        out["proto"] = str(ev.get("proto", "tcp")).lower()
        if out["proto"] not in ("tcp", "udp", "icmp"):
            raise EventError("proto must be tcp, udp or icmp")
    return out
