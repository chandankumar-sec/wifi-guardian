"""MAC helpers: vendor lookup (small demo table) and randomized-MAC detection.

The table below is only a demo subset so the tool runs with zero downloads.
For real use pass --oui path/to/oui.txt (IEEE registry, lines like "3C-D9-2B   (hex)   HP Inc.").
"""
import re

DEMO_OUI = {
    "08:00:27": "PCS Systems (VirtualBox)",
    "00:50:56": "VMware",
    "52:54:00": "QEMU/KVM",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "00:14:22": "Dell",
    "00:12:47": "Samsung",
    "3C:D9:2B": "Hewlett Packard",
    "50:C7:BF": "TP-Link",
    "00:1B:21": "Intel",
    "00:03:93": "Apple",
}

_MAC_RE = re.compile(r"^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$", re.I)


def norm_mac(mac):
    """Lower-case, colon separated. Raises ValueError on garbage."""
    if not isinstance(mac, str) or not _MAC_RE.match(mac.strip()):
        raise ValueError(f"bad MAC address: {mac!r}")
    return mac.strip().lower().replace("-", ":")


def is_randomized(mac):
    """Locally administered bit set: typical of phone 'private WiFi address' and many VMs/spoofed MACs."""
    return bool(int(norm_mac(mac)[:2], 16) & 0x02)


def load_oui(path):
    table = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^\s*([0-9A-F]{2})[-:]([0-9A-F]{2})[-:]([0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$", line, re.I)
            if m:
                table[":".join(m.group(i).upper() for i in (1, 2, 3))] = m.group(4)
    return table


def vendor(mac, table=None):
    mac = norm_mac(mac)
    if is_randomized(mac):
        return "Randomized (private address)"
    return (table or DEMO_OUI).get(mac[:8].upper(), "Unknown vendor")
