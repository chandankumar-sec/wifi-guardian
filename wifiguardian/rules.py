"""Rule catalogue: severity, MITRE ATT&CK mapping, recommended response and the L1 analyst playbook.

Every alert carries its rule's text so an analyst never has to guess what to do next.
"""

RULES = {
    "unknown_device": {
        "title": "Unknown device joined the WiFi",
        "severity": "medium",
        "mitre": ["T1200"],
        "action": "quarantine_mac",
        "playbook": [
            "Check the MAC and vendor. A randomized MAC is normal for phones, but ask who it belongs to.",
            "Compare the join time with visitors or new devices you expect.",
            "If it is yours, approve it (adds it to the allowlist). If not, keep it quarantined and change the WiFi password.",
            "Review the DNS and connection log of this MAC for the time it was online.",
        ],
    },
    "syn_flood": {
        "title": "SYN flood from a LAN device",
        "severity": "high",
        "mitre": ["T1498"],
        "action": "quarantine_mac",
        "playbook": [
            "Confirm the source MAC and device owner.",
            "Check whether the target is a single host (attack) or many hosts (scan).",
            "Isolate the source until the owner confirms it is not malicious.",
            "Escalate to L2 if the source is a known, trusted device (possible compromise).",
        ],
    },
    "udp_flood": {
        "title": "UDP packet flood from a LAN device",
        "severity": "high",
        "mitre": ["T1498"],
        "action": "quarantine_mac",
        "playbook": [
            "Identify target host and port.",
            "Isolate the source MAC and note start time for the incident report.",
            "Escalate if the source is a trusted device.",
        ],
    },
    "icmp_flood": {
        "title": "ICMP flood from a LAN device",
        "severity": "medium",
        "mitre": ["T1498"],
        "action": "rate_limit_ip",
        "playbook": [
            "Check the target. Large pings to the gateway can be a test tool, to a single host an attack.",
            "Rate-limit the source and ask the owner what they were running.",
        ],
    },
    "port_scan": {
        "title": "Port scan inside the network",
        "severity": "high",
        "mitre": ["T1046"],
        "action": "quarantine_mac",
        "playbook": [
            "Note the source MAC/IP and the list of ports and hosts probed.",
            "A new or unknown device scanning is high risk. A known device scanning may be compromised.",
            "Isolate the source and escalate to L2 with the evidence list.",
        ],
    },
    "arp_spoof": {
        "title": "ARP spoofing (possible man-in-the-middle)",
        "severity": "critical",
        "mitre": ["T1557.002"],
        "action": "quarantine_mac",
        "playbook": [
            "Compare the MAC that claimed the IP with the real owner's MAC.",
            "If the claimed IP is the gateway, treat every device as exposed: traffic may be intercepted.",
            "Quarantine the claiming MAC immediately and escalate to L2.",
            "Ask users to avoid logging in to anything until cleared; rotate any credentials used meanwhile.",
        ],
    },
    "rogue_dhcp": {
        "title": "Rogue DHCP server",
        "severity": "high",
        "mitre": ["T1557"],
        "action": "quarantine_mac",
        "playbook": [
            "A second DHCP server can hand out a malicious gateway or DNS. Identify the offering MAC.",
            "Quarantine it. Check which clients got a lease from it.",
            "Renew leases on affected clients after it is removed.",
        ],
    },
    "beaconing": {
        "title": "Regular outbound beaconing (possible C2)",
        "severity": "high",
        "mitre": ["T1071"],
        "action": "block_dst",
        "playbook": [
            "Note interval, destination and port. Regular timing to one external host is the key signal.",
            "Check the destination against threat intel and the device against what it should be doing.",
            "Block the destination and escalate to L2 for host investigation.",
        ],
    },
    "dns_tunnel": {
        "title": "DNS tunneling pattern",
        "severity": "high",
        "mitre": ["T1071.004", "T1048"],
        "action": "advise",
        "playbook": [
            "Look at the queried names: many long random sub-domains of one domain is the signal.",
            "Block or sinkhole the parent domain at the resolver.",
            "Escalate to L2 for the source device.",
        ],
    },
    "exfil_volume": {
        "title": "Unusually large upload to the internet",
        "severity": "medium",
        "mitre": ["T1041"],
        "action": "rate_limit_ip",
        "playbook": [
            "Confirm the device and destination. Cloud backups and updates are common false positives.",
            "If the destination is unknown or the device is idle otherwise, rate-limit and escalate.",
        ],
    },
    "bad_destination": {
        "title": "Contact with a blocklisted destination",
        "severity": "high",
        "mitre": ["T1071"],
        "action": "block_dst",
        "playbook": [
            "Check which feed listed the destination and why.",
            "Block the destination and review all traffic from this device for the last day.",
            "Escalate to L2 if the device keeps retrying (malware likely).",
        ],
    },
    "suspicious_port": {
        "title": "Outbound connection to a risky port",
        "severity": "low",
        "mitre": ["T1571"],
        "action": "advise",
        "playbook": [
            "Telnet, SMB, RDP or well-known backdoor ports leaving the home network are rarely legitimate.",
            "Ask the owner what the device was doing.",
        ],
    },
    "deauth_flood": {
        "title": "WiFi deauthentication flood",
        "severity": "high",
        "mitre": ["T1498"],
        "action": "advise",
        "playbook": [
            "Deauth frames kick devices off WiFi and are used to capture handshakes or force reconnects to an evil twin.",
            "Enable 802.11w (Protected Management Frames) on the access point if it supports it.",
            "Check for a rogue access point with the same SSID. Escalate to L2.",
        ],
    },
}

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

MITRE_NAMES = {
    "T1200": "Hardware Additions",
    "T1498": "Network Denial of Service",
    "T1046": "Network Service Discovery",
    "T1557": "Adversary-in-the-Middle",
    "T1557.002": "ARP Cache Poisoning",
    "T1071": "Application Layer Protocol",
    "T1071.004": "DNS",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1571": "Non-Standard Port",
}
