# WiFi Guardian: Live Network Monitor + Auto-Block (design proposal)

Status: proposal only. Nothing is built yet. Use only on a network you own.

## 1. What it is
A small Linux box (Raspberry Pi, old laptop, or a VM) that sits between your WiFi and the internet and does four jobs:
1. **See** every device and every connection in real time.
2. **Detect** suspicious behaviour (unknown device, flood, scan, spoofing, beaconing).
3. **Block** it automatically (or after one click, your choice).
4. **Explain** it like a SOC alert: severity, evidence, MITRE ATT&CK tag, recommended L1 action.

It is a mini NDR/IPS (network detection and response). That is what L1 SOC analysts triage every day.

## 2. Important reality check (so the project is honest)
- **"Real requests" = metadata, not content.** HTTPS is encrypted. We can see: device, destination IP, port, DNS names asked, TLS SNI (site name), bytes, timing, protocol. We cannot read page content or passwords. For plain HTTP we can see URLs.
- **We must sit in the path.** To see and block traffic, the box has to be the gateway/router (or the WiFi AP itself), or get a mirrored copy of traffic. A laptop just joined to the WiFi only sees its own traffic.
- **DDoS from the internet cannot be stopped by our box.** If an attacker fills your ISP line, only the ISP/CDN can help. What we CAN do: stop floods coming from devices inside the WiFi, throttle abusive sources, drop SYN floods and bad packets before they hurt the router, rate-limit new connections, and detect/alert on inbound flood patterns. We will label this "DoS/flood protection", and be clear in the README about the limit.
- **Deauth attacks** (kicking people off WiFi) need a second WiFi adapter in monitor mode to detect.

## 3. Features

### A. Live visibility
- Device inventory: IP, MAC, vendor (from MAC OUI), hostname, first/last seen, status (known / unknown / blocked).
- Live flow table: device -> destination IP, port, protocol, bytes, country/ASN (offline GeoIP).
- DNS log per device (what names each device asked for).
- TLS SNI log (which HTTPS sites, without decrypting).
- Top talkers, bandwidth per device, protocol mix, live traffic graph.

### B. Detections (each one is a rule with a name, severity and MITRE tag)
| Detection | How | MITRE |
|---|---|---|
| Unknown device joined | MAC not in allowlist / new DHCP lease | T1200 Hardware Additions |
| SYN flood / connection flood | new-connection rate per source over threshold | T1498 Network DoS |
| UDP / ICMP flood | packet rate per source | T1498 |
| Port scan | one source hitting many ports/hosts quickly | T1046 Network Service Discovery |
| ARP spoofing / MITM | IP-MAC mapping changes, gratuitous ARP spam | T1557 Adversary-in-the-Middle |
| Rogue DHCP server | DHCP offers from unexpected MAC | T1557 |
| DNS tunneling / DGA | long/high-entropy names, query volume (reuse your netanalyzer) | T1071.004 |
| Beaconing | regular-interval connections (reuse your netanalyzer) | T1071 |
| Known-bad destination | IP/domain on a blocklist (abuse.ch, Feodo, URLhaus feeds) | T1071 / T1568 |
| Suspicious ports | outbound to Telnet, SMB, RDP, odd high ports | various |
| Data exfil spike | one device uploads far more than its baseline | T1041 |
| Deauth flood (needs monitor-mode adapter) | many 802.11 deauth frames | T1498 / T1465 |
| MAC spoofing | known MAC with a changed vendor fingerprint / TTL | T1036 |

### C. Auto-protection (the "block immediately" part)
- **Default-deny for unknown devices:** unknown MAC goes to a quarantine group: internet blocked, only the dashboard can reach it, until you approve it. This answers "immediately block unknown device".
- **Auto-block rules** via nftables sets with timeouts: block a source IP/MAC for 10 min, 1 hr, or permanently.
- **Rate limits:** per-device new-connection and packet-rate limits; SYN cookies; drop invalid packets.
- **Modes:** Monitor only (alerts), Semi-auto (one-click approve), Full auto (blocks by itself). Starts in Monitor mode, so it cannot lock you out by mistake.
- **Safety:** your own admin device and the router are never blockable (protected list); every block is logged and has an undo button.

### D. SOC-analyst workflow (this is what makes it a *SOC* project, not just a firewall)
- Alert queue with severity, status (new / investigating / closed), assignee notes.
- Alert detail: evidence (packets/flows), timeline, affected device, MITRE tag, "what to do next" playbook steps for L1.
- One-click actions: block, quarantine, allowlist, mark false positive.
- Incident report export (Markdown/PDF), similar to your INC-2026-001 report.
- Daily summary: top alerts, new devices, blocked count.

### E. Dashboard (animated, not generic)
- Live network map: router in the middle, devices as nodes, animated traffic pulses along links, red pulse on suspicious.
- Live alert feed with sound/flash on critical.
- Attack replay: "play" a recorded attack so recruiters can see it without your hardware.
- Dark SOC theme matching your soc-triage-console style.

## 4. Architecture
```
 Phone/Laptop --WiFi--> [ Linux gateway box ] --> Router/Internet
                          |  capture (scapy / Zeek / Suricata)
                          |  detectors (Python rules)
                          |  enforcement (nftables / ipset, DHCP allowlist)
                          |  storage (SQLite)
                          |  API (FastAPI + WebSocket)
                          v
                     Web dashboard (HTML/JS, live)
```
Suggested stack: Python 3, scapy (or Zeek for richer logs), nftables, SQLite, FastAPI, vanilla JS + canvas/SVG for the map. Optional: Suricata with ET Open rules for signature detections.

## 5. Hardware / setup options
1. **Best:** Raspberry Pi or mini PC with an Ethernet port, acting as router/AP (hostapd + dnsmasq). Full visibility and blocking.
2. **Good:** Ubuntu VM in VirtualBox with a bridged adapter, plus Kali VM to generate test attacks (matches the video's lab style).
3. **Demo-only:** replay PCAP files in the dashboard with no real network.

Because many people can't run hardware, the repo ships with **simulated traffic and attack PCAPs** so everything runs on any laptop.

## 6. Safe testing plan
Attacks are generated only against your own lab: Kali VM running nmap (scan), hping3 (SYN/UDP flood), arpspoof/ettercap (ARP spoof), a fake beacon script, and a second unknown VM (new device). Each detection gets a unit test using PCAP/sample data, same as your other tools.

## 7. Build phases
- **MVP (v0.1):** device inventory + live flows + dashboard + unknown-device detection + alert queue, running on sample PCAPs.
- **v0.2:** flood, port-scan, ARP-spoof detections + nftables auto-block with undo + protected list.
- **v0.3:** DNS/SNI log, beaconing/DNS-tunnel (reusing netanalyzer), threat-feed blocklists, MITRE tags.
- **v0.4:** incident report export, playbooks, attack replay, deauth detection (optional hardware), README with screenshots and demo GIF.

## 8. Overlap with what you already have
- Reuses ideas from `netanalyzer` (beaconing, DNS tunneling) but adds live capture, enforcement and device tracking, which you don't have.
- Not a duplicate of phishscan, intellidetect-siem (rules/SIEM), or the log-file detectors: this one is live, real-time, and *acts*.

## 9. What recruiters / interviewers see
Live detection, response automation, MITRE mapping, triage workflow, safe-by-default design, tests, and honest limits. You can talk about each in an interview.

## 10. Open questions for you
1. Hardware: do you have a Raspberry Pi / spare laptop, or should we target VirtualBox VMs plus replayable PCAPs?
2. OS you will run it on (Ubuntu/Kali/Windows host with VMs)?
3. Default mode: Monitor-only first (recommended), or full auto-block from day one?
4. Include deauth detection (needs a USB WiFi adapter that supports monitor mode)?
5. Repo: add as a new tool inside `soc-triage-console`, or a separate repo `wifi-guardian`?
