# Test report

Run on 2026-10-04 against the built-in lab scenario (synthetic traffic). Python 3.11, Chromium headless via Playwright.

## Summary
| Layer | Result |
|---|---|
| Unit tests (`pytest`) | 39 passed on Python 3.9, 3.10, 3.12 and 3.13 |
| Fresh-install check (`pip install .` in a clean venv, `wifiguardian run`) | passed |
| Dashboard end-to-end (browser, 43 checks) | 43 passed |
| Live server + browser (`serve`, SSE stream, Approve buttons in semi mode) | passed (5 checks) |
| CLI commands | all ran as expected |
| Not tested | scapy sniffer, dnsmasq watcher on a real gateway, nftables rules loaded on a real kernel, deauth capture with real hardware |

## Detections (each fires on the scenario, and benign cases stay quiet)
| Rule | Fires on | Stays quiet on |
|---|---|---|
| unknown_device | guest phone, Kali VM | five allowlisted devices |
| port_scan | 20+ distinct host:port pairs in 30 s | 40 probes to one port |
| syn_flood | 240 SYNs in 10 s | 50 SYNs in 10 s |
| arp_spoof (critical) | non-gateway MAC claiming gateway IP | genuine gateway ARP |
| rogue_dhcp | offer from another MAC | offer from the gateway |
| deauth_flood | 36 frames in 10 s | 10 frames |
| beaconing | 30 s interval with 1 s jitter | irregular browsing, NTP |
| dns_tunnel | 10+ long random sub-domains | normal names |
| exfil_volume | 52 MB in 60 s to the internet | normal browsing |
| bad_destination | blocklisted IP and domain | n/a |
| suspicious_port | outbound Telnet | n/a |
| cooldown | 200 scan probes raise one alert, not 200 | |

## Forensic record
- Connection log has MAC, IP, hostname, vendor, randomized flag, join and leave times; a rejoin without a new lease keeps the last IP.
- Audit hash chain verifies; editing a row or deleting a row is detected (tests plus a manual tamper run: `audit chain BROKEN at seq 13`).
- `export-case` writes CSV, timeline JSON and audit chain; SHA-256 values in `MANIFEST.json` match the files.
- CSV export neutralizes formula-style hostnames (`=HYPERLINK(...)`).

## Response layer
- monitor: 9 recommended, 4 advice-only, nothing changed.
- semi: 9 pending approval.
- auto without `--apply`: 9 dry runs with exact nft commands.
- Gateway and admin laptop are skipped as protected; domain targets become advice, not nft commands.

## Dashboard checks (all passed)
Pause/resume, seek, speed, theme toggle; KPIs and rail counters; live alert feed; top talkers; DNS ticker; traffic chart; map canvas draws; alert queue, severity filters, alert detail (evidence, ATT&CK, L1 steps, nft command), status changes lower the open count; open device from alert; device table and detail (MAC, vendor, sessions, destinations, DNS names, alerts); approve device; connection log, CSV download, integrity panel; response table and protected list; replay end and restart; hostile hostname, DNS name and alert text rendered as text (no script execution); no JavaScript errors; no horizontal scroll at 390 px.

## Issues found while testing and fixed
1. A device that rejoined without a new DHCP lease showed no IP in the log. It now keeps its last known IP.
2. Device detail listed only the top 6 destinations, which hid the small C2 beacon traffic. It now lists 10 destinations and 14 DNS names.
3. CLI `run` did not show what the response layer did; it now prints an action summary.

## Hardening pass (before publishing)
- Every event is validated: bad MACs, IPs, timestamps, negative numbers, unknown types and unknown protocols are rejected with a reason. A 4,000-event random fuzz run raises no exception.
- Hostile strings (SQL, HTML) in hostnames and DNS names are stored as data and escaped on screen.
- Server: path traversal blocked, POST needs custom header and same origin, body size limited, port-in-use gives a clear message, a failed live source is shown in the dashboard instead of silently stopping.
- Memory: live feed capped at 20,000 items, beacon and DNS trackers bounded, packet flows merged per second before analysis.
- Reusing a database file: alert and action ids continue instead of overwriting, approved devices are remembered, sessions left open by a previous run are closed.
- Windows console output no longer crashes on odd characters in hostnames.
- Approve buttons for pending actions and devices (semi mode).

## Known gaps
- Vendor lookup uses a small demo table.
- Everything above ran on simulated traffic.
