# VirtualBox lab setup (Windows host)

Goal: a small lab where WiFi Guardian runs on a gateway VM and a Kali VM attacks a victim, all on your own machine.

## VMs
| VM | Role | Adapters |
|---|---|---|
| `gateway` (Ubuntu Server) | Runs WiFi Guardian, DHCP (dnsmasq), nftables | 1: NAT (internet). 2: Internal Network `wglab` |
| `victim` (Ubuntu or Windows) | Normal client | Internal Network `wglab` |
| `kali` | Attacker / unknown device | Internal Network `wglab` |

16 GB RAM is comfortable (about 3 GB per VM); 8 GB works with two VMs at a time.

## Gateway
1. Give the LAN adapter a static address, e.g. `192.168.50.1/24`, and enable forwarding: `sudo sysctl -w net.ipv4.ip_forward=1`.
2. Install dnsmasq with `dhcp-range=192.168.50.20,192.168.50.200,12h` on the LAN interface. Leases appear in `/var/lib/misc/dnsmasq.leases`.
3. NAT out to the internet (`nft add table ip nat`, masquerade on the NAT adapter) or use any NAT recipe you prefer.
4. `python3 -m wifiguardian nft-ruleset | sudo nft -f -` to load the quarantine and block sets.
5. Copy `config/example.json`, set the gateway IP/MAC, add your devices to `allowlist`.
6. Start: `sudo python3 -m wifiguardian serve --config my.json --iface <LAN iface> --leases /var/lib/misc/dnsmasq.leases --db wg.db` (needs `pip install scapy`). Open the dashboard from the host through a port forward or the gateway's LAN address.

## Generate test traffic from Kali (your own lab only)
| Test | Command | Expected alert |
|---|---|---|
| New device | boot Kali on the lab network | Unknown device joined |
| Port scan | `nmap -sS -p 1-1000 192.168.50.<victim>` | Port scan |
| SYN flood | `sudo hping3 -S --flood -p 80 192.168.50.<victim>` (stop after a few seconds) | SYN flood |
| ARP spoof | `sudo arpspoof -i eth0 -t <victim> 192.168.50.1` | ARP spoofing |
| Rogue DHCP | run a second dnsmasq on Kali | Rogue DHCP server |
| Beaconing | `while true; do curl -s http://<lab web server>/; sleep 30; done` | Beaconing |

## What a VM lab cannot show
VirtualBox internal networks are not WiFi. Real association events (SSID, BSSID, signal) and deauth detection need a physical WiFi adapter. In the VM lab, "joined" comes from the first DHCP lease. If you have a USB adapter that supports monitor mode, pass it through to the gateway VM and the deauth rule becomes live.

## Screenshots for your write-up
Run the attacks, then capture the alert queue, an alert detail with the playbook, the device register and the connection log. Export a case with `export-case` and include the `MANIFEST.json` in the repo as a sample of the evidence format.
