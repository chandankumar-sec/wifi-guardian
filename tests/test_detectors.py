from wifiguardian.config import build
from wifiguardian.engine import Engine
from wifiguardian.simulator import GW_IP, GW_MAC, KNOWN, demo_config, scenario

LAPTOP = KNOWN[0]


def run(events, cfg=None):
    eng = Engine(cfg or demo_config())
    for e in events:
        eng.process(e)
    return eng


def rules(eng):
    return [a["rule"] for a in eng.alerts.values()]


def flow(ts, src, dst, port, nbytes=500, syns=1, **kw):
    return {"type": "flow", "ts": ts, "src_ip": src, "dst_ip": dst, "dport": port, "proto": "tcp",
            "bytes": nbytes, "syns": syns, **kw}


def test_full_scenario_fires_every_rule_once():
    eng = run(scenario())
    got = rules(eng)
    for r in ["unknown_device", "port_scan", "syn_flood", "arp_spoof", "rogue_dhcp", "deauth_flood",
              "beaconing", "dns_tunnel", "exfil_volume", "bad_destination", "suspicious_port"]:
        assert r in got, r
    assert got.count("unknown_device") == 2        # guest phone + Kali VM
    assert got.count("beaconing") == 1             # no alert storm


def test_known_devices_and_regular_ntp_do_not_alert():
    eng = run([e for e in scenario() if e["type"] in ("assoc", "dhcp") and e.get("mac", "").lower() in
               {k[0] for k in KNOWN}] + [flow(1791057700 + i * 64, LAPTOP[1], "129.6.15.28", 123, 90, syns=0) for i in range(30)])
    assert eng.alerts == {}


def test_regular_beacon_to_external_host_detected_but_irregular_browsing_not():
    ip = LAPTOP[1]
    reg = run([flow(i * 30, ip, "203.0.113.5", 443) for i in range(12)])
    assert rules(reg) == ["beaconing"]
    irregular = [0, 7, 31, 33, 90, 91, 140, 200, 203, 260, 330, 331]
    assert rules(run([flow(t, ip, "203.0.113.5", 443) for t in irregular])) == []


def test_flood_below_threshold_is_quiet():
    assert rules(run([flow(i, "192.168.50.20", "192.168.50.60", 80, syns=5) for i in range(10)])) == []


def test_port_scan_needs_many_distinct_targets():
    same = [flow(i * 0.2, "192.168.50.99", "192.168.50.60", 80, 60) for i in range(40)]
    assert "port_scan" not in rules(run(same))
    spread = [flow(i * 0.2, "192.168.50.99", "192.168.50.60", 20 + i, 60) for i in range(20)]
    assert "port_scan" in rules(run(spread))


def test_arp_spoof_on_gateway_is_critical():
    eng = run([{"type": "arp", "ts": 5, "op": "reply", "src_mac": "08:00:27:aa:bb:cc", "src_ip": GW_IP, "dst_ip": "192.168.50.20"}])
    a = list(eng.alerts.values())[0]
    assert a["rule"] == "arp_spoof" and a["severity"] == "critical"


def test_genuine_gateway_arp_is_fine():
    eng = run([{"type": "arp", "ts": 5, "op": "reply", "src_mac": GW_MAC, "src_ip": GW_IP, "dst_ip": "192.168.50.20"}])
    assert eng.alerts == {}


def test_dhcp_offer_from_gateway_ok_other_is_rogue():
    ok = run([{"type": "dhcp_offer", "ts": 1, "server_mac": GW_MAC, "server_ip": GW_IP}])
    bad = run([{"type": "dhcp_offer", "ts": 1, "server_mac": "08:00:27:aa:bb:cc", "server_ip": "192.168.50.99"}])
    assert ok.alerts == {} and rules(bad) == ["rogue_dhcp"]


def test_deauth_threshold():
    few = run([{"type": "deauth", "ts": i, "src_mac": GW_MAC, "dst_mac": LAPTOP[0], "count": 2} for i in range(5)])
    many = run([{"type": "deauth", "ts": i, "src_mac": GW_MAC, "dst_mac": LAPTOP[0], "count": 12} for i in range(5)])
    assert few.alerts == {} and rules(many) == ["deauth_flood"]


def test_dns_tunnel_ignores_normal_long_names():
    ev = [{"type": "dns", "ts": i, "src_ip": LAPTOP[1], "query": "www.search.example", "qtype": "A"} for i in range(30)]
    assert run(ev).alerts == {}


def test_cooldown_prevents_alert_storm():
    ev = [flow(i * 0.1, "192.168.50.99", "192.168.50.60", 20 + i, 60) for i in range(200)]
    assert rules(run(ev)).count("port_scan") == 1


def test_private_range_check_treats_doc_ranges_as_internet():
    from wifiguardian.detectors import is_private
    assert is_private("192.168.1.5") and not is_private("203.0.113.9") and not is_private("8.8.8.8")
