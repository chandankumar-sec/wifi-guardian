import json
import random
import threading
import urllib.error
import urllib.request

import pytest

from wifiguardian.capture import FlowAggregator
from wifiguardian.engine import Engine
from wifiguardian.events import EventError, clean
from wifiguardian.server import Runtime, Server, make_handler
from wifiguardian.simulator import ATTACKER, demo_config, scenario


def test_bad_events_are_rejected_not_fatal():
    eng = Engine(demo_config())
    bad = [None, 5, "x", {}, {"type": "nope", "ts": 1}, {"type": "flow", "ts": 1},
           {"type": "flow", "ts": "abc", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
           {"type": "flow", "ts": 1, "src_ip": "999.1.1.1", "dst_ip": "2.2.2.2"},
           {"type": "assoc", "ts": 1, "mac": "zz:zz", "action": "join"},
           {"type": "assoc", "ts": 1, "mac": "aa:bb:cc:00:00:01", "action": "explode"},
           {"type": "flow", "ts": -5, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
           {"type": "flow", "ts": float("nan"), "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
           {"type": "flow", "ts": 1, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "bytes": -1},
           {"type": "flow", "ts": 1, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "proto": "sctp"}]
    for ev in bad:
        assert eng.process(ev) == []
    assert eng.rejected == len(bad) and eng.errors
    with pytest.raises(EventError):
        eng.process({"type": "flow"}, strict=True)


def test_clean_normalizes_values():
    ev = clean({"type": "dhcp", "ts": "5", "mac": "AA-BB-CC-00-00-01", "ip": " 192.168.1.5 ", "action": "lease"})
    assert ev["mac"] == "aa:bb:cc:00:00:01" and ev["ip"] == "192.168.1.5" and ev["ts"] == 5.0


def test_fuzz_random_events_never_crash():
    rnd = random.Random(1)
    eng = Engine(demo_config())
    pool = [None, "", "x", 0, -1, 1e18, "aa:bb:cc:00:00:01", "192.168.50.20", "10.0.0.1", "a.b.c", True, [], {}]
    types = ["assoc", "dhcp", "flow", "dns", "arp", "dhcp_offer", "deauth", "junk"]
    keys = ["type", "ts", "mac", "src_mac", "dst_mac", "server_mac", "ip", "src_ip", "dst_ip", "dport", "proto",
            "bytes", "syns", "packets", "count", "action", "query", "hostname", "sni"]
    for _ in range(4000):
        ev = {k: rnd.choice(pool) for k in rnd.sample(keys, rnd.randint(0, 10))}
        ev["type"] = rnd.choice(types)
        if rnd.random() < .7:
            ev["ts"] = rnd.random() * 1000
        eng.process(ev)       # must not raise
    assert eng.store.verify()[0]


def test_hostile_strings_are_stored_as_data():
    eng = Engine(demo_config())
    evil = "'); DROP TABLE devices;--<script>alert(1)</script>"
    eng.process({"type": "assoc", "ts": 1, "mac": "aa:bb:cc:00:00:07", "action": "join"})
    eng.process({"type": "dhcp", "ts": 2, "mac": "aa:bb:cc:00:00:07", "ip": "192.168.50.7", "hostname": evil, "action": "lease"})
    eng.process({"type": "dns", "ts": 3, "src_ip": "192.168.50.7", "query": evil, "qtype": "A"})
    assert eng.store.rows("SELECT COUNT(*) n FROM devices")[0]["n"] >= 2
    assert eng.store.devices()[-1]["hostname"] == evil[:128]


def test_flow_aggregator_merges_packets():
    out = []
    agg = FlowAggregator(out.append)
    for _ in range(500):
        agg.add_event({"type": "flow", "ts": 1, "src_ip": "192.168.50.9", "dst_ip": "8.8.8.8", "dport": 443,
                       "proto": "tcp", "bytes": 100, "packets": 1, "syns": 0})
    agg.add_event({"type": "dns", "ts": 1, "src_ip": "192.168.50.9", "query": "x.example"})
    assert agg.flush() == 1
    assert out[0]["type"] == "dns" and out[1]["packets"] == 500 and out[1]["bytes"] == 50000


def test_semi_mode_approve_action_flow():
    eng = Engine(demo_config("semi"))
    for e in scenario():
        eng.process(e)
    pend = [a for a in eng.actions.values() if a["state"] == "pending_approval"]
    assert pend
    act = eng.approve_action(pend[0]["id"], 99)
    assert act["state"] == "dry_run" and eng.feed[-1]["k"] == "action"
    assert eng.approve_action(pend[0]["id"], 100) is None            # cannot approve twice
    assert eng.approve_action("ACT-9999", 100) is None


def test_monitor_mode_cannot_be_approved_into_action():
    eng = Engine(demo_config("monitor"))
    for e in scenario():
        eng.process(e)
    rec = [a for a in eng.actions.values() if a["state"] == "recommended"][0]
    assert eng.approve_action(rec["id"], 1) is None and rec["state"] == "recommended"


@pytest.fixture()
def server():
    rt = Runtime(mode="semi", speed=2000)
    srv = Server(("127.0.0.1", 0), make_handler(rt))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    rt.start()
    import time
    for _ in range(100):
        if rt.done:
            break
        time.sleep(0.1)
    yield rt, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_server_endpoints_and_csrf(server):
    rt, base = server
    meta = json.load(urllib.request.urlopen(base + "/api/meta"))
    assert meta["mode"] == "semi" and meta["live"] is False
    assert b"WiFi Guardian" in urllib.request.urlopen(base + "/").read()
    assert urllib.request.urlopen(base + "/api/connection-log.csv").read().startswith(b"join_ts")
    for bad in ("/../wifiguardian/engine.py", "/%2e%2e/wifiguardian/engine.py", "/nope.js"):
        try:
            urllib.request.urlopen(base + bad)
            assert False, bad
        except urllib.error.HTTPError as e:
            assert e.code == 404
    pend = [a for a in rt.engine.actions.values() if a["state"] == "pending_approval"][0]["id"]
    assert _post(base + "/api/approve-action", {"id": pend}) == 403                                   # no header
    assert _post(base + "/api/approve-action", {"id": pend}, {"X-WG-Request": "1", "Origin": "http://evil.example"}) == 403
    assert _post(base + "/api/approve-action", {"id": pend}, {"X-WG-Request": "1"}) == 200
    assert _post(base + "/api/approve-action", {"id": pend}, {"X-WG-Request": "1"}) == 409
    assert _post(base + "/api/approve-device", {"mac": "nonsense"}, {"X-WG-Request": "1"}) == 400
    assert _post(base + "/api/approve-device", {"mac": ATTACKER[0]}, {"X-WG-Request": "1"}) == 200
    assert rt.engine.devices[ATTACKER[0]]["status"] == "known"
    assert _post(base + "/api/unknown", {}, {"X-WG-Request": "1"}) == 404


def test_sse_stream_delivers_everything_then_ends(server):
    rt, base = server
    body = urllib.request.urlopen(base + "/api/stream", timeout=10).read().decode()
    assert body.count('"k": "alert"') == 13 and "event: end" in body


def test_feed_trimming_keeps_stream_consistent(monkeypatch):
    import wifiguardian.server as srv
    monkeypatch.setattr(srv, "FEED_LIMIT", 50)
    rt = Runtime(speed=1e9)
    for e in scenario():
        rt.push(e)
    items, pos = rt.snapshot(0)
    assert len(items) == 50 and pos == rt.base + 50 and rt.base > 0
    more, pos2 = rt.snapshot(pos)
    assert more == [] and pos2 == pos


def test_resuming_a_database_keeps_ids_unique_and_remembers_approvals(tmp_path):
    from wifiguardian.forensics import Forensics
    db = str(tmp_path / "wg.db")
    e1 = Engine(demo_config(), store=Forensics(db))
    for e in scenario():
        e1.process(e)
    e1.approve_device(ATTACKER[0], 1, name="lab kali")
    e1.finish()
    e2 = Engine(demo_config(), store=Forensics(db))
    assert e2.is_known(ATTACKER[0])                              # approval survived the restart
    assert e2.store.rows("SELECT COUNT(*) n FROM sessions WHERE leave_ts IS NULL")[0]["n"] == 0   # stale sessions closed
    for e in scenario():
        e2.process(e)
    e2.finish()
    ids = [r["id"] for r in e2.store.rows("SELECT id FROM alerts")]
    assert len(ids) == len(set(ids)) >= 24                       # second run did not overwrite the first
    assert e2.store.verify()[0]
