import json
import os

from wifiguardian.__main__ import main
from wifiguardian.engine import Engine
from wifiguardian.forensics import Forensics
from wifiguardian.oui import is_randomized, norm_mac, vendor
from wifiguardian.simulator import ATTACKER, GUEST, KNOWN, demo_config, scenario


def engine():
    eng = Engine(demo_config())
    for e in scenario():
        eng.process(e)
    return eng


def test_connection_log_records_mac_ip_hostname_and_times():
    rows = {(r["mac"], r["join_ts"]): r for r in engine().store.connection_log()}
    kali = [r for r in rows.values() if r["mac"] == ATTACKER[0]][0]
    assert kali["ip"] == ATTACKER[1] and kali["hostname"] == "kali" and kali["leave_ts"] is None
    guest = [r for r in rows.values() if r["mac"] == GUEST[0]][0]
    assert guest["leave_ts"] is not None and guest["randomized"] == 1


def test_phone_has_two_sessions_after_deauth():
    sessions = engine().store.timeline(KNOWN[1][0])["sessions"]
    assert len(sessions) == 2 and sessions[0]["leave_ts"] and sessions[1]["leave_ts"] is None


def test_audit_chain_verifies_and_detects_tampering():
    eng = engine()
    ok, bad, n = eng.store.verify()
    assert ok and n > 20
    seq = eng.store.db.execute("SELECT seq FROM audit WHERE payload LIKE '%08:00:27:de:ad:99%' ORDER BY seq").fetchone()[0]
    eng.store.db.execute("UPDATE audit SET payload=replace(payload,'08:00:27:de:ad:99','00:00:00:00:00:00') WHERE seq=?", (seq,))
    ok, bad, _ = eng.store.verify()
    assert not ok and bad == seq


def test_deleted_row_breaks_chain():
    eng = engine()
    eng.store.db.execute("DELETE FROM audit WHERE seq=7")
    assert eng.store.verify()[0] is False


def test_export_case_manifest_hashes_match(tmp_path):
    import hashlib
    eng = engine()
    m = eng.store.export_case(str(tmp_path), ATTACKER[0])
    for name, digest in m["files"].items():
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == digest
    tl = json.loads((tmp_path / "timeline_080027dead99.json").read_text())
    assert tl["device"][0]["mac"] == ATTACKER[0] and tl["alerts"]


def test_dns_and_flow_history_per_device():
    tl = engine().store.timeline(KNOWN[3][0])   # the Pi
    assert any(".tunnel.example" in d["query"] for d in tl["dns"])
    assert any(f["dst_ip"] == "203.0.113.77" for f in tl["flows"])


def test_mac_helpers():
    assert norm_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert is_randomized("da:a1:19:5c:3e:77") and not is_randomized("08:00:27:de:ad:99")
    assert vendor("b8:27:eb:00:00:01") == "Raspberry Pi Foundation"
    try:
        norm_mac("not-a-mac")
        assert False
    except ValueError:
        pass


def test_cli_run_exit_code_and_persistent_db(tmp_path, capsys):
    db = str(tmp_path / "wg.db")
    assert main(["run", "--db", db]) == 1          # high-severity alerts present
    assert main(["verify", "--db", db]) == 0
    assert "audit chain OK" in capsys.readouterr().out
    assert os.path.getsize(db) > 0


def test_csv_export_neutralizes_formula_hostnames():
    from wifiguardian.config import build
    cfg = build({"allowlist": {}})
    eng = Engine(cfg)
    eng.process({"type": "assoc", "ts": 1, "mac": "aa:bb:cc:00:00:01", "action": "join"})
    eng.process({"type": "dhcp", "ts": 2, "mac": "aa:bb:cc:00:00:01", "ip": "192.168.50.9",
                 "hostname": "=HYPERLINK(\"http://x.example\")", "action": "lease"})
    assert "'=HYPERLINK" in eng.store.connection_log_csv()


def test_dnsmasq_lease_parser(tmp_path):
    from wifiguardian.capture import parse_dnsmasq_leases
    f = tmp_path / "leases"
    f.write_text("1791100800 aa:bb:cc:00:00:02 192.168.50.12 laptop 01:aa\n1791100900 aa:bb:cc:00:00:03 192.168.50.13 * *\n")
    ev = parse_dnsmasq_leases(str(f))
    assert [e["ip"] for e in ev] == ["192.168.50.12", "192.168.50.13"] and ev[1]["hostname"] is None
