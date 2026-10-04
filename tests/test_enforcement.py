from wifiguardian.enforcement import Enforcer, nft_ruleset, undo_commands
from wifiguardian.engine import Engine
from wifiguardian.simulator import ATTACKER, GW_MAC, KNOWN, demo_config, scenario


def run(mode):
    eng = Engine(demo_config(mode))
    for e in scenario():
        eng.process(e)
    return eng


def test_monitor_mode_changes_nothing():
    eng = run("monitor")
    states = {a["state"] for a in eng.actions.values()}
    assert states <= {"recommended", "advice_only"}
    assert all(d["status"] != "quarantined" for d in eng.devices.values())


def test_semi_mode_waits_for_approval():
    assert any(a["state"] == "pending_approval" for a in run("semi").actions.values())


def test_auto_without_apply_is_dry_run_with_correct_commands():
    eng = run("auto")
    acts = [a for a in eng.actions.values() if a["kind"] == "quarantine_mac" and a["target"] == ATTACKER[0]]
    assert acts and all(a["state"] == "dry_run" for a in acts)
    assert acts[0]["commands"] == [f"nft add element inet wifiguardian quarantine_macs {{ {ATTACKER[0]} timeout 1h }}"]


def test_protected_devices_are_never_blocked():
    cfg = demo_config("auto")
    enf = Enforcer(cfg)
    alert = {"id": "WG-1", "ts": 1, "rule": "port_scan"}
    for mac in (GW_MAC, KNOWN[0][0]):          # gateway and admin laptop
        act = enf.decide(alert, mac, "192.168.50.20")
        assert act["state"] == "skipped_protected" and act["commands"] == []


def test_domain_targets_are_advice_not_nft_commands():
    eng = run("auto")
    dom = [a for a in eng.actions.values() if a["target"] == "c2-update.example"][0]
    assert dom["kind"] == "advise" and dom["commands"] == []


def test_undo_and_ruleset_text():
    assert undo_commands("quarantine_mac", "aa:bb:cc:dd:ee:ff") == [
        "nft delete element inet wifiguardian quarantine_macs { aa:bb:cc:dd:ee:ff }"]
    assert "quarantine_macs" in nft_ruleset() and "ct state invalid drop" in nft_ruleset()
