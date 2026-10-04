import argparse
import json
import os
import sys

from . import __version__
from .config import load as load_config
from .engine import Engine
from .enforcement import nft_ruleset
from .forensics import Forensics, iso
from .rules import SEVERITY_ORDER
from .simulator import BASE_TS, demo_config, scenario


def _run_events(events, cfg, db):
    eng = Engine(cfg, store=Forensics(db))
    for ev in events:
        eng.process(ev)
    eng.finish()
    if eng.rejected:
        print(f"warning: {eng.rejected} invalid events skipped (first problem: {eng.errors[0]})", file=sys.stderr)
    return eng


def _events(args):
    if args.events:
        events = []
        with open(args.events, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    print(f"warning: line {n} is not valid JSON ({exc.msg}), skipped", file=sys.stderr)
        return events
    return scenario()


def _cfg(args):
    return load_config(args.config) if args.config else demo_config(args.mode)


def cmd_run(a):
    eng = _run_events(_events(a), _cfg(a), a.db)
    rows = sorted(eng.alerts.values(), key=lambda x: (x["ts"]))
    print(f"{'ID':8} {'TIME':8} {'SEV':9} {'RULE':16} {'SOURCE':20} SUMMARY")
    for x in rows:
        print(f"{x['id']:8} {x['ts']:<8.0f} {x['severity']:9} {x['rule']:16} {(x['src_ip'] or x['src_mac'] or '-'):20} {x['summary']}")
    states = {}
    for a in eng.actions.values():
        states[a["state"]] = states.get(a["state"], 0) + 1
    print("\nactions: " + ", ".join(f"{k} {v}" for k, v in sorted(states.items())))
    ok, bad, n = eng.store.verify()
    print(f"{len(rows)} alerts, {len(eng.devices)} devices, audit chain {'OK' if ok else 'BROKEN at ' + str(bad)} ({n} entries)")
    return 1 if any(SEVERITY_ORDER[x["severity"]] >= 3 for x in rows) else 0


def cmd_build_demo(a):
    from .simulator import demo_config as dc
    eng = _run_events(scenario(), dc("monitor"), ":memory:")
    ok, _, n = eng.store.verify()
    data = {"meta": {"ssid": eng.cfg["ssid"], "mode": "monitor", "gateway": eng.cfg["gateway"],
                     "protected": eng.cfg["protected"], "start": BASE_TS, "duration": max(e["t"] for e in eng.feed) - BASE_TS,
                     "audit": {"ok": ok, "entries": n, "head": eng.store._head}},
            "feed": eng.feed}
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("window.WG_DEMO = " + json.dumps(data, separators=(",", ":")) + ";\n")
    print(f"wrote {a.out}: {len(eng.feed)} feed items, {len(eng.alerts)} alerts")


def cmd_export(a):
    eng = _run_events(_events(a), _cfg(a), a.db)
    m = eng.store.export_case(a.out, a.mac)
    print(f"case written to {a.out}, chain head {m['chain_head'][:16]}...")
    for n, h in m["files"].items():
        print(f"  {h[:16]}  {n}")


def cmd_log(a):
    eng = _run_events(_events(a), _cfg(a), a.db)
    print(f"{'JOINED (UTC)':21} {'LEFT (UTC)':21} {'MAC':18} {'IP':15} {'HOSTNAME':16} {'STATUS':9} VENDOR")
    for r in eng.store.connection_log():
        left = iso(r["leave_ts"]) if r["leave_ts"] else "(still online)"
        print(f"{iso(r['join_ts']):21} {left:21} {r['mac']:18} {(r['ip'] or '-'):15} {(r['hostname'] or '-'):16} {r['status']:9} {r['vendor']}")


def cmd_verify(a):
    s = Forensics(a.db)
    ok, bad, n = s.verify()
    print("audit chain OK" if ok else f"audit chain BROKEN at seq {bad}", f"({n} entries)")
    return 0 if ok else 2


def cmd_serve(a):
    from .server import serve
    live = a.iface or a.leases
    if live and not a.config:
        raise SystemExit("live mode needs --config with your gateway ip/mac and allowlist")
    cfg = load_config(a.config) if a.config else None
    if cfg and a.mode != "monitor":
        cfg["mode"] = a.mode
    serve(a.host, a.port, a.mode, a.speed, cfg=cfg, iface=a.iface, leases=a.leases, db=a.db)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):       # Windows consoles: never crash on odd hostnames
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(prog="wifiguardian", description="WiFi monitoring, detection and forensic record")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, db=True):
        sp.add_argument("--config", help="JSON config (default: built-in demo lab)")
        sp.add_argument("--events", help="JSONL events file (default: built-in scenario)")
        sp.add_argument("--mode", choices=["monitor", "semi", "auto"], default="monitor")
        if db:
            sp.add_argument("--db", default=":memory:", help="SQLite file for the forensic record")

    sp = sub.add_parser("run", help="process events and print the alert table"); common(sp); sp.set_defaults(fn=cmd_run)
    sp = sub.add_parser("log", help="print the who-connected-when register"); common(sp); sp.set_defaults(fn=cmd_log)
    sp = sub.add_parser("export-case", help="write evidence files with SHA-256 manifest"); common(sp)
    sp.add_argument("--out", required=True); sp.add_argument("--mac"); sp.set_defaults(fn=cmd_export)
    sp = sub.add_parser("verify", help="check the audit hash chain of a database")
    sp.add_argument("--db", required=True); sp.set_defaults(fn=cmd_verify)
    sp = sub.add_parser("build-demo", help="regenerate dashboard/demo-data.js")
    sp.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "dashboard", "demo-data.js")); sp.set_defaults(fn=cmd_build_demo)
    sp = sub.add_parser("serve", help="serve the dashboard with a live replay")
    sp.add_argument("--host", default="127.0.0.1"); sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--mode", choices=["monitor", "semi", "auto"], default="monitor")
    sp.add_argument("--speed", type=float, default=8.0)
    sp.add_argument("--config", help="JSON config (required for live mode)")
    sp.add_argument("--iface", help="interface to sniff (live, experimental, needs scapy and root)")
    sp.add_argument("--leases", help="dnsmasq lease file to watch (live)")
    sp.add_argument("--db", default=":memory:", help="SQLite file for the forensic record")
    sp.set_defaults(fn=cmd_serve)
    sp = sub.add_parser("nft-ruleset", help="print the base nftables ruleset for the gateway")
    sp.set_defaults(fn=lambda a: print(nft_ruleset()))

    a = p.parse_args(argv)
    try:
        return a.fn(a) or 0
    except FileNotFoundError as exc:
        raise SystemExit(f"error: file not found: {exc.filename}")
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}")


if __name__ == "__main__":
    sys.exit(main())
