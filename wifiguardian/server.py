"""Tiny stdlib web server: serves the dashboard and streams the engine feed as Server-Sent Events.

Sources: the built-in scenario (replayed in real time) or, experimentally, a real interface / dnsmasq lease file.
Bound to localhost by default. There is no login: do not expose it to an untrusted network.
POST endpoints (approvals) need a custom header and a same-origin request, so another web page
open in your browser cannot trigger them.
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import Engine
from .simulator import demo_config, scenario

ROOT = os.path.join(os.path.dirname(__file__), "dashboard")
TYPES = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".css": "text/css"}
FEED_LIMIT = 20000          # live mode keeps the newest items only; the database keeps everything
MAX_BODY = 4096


class Runtime:
    def __init__(self, mode="monitor", speed=8.0, db=":memory:", cfg=None, iface=None, leases=None):
        from .forensics import Forensics
        self.cfg = cfg or demo_config(mode)
        self.engine = Engine(self.cfg, store=Forensics(db))
        self.speed, self.iface, self.leases = speed, iface, leases
        self.lock = threading.Lock()
        self.done = False
        self.error = None
        self.base = 0                # number of feed items already trimmed away

    @property
    def live(self):
        return bool(self.iface or self.leases)

    def start(self):
        threading.Thread(target=self._guard, args=(self._live if self.live else self._run,), daemon=True).start()

    def _guard(self, fn):
        try:
            fn()
        except SystemExit as exc:            # e.g. scapy missing
            self.error = str(exc)
        except Exception as exc:             # keep the dashboard up and tell the user what broke
            self.error = f"{type(exc).__name__}: {exc}"
        if self.error:
            print(f"error: {self.error}", file=sys.stderr)
        if not self.live:
            self.done = True

    def push(self, ev):
        with self.lock:
            self.engine.process(ev)
            over = len(self.engine.feed) - FEED_LIMIT
            if over > 0:
                del self.engine.feed[:over]
                self.base += over

    def _live(self):
        """Experimental: real interface + dnsmasq leases. Join times come from the first lease seen."""
        from .capture import FlowAggregator, parse_dnsmasq_leases, sniff
        if self.iface:
            agg = FlowAggregator(self.push)
            threading.Thread(target=agg.run, daemon=True).start()
            threading.Thread(target=self._guard, args=(lambda: sniff(self.iface, agg.add_event),), daemon=True).start()
        seen = set()
        while True:
            if self.leases:
                try:
                    for ev in parse_dnsmasq_leases(self.leases):
                        key = (ev["mac"], ev["ip"])
                        if key not in seen:
                            seen.add(key)
                            now = time.time()
                            self.push({"type": "assoc", "ts": now, "mac": ev["mac"], "action": "join", "ip": ev["ip"]})
                            ev["ts"] = now
                            self.push(ev)
                except OSError as exc:
                    self.error = f"cannot read lease file: {exc}"
            time.sleep(5)

    def _run(self):
        events = scenario()
        last = events[0]["ts"]
        for ev in events:
            time.sleep(max(0.0, (ev["ts"] - last) / self.speed))
            last = ev["ts"]
            self.push(ev)

    def snapshot(self, start):
        """Items from absolute index `start` on; returns (items, new_start)."""
        with self.lock:
            lo = max(0, start - self.base)
            items = list(self.engine.feed[lo:])
            return items, self.base + lo + len(items)

    def _now(self):
        return time.time() if (self.live or not self.engine.feed) else self.engine.feed[-1]["t"]

    def approve_device(self, mac):
        with self.lock:
            self.engine.approve_device(mac, self._now())

    def approve_action(self, action_id):
        with self.lock:
            return self.engine.approve_action(action_id, self._now()) is not None


def make_handler(rt):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/meta":
                return self._send(200, json.dumps({"mode": rt.cfg["mode"], "ssid": rt.cfg["ssid"],
                                                   "gateway": rt.cfg["gateway"], "protected": rt.cfg["protected"],
                                                   "live": rt.live, "error": rt.error}))
            if path == "/api/stream":
                return self._stream()
            if path == "/api/connection-log.csv":
                with rt.lock:
                    return self._send(200, rt.engine.store.connection_log_csv(), "text/csv; charset=utf-8")
            name = "index.html" if path == "/" else os.path.normpath(path.lstrip("/"))
            full = os.path.realpath(os.path.join(ROOT, name))
            if not full.startswith(os.path.realpath(ROOT) + os.sep) or not os.path.isfile(full):
                return self._send(404, "not found", "text/plain")
            with open(full, "rb") as fh:
                self._send(200, fh.read(), TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))

        def _stream(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            pos, idle = 0, 0
            try:
                while True:
                    items, pos = rt.snapshot(pos)
                    for it in items:
                        self.wfile.write(f"data: {json.dumps(it)}\n\n".encode())
                    if items:
                        idle = 0
                    else:
                        idle += 1
                        self.wfile.write(b": keepalive\n\n")
                        if rt.done and idle > 2:
                            self.wfile.write(b"event: end\ndata: {}\n\n")
                            self.wfile.flush()
                            return
                    self.wfile.flush()
                    time.sleep(0.25)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        def do_POST(self):
            # CSRF guard: custom header (forces a CORS preflight we never answer) plus same-origin check
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin")
            if self.headers.get("X-WG-Request") != "1" or (origin and origin.split("://", 1)[-1] != host):
                return self._send(403, json.dumps({"error": "forbidden"}))
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n > MAX_BODY:
                    return self._send(413, json.dumps({"error": "body too large"}))
                body = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("body must be an object")
            except ValueError:
                return self._send(400, json.dumps({"error": "bad json"}))
            if self.path == "/api/approve-device" and isinstance(body.get("mac"), str):
                try:
                    rt.approve_device(body["mac"])
                except ValueError as exc:
                    return self._send(400, json.dumps({"error": str(exc)}))
                return self._send(200, json.dumps({"ok": True}))
            if self.path == "/api/approve-action" and isinstance(body.get("id"), str):
                ok = rt.approve_action(body["id"])
                return self._send(200 if ok else 409, json.dumps({"ok": ok}))
            self._send(404, json.dumps({"error": "unknown endpoint"}))

    return H


class Server(ThreadingHTTPServer):
    daemon_threads = True          # open dashboards must not block shutdown


def serve(host="127.0.0.1", port=8765, mode="monitor", speed=8.0, cfg=None, iface=None, leases=None, db=":memory:"):
    rt = Runtime(mode=mode, speed=speed, cfg=cfg, iface=iface, leases=leases, db=db)
    try:
        srv = Server((host, port), make_handler(rt))
    except OSError as exc:
        raise SystemExit(f"error: cannot listen on {host}:{port} ({exc.strerror or exc}). Try --port <other>.")
    rt.start()
    src = f"live on {iface or leases}" if rt.live else f"replay speed x{speed:g}"
    print(f"WiFi Guardian dashboard: http://{host}:{port}  (mode={rt.cfg['mode']}, {src})  Ctrl+C to stop")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: the dashboard has no login. Only expose it on a network you trust.", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        rt.engine.finish()
        srv.server_close()
