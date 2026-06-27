"""gamekeeper dashboard — a stdlib HTTP server + a JSON API over the store.

Loopback by default. One GET assembles the whole dashboard state; POSTs run a scan or
set a label. No build step, no framework — the page is a single self-contained file.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import config
from ..store import Store

_HERE = os.path.dirname(os.path.abspath(__file__))


def _state(store: Store) -> dict:
    return {
        "counts": store.counts(),
        "devices": store.devices(),
        "events": store.events(120),
        "probes": store.probes(120),
        "bans": store.bans(),
        "monitor": {"iface": config.MON_IFACE or "",
                    "tools": {"airmon-ng": bool(config.AIRMON_BIN), "iw": bool(config.IW_BIN),
                              "tshark": bool(config.TSHARK_BIN), "tcpdump": bool(config.TCPDUMP_BIN)}},
    }


class Handler(BaseHTTPRequestHandler):
    store: Store = None

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            with open(os.path.join(_HERE, "app.html"), "rb") as fh:
                return self._send(200, fh.read(), "text/html; charset=utf-8")
        if self.path == "/api/state":
            return self._send(200, json.dumps(_state(self.store), default=str))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            data = json.loads(self.rfile.read(n) or "{}")
        except json.JSONDecodeError:
            data = {}
        if self.path == "/api/scan":
            from ..cli import run_scan
            run_scan(self.store, active=bool(data.get("active")))
            return self._send(200, json.dumps(_state(self.store), default=str))
        if self.path == "/api/autolabel":
            from ..labeler import autolabel
            res = autolabel(self.store, relabel_all=bool(data.get("all")))
            st = _state(self.store)
            st["autolabel"] = res
            return self._send(200, json.dumps(st, default=str))
        if self.path == "/api/label":
            mac = (data.get("mac") or "").upper()
            if mac and self.store.device(mac):
                self.store.set_label(mac, label=data.get("label"), trust=data.get("trust"),
                                     notes=data.get("notes"))
                return self._send(200, json.dumps({"ok": True}))
            return self._send(400, json.dumps({"error": "unknown mac"}))
        return self._send(404, json.dumps({"error": "not found"}))


def run(host=None, port=None):
    host = host or config.WEB_BIND
    port = port or config.WEB_PORT
    Handler.store = Store()
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"gamekeeper dashboard · http://{host}:{port}  (Ctrl-C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
