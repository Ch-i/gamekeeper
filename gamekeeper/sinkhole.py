"""DNS sinkhole + low-interaction honeypot — lure and log probing bots.

**Honeypot.** Opens decoy services on a set of ports. When something connects, we send a
terse banner, record the probe (source, port, first bytes) to the store, and close. It
*never* executes or reflects what the client sends — it only observes. Repeat probers
become ban candidates (see defense.py). Runs unprivileged on high ports; well-known ports
(<1024) need privilege or a granted capability.

**Sinkhole.** A small DNS responder that answers blocklisted domains with 0.0.0.0 and
forwards everything else upstream — the Pi-hole pattern. Point your router's DHCP DNS at
this host to protect the whole LAN. Binding :53 needs privilege.

See knowledge/STRATEGY.md for why low-interaction (safe, low-noise) is the right default.
"""
from __future__ import annotations

import socket
import threading
from datetime import datetime, timezone

from . import config
from .store import Store

# decoy port -> service name (the services bots probe most). Deliberately EXCLUDES
# common real services on a host (22 ssh, 80 http, 443, 445 smb, 3389 rdp): the honeypot
# uses host networking, so binding those could shadow a real service. The bind also skips
# any port already in use, and refuses :22 outright (see NEVER_BIND).
DECOYS = {21: "ftp", 23: "telnet", 2323: "telnet", 2222: "ssh", 5555: "adb",
          1433: "mssql", 3306: "mysql", 6379: "redis", 9200: "elastic", 5900: "vnc",
          8080: "http", 8443: "https"}
# Ports we refuse to bind even if asked — shadowing these would be dangerous.
NEVER_BIND = {22}
BANNERS = {"ftp": b"220 (vsFTPd 3.0.3)\r\n", "telnet": b"\xff\xfb\x01login: ",
           "ssh": b"SSH-2.0-OpenSSH_8.9p1\r\n", "http": b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
           "redis": b"-NOAUTH Authentication required.\r\n", "mysql": b"\x4a\x00\x00\x00\x0a"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _handle(conn, addr, port, service, store):
    try:
        conn.settimeout(2.0)
        if BANNERS.get(service):
            try:
                conn.sendall(BANNERS[service])
            except OSError:
                pass
        try:
            data = conn.recv(256)
        except OSError:
            data = b""
        payload = data[:96].decode("latin1", "replace").strip() if data else "connect-only"
        store.add_probe(addr[0], None, port, "tcp", service, payload, _now())
        store.add_event(None, addr[0], "probe", f"honeypot hit :{port} ({service}) — {payload[:40]}",
                        _now(), severity="warn")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _listen(port, service, store, stop) -> str:
    if port in NEVER_BIND:
        return f"  :{port:<5} {service:8} — REFUSED (never shadow SSH)"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        s.listen(16)
        s.settimeout(1.0)
    except OSError as e:
        s.close()
        return f"  :{port:<5} {service:8} — skipped ({e.strerror or e})"

    def loop():
        while not stop.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle, args=(conn, addr, port, service, store), daemon=True).start()
        s.close()

    threading.Thread(target=loop, daemon=True).start()
    return f"  :{port:<5} {service:8} — listening"


def run_honeypot(ports=None, store=None, block=True):
    store = store or Store()
    ports = ports or list(DECOYS)
    stop = threading.Event()
    print("gamekeeper honeypot — decoy services (observe-only). Probes are logged.\n")
    for p in ports:
        print(_listen(p, DECOYS.get(p, "decoy"), store, stop))
    print("\n  Caught probes show in the dashboard and become ban candidates "
          "(`gamekeeper ban list`).")
    if not block:
        return stop
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        stop.set()
        print("\n  stopped.")


def cli(args) -> int:
    if getattr(args, "status", False):
        store = Store()
        print(f"  honeypot decoys available: {', '.join(str(p) for p in DECOYS)}")
        print(f"  probes logged so far: {store.counts()['probes']}")
        print(f"  DNS sinkhole: bind :53 (needs privilege); blocklist at knowledge/blocklist.txt")
        return 0
    ports = None
    if getattr(args, "ports", None):
        ports = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
    run_honeypot(ports=ports)
    return 0
