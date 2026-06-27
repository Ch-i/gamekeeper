"""gamekeeper CLI — scan, label, watch, serve, and the defence modules."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import config, fingerprint, discover
from .store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_scan(store: Store, *, active=False, on_event=None) -> list[dict]:
    """Discover → fingerprint → upsert → log timeline events. Returns the device list."""
    now = _now()
    devs = discover.scan(active=active)
    seen = []
    for d in devs:
        d["dtype"] = fingerprint.classify(d)["dtype"]
        outcome = store.upsert_device(d, now)
        seen.append(d["mac"])
        if outcome == "new":
            store.add_event(d["mac"], d["ip"], "new_device",
                            f"{d.get('vendor') or 'unknown vendor'} · {d.get('hostname') or d['ip']}",
                            now, severity="notice")
            if on_event:
                on_event("new_device", **d)
        elif outcome in ("returned", "ip_change"):
            store.add_event(d["mac"], d["ip"], outcome, d.get("hostname") or d["ip"], now)
    gone = store.mark_absent(seen, now)
    for m in gone:
        store.add_event(m, None, "departed", "no longer in the neighbour table", now)
    return store.devices()


def _resolve_mac(store: Store, ident: str) -> str | None:
    ident = ident.strip()
    if ":" in ident or "-" in ident and len(ident) >= 12:
        return ident.upper()
    for d in store.devices():            # allow lookup by IP or label
        if d["ip"] == ident or (d.get("label") or "").lower() == ident.lower():
            return d["mac"]
    return None


def _print_table(devs: list[dict]) -> None:
    if not devs:
        print("  no devices yet — run `gamekeeper scan` (try --active to ping-sweep).")
        return
    print(f"\n  {'STATUS':7} {'IP':15} {'MAC':18} {'TYPE':14} {'VENDOR':22} LABEL / HOST")
    for d in devs:
        dot = "● up" if d.get("present") else "○ away"
        label = d.get("label") or d.get("hostname") or ""
        rnd = " ~rnd" if d.get("randomized") else ""
        print(f"  {dot:7} {d.get('ip') or '':15} {(d.get('mac') or '')[:17]:18} "
              f"{(d.get('dtype') or '?'):14} {(d.get('vendor') or '')[:22]:22} {label}{rnd}")
    up = sum(1 for d in devs if d.get("present"))
    print(f"\n  {up} present · {len(devs)} known.  Label one:  gamekeeper label <ip> \"name\"")


def _scan(args) -> int:
    store = Store()
    devs = run_scan(store, active=args.active)
    if args.json:
        print(json.dumps(devs, indent=2, default=str))
    else:
        _print_table(devs)
    return 0


def _list(args) -> int:
    store = Store()
    devs = store.devices()
    if args.json:
        print(json.dumps(devs, indent=2, default=str))
    else:
        _print_table(devs)
    return 0


def _label(args) -> int:
    store = Store()
    mac = _resolve_mac(store, args.target)
    if not mac or not store.device(mac):
        print(f"gamekeeper: no device matches '{args.target}' (scan first?)", file=sys.stderr)
        return 1
    store.set_label(mac, label=args.name, trust=args.trust, notes=args.notes)
    d = store.device(mac)
    print(f"  labelled {d['ip']} ({mac}) → «{d.get('label')}»"
          + (f"  trust={d['trust']}" if args.trust else ""))
    return 0


def _watch(args) -> int:
    import time
    store = Store()
    interval = args.interval or config.WATCH_INTERVAL
    print(f"gamekeeper watch · every {interval}s · Ctrl-C to stop", file=sys.stderr)
    try:
        while True:
            def on_event(kind, **d):
                print(f"  ⚡ {kind}: {d.get('ip')} {d.get('vendor') or ''} {d.get('hostname') or ''}",
                      file=sys.stderr, flush=True)
            devs = run_scan(store, active=args.active, on_event=on_event)
            up = sum(1 for x in devs if x.get("present"))
            print(f"  [{_now()}] {up} present / {len(devs)} known", file=sys.stderr, flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


def _serve(args) -> int:
    from .web import server
    server.run(host=args.host, port=args.port)
    return 0


def _monitor(args) -> int:
    from . import monitor
    return monitor.cli(args)


def _honeypot(args) -> int:
    from . import sinkhole
    return sinkhole.cli(args)


def _ban(args) -> int:
    from . import defense
    return defense.cli(args)


def _report(args) -> int:
    from . import report
    return report.cli(args)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gamekeeper",
                                description="Know who's on your land, and keep it safe.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="discover + label devices on your net")
    s.add_argument("--active", action="store_true", help="also ping-sweep (nmap; louder)")
    s.add_argument("--json", action="store_true")

    ls = sub.add_parser("list", help="show known devices from the store")
    ls.add_argument("--json", action="store_true")

    lb = sub.add_parser("label", help="name a device and set its trust")
    lb.add_argument("target", help="IP, MAC, or existing label")
    lb.add_argument("name", nargs="?", default=None, help="human label")
    lb.add_argument("--trust", choices=["known", "guest", "unknown", "blocked"], default=None)
    lb.add_argument("--notes", default=None)

    w = sub.add_parser("watch", help="rescan on an interval; log arrivals/departures")
    w.add_argument("--interval", type=int, default=None, help="seconds (default %d)" % config.WATCH_INTERVAL)
    w.add_argument("--active", action="store_true")

    sv = sub.add_parser("serve", help="run the web dashboard")
    sv.add_argument("--port", type=int, default=None)
    sv.add_argument("--host", default=None,
                    help="bind address (default 127.0.0.1; use your Tailscale IP / 0.0.0.0 for remote access)")

    mo = sub.add_parser("monitor", help="AWUS Wi-Fi WIDS (deauth/evil-twin/ARP-spoof)")
    mo.add_argument("--iface", default=None, help="monitor-capable interface (the AWUS)")
    mo.add_argument("--setup", action="store_true", help="print the monitor-mode setup steps")

    hp = sub.add_parser("honeypot", help="DNS sinkhole + low-interaction honeypot for probing bots")
    hp.add_argument("--ports", default=None, help="comma list of decoy ports to listen on")
    hp.add_argument("--status", action="store_true")

    bn = sub.add_parser("ban", help="ban/unban a probing source (gated firewall rule)")
    bn.add_argument("action", choices=["add", "list", "remove", "plan"])
    bn.add_argument("target", nargs="?", help="IP to ban/unban")
    bn.add_argument("--reason", default="probing")
    bn.add_argument("--apply", action="store_true", help="actually apply the rule (needs privilege)")

    rp = sub.add_parser("report", help="LLM behaviour report for a device")
    rp.add_argument("target", help="IP, MAC, or label")
    rp.add_argument("--json", action="store_true")

    args = p.parse_args(argv)
    return {
        "scan": _scan, "list": _list, "label": _label, "watch": _watch, "serve": _serve,
        "monitor": _monitor, "honeypot": _honeypot, "ban": _ban, "report": _report,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
