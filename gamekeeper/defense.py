"""Bans — turn probing behaviour into a firewall block, safely.

A ban is a recommendation until a human applies it. `plan`/`add` generate an nftables
(or iptables) drop rule and record it; nothing touches the firewall unless you pass
`--apply` (which needs privilege). Two safety rails matter most:

- **Self-lockout protection.** We refuse to ban the default gateway, this host's own
  addresses, loopback, or any device you've labelled `trust=known`. Locking yourself out
  of your own network is the classic foot-gun.
- **Human-gated by default.** Auto-banning is opt-in; the dashboard surfaces ban
  *candidates* (repeat probers) for you to confirm.

See knowledge/STRATEGY.md.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone

from .store import Store

PROBE_BAN_THRESHOLD = 5   # distinct honeypot hits before a source is a ban candidate


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=15)
    except Exception as e:
        class _R: returncode = 1; stderr = str(e); stdout = ""
        return _R()


def protected_ips() -> set[str]:
    """Addresses we must never ban (gateway, self, loopback)."""
    ips = {"127.0.0.1", "::1", "0.0.0.0"}
    r = _run(["ip", "-j", "route", "show", "default"])
    try:
        for route in json.loads(r.stdout or "[]"):
            if route.get("gateway"):
                ips.add(route["gateway"])
    except (json.JSONDecodeError, AttributeError):
        pass
    r = _run(["ip", "-j", "-4", "addr", "show"])
    try:
        for a in json.loads(r.stdout or "[]"):
            for info in a.get("addr_info", []):
                if info.get("local"):
                    ips.add(info["local"])
    except (json.JSONDecodeError, AttributeError):
        pass
    return ips


def _rule(ip: str, table="nft") -> str:
    if table == "nft":
        return f"nft add rule inet filter input ip saddr {ip} drop"
    return f"iptables -I INPUT -s {ip} -j DROP"


def can_ban(store: Store, ip: str) -> tuple[bool, str]:
    if ip in protected_ips():
        return False, "protected address (gateway / self / loopback) — refusing"
    for d in store.devices():
        if d.get("ip") == ip and d.get("trust") == "known":
            return False, f"device is labelled trust=known ({d.get('label') or d['mac']}) — refusing"
    return True, ""


def ban(store: Store, ip: str, reason: str, apply: bool) -> dict:
    ok, why = can_ban(store, ip)
    if not ok:
        return {"status": "refused", "reason": why}
    has_nft = shutil.which("nft")
    rule = _rule(ip, "nft" if has_nft else "ipt")
    applied = False
    if apply:
        cmd = rule.split()
        if cmd and shutil.which(cmd[0]):
            res = _run(cmd)
            applied = res.returncode == 0
            if not applied:
                return {"status": "apply-failed", "rule": rule,
                        "error": (res.stderr or "needs root").strip()[:200]}
        else:
            return {"status": "no-firewall-tool", "rule": rule,
                    "hint": "install nftables or iptables, and run with privilege"}
    bid = store.add_ban(ip, None, reason, rule, applied, _now())
    store.add_event(None, ip, "ban", f"{'applied' if applied else 'planned'}: {reason}",
                    _now(), severity="bad")
    return {"status": "applied" if applied else "planned", "ban_id": bid, "rule": rule}


def candidates(store: Store) -> list[dict]:
    """Repeat probers worth banning, from the honeypot log (minus protected/known)."""
    out = []
    for ip, n in store.probe_counts().items():
        if n < PROBE_BAN_THRESHOLD:
            continue
        ok, why = can_ban(store, ip)
        out.append({"ip": ip, "probes": n, "bannable": ok, "note": why})
    return out


def cli(args) -> int:
    store = Store()
    if args.action == "list":
        cs = candidates(store)
        if cs:
            print("  ban candidates (repeat probers):")
            for c in cs:
                print(f"    {c['ip']:15} {c['probes']} probes  "
                      f"{'→ bannable' if c['bannable'] else '✗ '+c['note']}")
        for b in store.bans():
            print(f"  #{b['id']} {b['ip']:15} {'applied' if b['applied'] else 'planned'} — {b['reason']}")
        if not cs and not store.bans():
            print("  no bans or candidates.")
        return 0
    if not args.target:
        print("gamekeeper ban: need an IP", file=__import__("sys").stderr)
        return 1
    if args.action in ("add", "plan"):
        res = ban(store, args.target, args.reason, apply=args.apply and args.action == "add")
        print(f"  {res['status']}: {res.get('rule','')}")
        if res.get("reason"):
            print(f"  {res['reason']}")
        if res.get("hint"):
            print(f"  hint: {res['hint']}")
        return 0 if res["status"] in ("planned", "applied") else 1
    if args.action == "remove":
        print("  release: delete the matching firewall rule and mark released (apply by hand for now).")
        return 0
    return 1
