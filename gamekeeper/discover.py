"""Who is on the net — passive-first device discovery.

Primary source is the kernel neighbour table (`ip neigh`: ARP for IPv4, NDP for IPv6),
which is privilege-free and already knows every host this machine has spoken to. We
enrich each with a reverse-DNS hostname and an OUI vendor. An optional active sweep
(`nmap -sn`) fills in hosts the box hasn't talked to yet; it is off by default because
active probing is louder. See knowledge/STRATEGY.md.
"""
from __future__ import annotations

import json
import socket
import subprocess

from . import config, oui

_DEAD = {"FAILED", "INCOMPLETE", "NOARP"}


def _run(args: list[str], timeout=20) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def interfaces() -> list[str]:
    out = _run(["ip", "-o", "link", "show"])
    names = []
    for line in out.splitlines():
        parts = line.split(": ", 2)
        if len(parts) >= 2:
            names.append(parts[1].split("@")[0])
    return names


def neighbours() -> list[dict]:
    """Parse `ip -j neigh` into {ip, mac, iface, state} for real, on-LAN neighbours."""
    raw = _run(["ip", "-j", "neigh", "show"])
    try:
        entries = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    keep_ifaces = set(config.lan_ifaces(interfaces()))
    out = []
    for e in entries:
        mac, ip, dev = e.get("lladdr"), e.get("dst"), e.get("dev")
        state = (e.get("state") or [""])[0] if isinstance(e.get("state"), list) else e.get("state", "")
        if not mac or not ip or dev not in keep_ifaces or state in _DEAD:
            continue
        out.append({"ip": ip, "mac": mac.upper(), "iface": dev, "state": state})
    return out


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def scan(active: bool = False) -> list[dict]:
    """Return the current device list: passive neighbour table + hostname + vendor.

    `active=True` adds an `nmap -sn` ping sweep of each LAN subnet first (needs nmap;
    louder but finds quiet hosts). Deduped by MAC, last writer wins on IP.
    """
    if active:
        _active_sweep()
    seen: dict[str, dict] = {}
    for n in neighbours():
        d = dict(n)
        d["vendor"] = oui.vendor(n["mac"])
        d["randomized"] = oui.is_randomized(n["mac"])
        d["hostname"] = reverse_dns(n["ip"])
        seen[n["mac"]] = d
    return list(seen.values())


def _active_sweep() -> None:
    """Best-effort: ping-sweep each LAN /24 so the neighbour table populates. Quiet on
    failure; never raises. Requires nmap."""
    if not config.NMAP_BIN:
        return
    for cidr in _lan_cidrs():
        _run([config.NMAP_BIN, "-sn", "-n", "--max-retries", "1", cidr], timeout=60)


def _lan_cidrs() -> list[str]:
    raw = _run(["ip", "-j", "-4", "addr", "show"])
    try:
        addrs = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    keep = set(config.lan_ifaces(interfaces()))
    cidrs = []
    for a in addrs:
        if a.get("ifname") not in keep:
            continue
        for info in a.get("addr_info", []):
            if info.get("family") == "inet" and not info.get("local", "").startswith("127."):
                net = info["local"].rsplit(".", 1)[0] + ".0"
                cidrs.append(f"{net}/{info.get('prefixlen', 24)}")
    return sorted(set(cidrs))
