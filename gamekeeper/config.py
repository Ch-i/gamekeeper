"""gamekeeper configuration — every value overridable via GAMEKEEPER_* env vars."""
from __future__ import annotations

import os
import shutil


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


_HERE = os.path.dirname(os.path.abspath(__file__))

# --- what counts as "my net" ---
# Physical/Wi-Fi interfaces to enumerate. Empty = auto (all non-virtual).
LAN_IFACES = [s.strip() for s in _env("GAMEKEEPER_LAN_IFACES", "").split(",") if s.strip()]
# Interfaces never treated as the LAN (containers, bridges, vpn, loopback).
VIRTUAL_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "vnet", "tailscale", "tun", "tap", "wg")

# --- monitor mode / WIDS (the AWUS) ---
MON_IFACE = _env("GAMEKEEPER_MON_IFACE", "")          # e.g. wlx5c628b75cf56
MON_CHANNELS = _env("GAMEKEEPER_MON_CHANNELS", "")    # "1,6,11" — empty = hop all

# --- watch cadence ---
WATCH_INTERVAL = int(_env("GAMEKEEPER_WATCH_INTERVAL", "300"))   # seconds between rescans

# --- web UI ---
WEB_BIND = _env("GAMEKEEPER_WEB_BIND", "127.0.0.1")   # loopback by default
WEB_PORT = int(_env("GAMEKEEPER_WEB_PORT", "8278"))

# --- state ---
DB_PATH = _env("GAMEKEEPER_DB", os.path.join(_HERE, "state", "gamekeeper.sqlite"))

# --- external tools (presence is feature-detected, never assumed) ---
NMAP_BIN = shutil.which("nmap")
TCPDUMP_BIN = shutil.which("tcpdump")
TSHARK_BIN = shutil.which("tshark")
AIRMON_BIN = shutil.which("airmon-ng")
IW_BIN = shutil.which("iw")

# nmap ships a large MAC-prefix table; prefer it for vendor lookup.
OUI_FILE = next(
    (p for p in ("/usr/share/nmap/nmap-mac-prefixes",
                 "/usr/share/ieee-data/oui.txt",
                 "/var/lib/ieee-data/oui.txt") if os.path.exists(p)),
    "",
)


def lan_ifaces(all_ifaces: list[str]) -> list[str]:
    """Resolve which interfaces to scan: the configured list, or every non-virtual one."""
    if LAN_IFACES:
        return [i for i in all_ifaces if i in LAN_IFACES]
    return [i for i in all_ifaces if not i.startswith(VIRTUAL_PREFIXES)]
