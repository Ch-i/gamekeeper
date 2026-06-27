"""MAC address → vendor, and MAC privacy/randomization detection.

The first three octets of a MAC are the OUI (Organizationally Unique Identifier),
registered to a manufacturer. We resolve it from nmap's bundled prefix table when
present (tens of thousands of entries), falling back to a small built-in subset so the
tool still labels common gear with no external files. See knowledge/STRATEGY.md.
"""
from __future__ import annotations

import re
from functools import lru_cache

from . import config

# A minimal fallback so vendor labels work even with no OUI file on the box.
_BUILTIN = {
    "001451": "Apple", "3C0754": "Apple", "F0989D": "Apple", "A4B197": "Apple",
    "FCFC48": "Apple", "DCA904": "Apple", "001A11": "Google", "F4F5E8": "Google",
    "3C5AB4": "Google", "44070B": "Amazon", "FCA183": "Amazon", "68037E": "Amazon",
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi (Trading)",
    "E45F01": "Raspberry Pi (Trading)", "D83ADD": "Raspberry Pi (Trading)",
    "3C71BF": "Espressif (ESP)", "240AC4": "Espressif (ESP)", "A4CF12": "Espressif (ESP)",
    "ECFABC": "Espressif (ESP)", "001599": "Samsung", "F008F1": "Samsung",
    "8CF5A3": "Samsung", "AC5F3E": "Samsung", "001132": "Synology",
    "0011D8": "Asustek", "2CFDA1": "Asustek", "001018": "Broadcom",
    "00E04C": "Realtek", "5C628B": "Realtek (Alfa AWUS)", "001A2B": "Ayecom/Alfa",
    "000C29": "VMware", "005056": "VMware", "0242AC": "Docker (bridge)",
    "B8273A": "TP-Link", "50C7BF": "TP-Link", "001D0F": "TP-Link",
    "0026BB": "Apple", "001E06": "WIBRAIN", "001565": "Ubiquiti", "F09FC2": "Ubiquiti",
    "FCECDA": "Ubiquiti", "0418D6": "Ubiquiti", "788A20": "Ubiquiti",
    "E063DA": "Ubiquiti", "002586": "Netgear", "A040A0": "Netgear",
}


@lru_cache(maxsize=1)
def _table() -> dict:
    table = dict(_BUILTIN)
    if config.OUI_FILE:
        try:
            with open(config.OUI_FILE, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    # nmap format:  "001451 Apple"   |  IEEE oui.txt: "00-14-51 (hex) Apple"
                    m = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line.strip())
                    if m:
                        table.setdefault(m.group(1).upper(), m.group(2).strip())
                        continue
                    m = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    if m:
                        table.setdefault((m.group(1) + m.group(2) + m.group(3)).upper(),
                                         m.group(4).strip())
        except OSError:
            pass
    return table


def _norm(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()


def is_randomized(mac: str) -> bool:
    """A locally-administered MAC (privacy/random) has bit 0x02 set in the first octet —
    most modern phones rotate these, which matters for stable device identity."""
    h = _norm(mac)
    if len(h) < 2:
        return False
    try:
        return bool(int(h[:2], 16) & 0x02)
    except ValueError:
        return False


def vendor(mac: str) -> str:
    h = _norm(mac)
    if len(h) < 6:
        return ""
    if is_randomized(mac):
        return "(randomized MAC)"
    return _table().get(h[:6], "")


def table_size() -> int:
    return len(_table())


@lru_cache(maxsize=512)
def vendor_online(mac: str) -> str:
    """Look the OUI up against an online MAC-vendor registry (richer/newer than the
    bundled table). Used on demand by `identify`, never in the hot scan path. Returns
    '' for randomized/private MACs or on any failure. Results are cached."""
    import json
    import urllib.request

    h = _norm(mac)
    if len(h) < 6 or is_randomized(mac):
        return ""
    # 1) maclookup.app (JSON: company, country)
    try:
        req = urllib.request.Request(f"https://api.maclookup.app/v2/macs/{h[:6]}",
                                     headers={"User-Agent": "gamekeeper"})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        if d.get("success") and d.get("company"):
            return d["company"].strip()
    except Exception:
        pass
    # 2) macvendors.com (plain text)
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{h[:6]}",
                                     headers={"User-Agent": "gamekeeper"})
        with urllib.request.urlopen(req, timeout=8) as r:
            txt = r.read().decode("utf-8", "replace").strip()
        if txt and "errors" not in txt.lower():
            return txt
    except Exception:
        pass
    return ""
