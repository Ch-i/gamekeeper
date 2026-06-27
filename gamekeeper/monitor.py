"""Wi-Fi WIDS over the AWUS in monitor mode — see the attacks a wired view can't.

The Layer-2 attacks that matter for home defence live in 802.11 *management* frames,
which only a monitor-mode interface sees:

- **deauth flood** — a burst of deauthentication frames forcing clients off (often the
  setup move for an evil twin). Signature: many deauth frames in a short window.
- **rogue / evil-twin AP** — a beacon advertising your SSID from a BSSID (or channel)
  you've never seen. Signature: known SSID, unknown BSSID.
- **ARP spoofing** — one MAC answering for many IPs / gratuitous ARP storms.

This module feature-detects its tools (`airmon-ng`/`iw` + `tshark`); when they're absent
it prints the exact, researched setup. Capture/dwell strategy in knowledge/STRATEGY.md.
"""
from __future__ import annotations

from . import config

SETUP = """  Monitor-mode setup for the AWUS (RTL8812AU):

    sudo apt install aircrack-ng tshark            # airmon-ng, iw, tshark
    sudo airmon-ng check kill                       # stop NetworkManager/wpa_supplicant
    sudo airmon-ng start {iface}                    # -> {iface}mon (or use: iw dev {iface} set type monitor)
    # dwell on your AP's channel, hop for discovery:
    sudo iw dev {iface}mon set channel 6

  Then:  sudo gamekeeper monitor --iface {iface}mon
  (Tip from the research: always 'check kill' first — stray processes flip the card back
   to managed mode and break channel control.)
"""


def _have_tools() -> dict:
    return {"airmon-ng": bool(config.AIRMON_BIN), "iw": bool(config.IW_BIN),
            "tshark": bool(config.TSHARK_BIN)}


def detect_deauth(iface: str, window=10, threshold=20, on_event=None) -> dict:
    """Count 802.11 deauth frames in a window via tshark. A spike ⇒ likely deauth attack.

    Requires tshark + a monitor-mode iface + privilege. Returns a summary dict.
    """
    import subprocess
    cmd = [config.TSHARK_BIN, "-i", iface, "-a", f"duration:{window}",
           "-Y", "wlan.fc.type_subtype == 0x0c", "-T", "fields", "-e", "wlan.sa"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=window + 10)
    except Exception as e:
        return {"error": str(e)}
    sources = [s for s in r.stdout.splitlines() if s.strip()]
    n = len(sources)
    hit = n >= threshold
    if hit and on_event:
        on_event("deauth_flood", count=n, window=window)
    return {"deauth_frames": n, "window_s": window, "attack_suspected": hit,
            "top_sources": _top(sources)}


def _top(items, k=5):
    from collections import Counter
    return Counter(items).most_common(k)


def cli(args) -> int:
    iface = args.iface or config.MON_IFACE or "wlan0"
    if getattr(args, "setup", False):
        print(SETUP.format(iface=iface))
        return 0
    tools = _have_tools()
    missing = [t for t, ok in tools.items() if not ok]
    if missing:
        print(f"  monitor mode needs: {', '.join(missing)} (not installed).")
        print(f"  AWUS detected as: {config.MON_IFACE or 'set GAMEKEEPER_MON_IFACE=wlx...'}")
        print("\n" + SETUP.format(iface=iface))
        return 1
    print(f"  WIDS on {iface} — watching for deauth floods (Ctrl-C to stop)…")
    try:
        while True:
            res = detect_deauth(iface, on_event=lambda k, **kw: print(f"  ⚠ {k}: {kw}"))
            print(f"  {res}")
    except KeyboardInterrupt:
        return 0
