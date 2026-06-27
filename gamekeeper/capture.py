"""Packet capture — the Wireshark side.

Writes a `.pcap` you can open directly in Wireshark, and prints a quick protocol
breakdown. Uses tshark when present (full dissection), else tcpdump. Capturing needs raw
sockets — run it inside the Docker image (which has the tools + `NET_RAW`) or with
privilege on the host.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone

from . import config, discover


def _tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_iface() -> str:
    lan = config.lan_ifaces(discover.interfaces())
    return lan[0] if lan else "any"


def capture(iface=None, seconds=20, out=None, bpf="") -> dict:
    iface = iface or _default_iface()
    out = out or f"/tmp/gamekeeper-{iface}-{_tag()}.pcap"
    if config.TSHARK_BIN:
        cmd = [config.TSHARK_BIN, "-i", iface, "-a", f"duration:{seconds}", "-w", out]
    elif config.TCPDUMP_BIN:
        cmd = [config.TCPDUMP_BIN, "-i", iface, "-w", out, "-G", str(seconds), "-W", "1"]
    else:
        return {"error": "need tshark or tcpdump (use the Docker image)"}
    if bpf:
        cmd.append(bpf)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 20)
    except Exception as e:
        return {"error": str(e)}
    ok = os.path.exists(out) and os.path.getsize(out) > 0
    return {"iface": iface, "pcap": out if ok else None, "ok": ok,
            "open_with": f"wireshark {out}" if ok else "",
            "error": "" if ok else (r.stderr.strip()[:200] or "no packets / needs privilege")}


def summary(iface=None, seconds=15) -> dict:
    iface = iface or _default_iface()
    if not config.TSHARK_BIN:
        return {"note": "protocol summary needs tshark (bundled in the Docker image)"}
    try:
        r = subprocess.run([config.TSHARK_BIN, "-i", iface, "-a", f"duration:{seconds}",
                            "-q", "-z", "io,phs"], capture_output=True, text=True, timeout=seconds + 20)
        return {"iface": iface, "protocol_hierarchy": r.stdout or r.stderr[:300]}
    except Exception as e:
        return {"error": str(e)}


def cli(args) -> int:
    iface = args.iface
    if getattr(args, "summary", False):
        res = summary(iface, seconds=args.seconds)
        print(res.get("protocol_hierarchy") or res.get("note") or res.get("error"))
        return 0
    res = capture(iface, seconds=args.seconds, out=args.out, bpf=args.bpf or "")
    if res.get("ok"):
        print(f"  captured {res['iface']} for {args.seconds}s → {res['pcap']}")
        print(f"  open it:  {res['open_with']}")
    else:
        print(f"  capture failed on {res.get('iface')}: {res.get('error')}")
        return 1
    return 0
