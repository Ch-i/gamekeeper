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


def _can_local() -> bool:
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    return bool(config.TSHARK_BIN or (config.TCPDUMP_BIN and root))


def _gamekeeper_container() -> str:
    import shutil
    if not shutil.which("docker"):
        return ""
    try:
        r = subprocess.run(["docker", "ps", "--filter", "ancestor=gamekeeper:latest",
                            "--format", "{{.Names}}"], capture_output=True, text=True, timeout=10)
        names = r.stdout.split()
        return names[0] if names else ""
    except Exception:
        return ""


def capture(iface=None, seconds=20, out=None, bpf="") -> dict:
    iface = iface or _default_iface()
    out = out or f"/tmp/gamekeeper-{iface}-{_tag()}.pcap"
    summary, err = "", ""
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    # 1) capture in-process if we're privileged. tcpdump writes as root without dropping
    #    privilege (tshark/dumpcap drop to a restricted user and fail on bind-mounted dirs),
    #    so prefer tcpdump for the write and use tshark only to summarise the saved file.
    if root and (config.TCPDUMP_BIN or config.TSHARK_BIN):
        if config.TCPDUMP_BIN:
            cmd = ["timeout", str(seconds), config.TCPDUMP_BIN, "-i", iface, "-w", out, "-n"]
            if bpf:
                cmd += bpf.split()
        else:
            cmd = [config.TSHARK_BIN, "-i", iface, "-a", f"duration:{seconds}", "-w", out]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 25)
            err = r.stderr.strip()[:200]
        except Exception as e:
            err = str(e)
        if config.TSHARK_BIN and os.path.exists(out):
            summary = summary_of(out)
    else:
        # 2) bridge into the running gamekeeper container (has tshark + NET_RAW); it writes
        #    to the shared /data volume, which is this host's gamekeeper/state dir.
        cont = _gamekeeper_container()
        if not cont:
            return {"iface": iface, "ok": False,
                    "error": "no local tshark/privilege and no gamekeeper container running"}
        cname = os.path.basename(out)
        # tcpdump writes as root (no privilege-drop); then tshark -r summarises the saved file.
        inner = (f"mkdir -p /data/captures && timeout {seconds} tcpdump -i {iface or 'any'} "
                 f"-w /data/captures/{cname} -n 2>/dev/null; "
                 f"tshark -r /data/captures/{cname} -q -z io,phs 2>/dev/null")
        try:
            r = subprocess.run(["docker", "exec", cont, "sh", "-c", inner],
                               capture_output=True, text=True, timeout=seconds + 40)
            summary = r.stdout
            err = r.stderr.strip()[:200]
        except Exception as e:
            err = str(e)
    ok = os.path.exists(out) and os.path.getsize(out) > 0
    return {"iface": iface, "pcap": out if ok else None, "ok": ok, "summary": summary,
            "open_with": f"wireshark {out}" if ok else "",
            "error": "" if ok else (err or "no packets")}


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


def summary_of(pcap: str) -> str:
    """Protocol hierarchy of a saved pcap (reads the file, no second capture)."""
    if not config.TSHARK_BIN or not os.path.exists(pcap):
        return ""
    try:
        r = subprocess.run([config.TSHARK_BIN, "-r", pcap, "-q", "-z", "io,phs"],
                           capture_output=True, text=True, timeout=30)
        return r.stdout or ""
    except Exception:
        return ""


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
