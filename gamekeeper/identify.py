"""De-anonymise a device — actively map its open ports and OS with nmap.

An "unknown vendor" usually just means the MAC's OUI wasn't in the table. An active nmap
scan reveals open ports, service banners, and (with privilege) an OS guess — which sharpen
the device type and feed better LLM labels. Active scanning is louder than passive
discovery; use it only on your own network.
"""
from __future__ import annotations

import json
import subprocess
import xml.etree.ElementTree as ET

from . import config
from .fingerprint import classify
from .store import Store


def _nmap(ip: str, deep: bool) -> str:
    if not config.NMAP_BIN:
        return ""
    args = [config.NMAP_BIN, "-sV", "--version-light", "-T4", "--max-retries", "1", "-oX", "-", ip]
    if deep:  # OS detection — needs raw sockets / root (the container has them)
        args = [config.NMAP_BIN, "-sV", "-O", "-T4", "--max-retries", "1", "-oX", "-", ip]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=240)
        return r.stdout
    except Exception:
        return ""


def _parse(xml: str) -> tuple[list[dict], str]:
    ports, os_guess = [], ""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return ports, os_guess
    for p in root.iter("port"):
        st = p.find("state")
        if st is not None and st.get("state") == "open":
            svc = p.find("service")
            ports.append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                          "service": svc.get("name", "") if svc is not None else "",
                          "product": (svc.get("product", "") if svc is not None else "")})
    om = root.find(".//osmatch")
    if om is not None:
        os_guess = f"{om.get('name','')} ({om.get('accuracy','')}%)"
    return ports, os_guess


def identify(ip: str, store: Store | None = None, deep: bool = False) -> dict:
    store = store or Store()
    ports, os_guess = _parse(_nmap(ip, deep))
    dev = store.device_by_ip(ip)
    newtype = None
    if dev:
        store.set_ports(dev["mac"], json.dumps(ports), os_guess or None)
        cl = classify({**dev, "ports": [p["port"] for p in ports]})
        newtype = cl["dtype"]
        if newtype and newtype != "unknown":
            store.set_label(dev["mac"], dtype=newtype)
    return {"ip": ip, "mac": dev["mac"] if dev else None, "ports": ports,
            "os": os_guess, "dtype": newtype}


def cli(args) -> int:
    if not config.NMAP_BIN:
        print("  identify needs nmap (in the Docker image)")
        return 1
    store = Store()
    res = identify(args.target, store=store, deep=args.deep)
    print(f"\n  identify {args.target}" + (f"  ({res['mac']})" if res["mac"] else ""))
    if res["os"]:
        print("  OS guess:", res["os"])
    for p in res["ports"]:
        print(f"    {p['port']:>5}/{p['proto']:3} {p['service']:12} {p['product']}")
    if not res["ports"]:
        print("    no open ports found")
    print("  device type →", res.get("dtype") or "unchanged")
    return 0
