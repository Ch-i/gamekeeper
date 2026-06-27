"""Device-type classification — turn raw (mac, vendor, hostname, ports) into a label.

Multi-signal, in the order the research found most reliable: OUI vendor, then hostname
hints (DNS/mDNS/NetBIOS names leak a lot), then open ports / services. No single signal
decides; they vote. The heuristics live here so they're easy to read and extend; a
fuller signature set can be layered from knowledge/fingerprints.yaml. See
knowledge/STRATEGY.md.
"""
from __future__ import annotations

import re

# vendor substring -> (type, hint)
_VENDOR = [
    (r"apple", "apple-device"), (r"raspberry pi", "sbc"), (r"espressif|esp", "iot"),
    (r"ubiquiti|tp-link|netgear|asus|d-link|zyxel|mikrotik|cisco|aruba", "network-gear"),
    (r"samsung|xiaomi|huawei|oneplus|google", "mobile-or-iot"),
    (r"amazon", "voice-assistant"), (r"sonos|roku|lg electronics|vizio", "media"),
    (r"synology|qnap|western digital|seagate", "nas"),
    (r"hewlett|hp inc|canon|epson|brother|lexmark", "printer"),
    (r"hikvision|dahua|axis|reolink|wyze|amcrest", "camera"),
    (r"philips|signify|tuya|sonoff|shelly|nest|ecobee", "smart-home"),
    (r"intel|realtek|broadcom|dell|lenovo|microsoft|vmware", "computer"),
]
# hostname regex -> type (stronger than vendor when present)
_HOST = [
    (r"iphone|ipad|-ios|androidphone|pixel|galaxy", "phone"),
    (r"macbook|imac|-mbp|laptop|thinkpad|desktop|-pc\b|win(dows)?-", "computer"),
    (r"appletv|firetv|chromecast|roku|shield|-tv\b|bravia", "media"),
    (r"echo|alexa|google-?home|nest-?(mini|hub|audio)|homepod", "voice-assistant"),
    (r"printer|hpprint|epson|canon|officejet|laserjet", "printer"),
    (r"cam(era)?|ipcam|doorbell|ring-|nestcam", "camera"),
    (r"nas|synology|diskstation|qnap|truenas|freenas", "nas"),
    (r"router|gateway|-ap\b|unifi|openwrt|dd-wrt|fritz", "network-gear"),
    (r"raspberrypi|rpi-|esp-|esp32|esp8266|tasmota|shelly|sonoff", "iot"),
    (r"hue|lifx|smartthings|tuya|thermostat|ecobee", "smart-home"),
]
# open port -> type vote
_PORT = {
    9100: "printer", 631: "printer", 515: "printer",
    554: "camera", 8554: "camera", 37777: "camera",
    548: "nas", 445: "computer-or-nas", 139: "computer-or-nas", 5000: "nas",
    53: "network-gear", 67: "network-gear", 1900: "media",
    22: "server", 8123: "smart-home", 1883: "iot", 8883: "iot",
}


def _vendor_type(vendor: str) -> str:
    v = (vendor or "").lower()
    for pat, t in _VENDOR:
        if re.search(pat, v):
            return t
    return ""


def _host_type(hostname: str) -> str:
    h = (hostname or "").lower()
    for pat, t in _HOST:
        if re.search(pat, h):
            return t
    return ""


def classify(dev: dict) -> dict:
    """Return {dtype, confidence, reasons[]} for a device dict (mac/vendor/hostname/ports)."""
    reasons, votes = [], {}

    def vote(t, weight, why):
        if not t:
            return
        votes[t] = votes.get(t, 0) + weight
        reasons.append(why)

    vt = _vendor_type(dev.get("vendor", ""))
    vote(vt, 1, f"vendor «{dev.get('vendor')}» → {vt}" if vt else "")
    ht = _host_type(dev.get("hostname", ""))
    vote(ht, 2, f"hostname «{dev.get('hostname')}» → {ht}" if ht else "")
    for p in dev.get("ports", []) or []:
        pt = _PORT.get(p)
        vote(pt, 2, f"port {p} → {pt}" if pt else "")

    if dev.get("randomized"):
        reasons.append("randomized MAC (likely a phone with privacy address)")
        votes["phone"] = votes.get("phone", 0) + 1

    if not votes:
        return {"dtype": "unknown", "confidence": 0.0, "reasons": ["no distinguishing signal yet"]}
    best = max(votes, key=votes.get)
    total = sum(votes.values())
    return {"dtype": best, "confidence": round(votes[best] / total, 2),
            "reasons": [r for r in reasons if r]}
