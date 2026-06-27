# gamekeeper — the researched, optimized approach to defensive sniffing

This is the *why* behind how gamekeeper identifies, watches, and protects. Everything
here is for a network **you own or are authorised to monitor**, for defence.

## 1. Labelling — identify by many weak signals, not one

No single signal is reliable, so gamekeeper votes across several (in rough order of
strength):

| signal | what it tells you | source |
|---|---|---|
| **OUI** (first 3 MAC octets) | manufacturer | IEEE registry / nmap prefix table (32k+) |
| **hostname** (DNS / mDNS / NetBIOS) | often the device's own name | reverse DNS, mDNS |
| **DHCP fingerprint** (option ordering, vendor class, parameter request list) | OS / device class | DHCP DISCOVER/REQUEST |
| **TTL** | OS family | any packet |
| **open ports / services** | role (printer 9100, camera 554, NAS 548…) | nmap |

A **locally-administered MAC** (bit `0x02` set in the first octet) is a *randomized
privacy address* — the default on modern iOS/Android. gamekeeper flags these, because they
rotate and can't be treated as a stable identity.

Sources: [DHCP fingerprinting](https://securew2.com/blog/dhcp-fingerprinting-explained) ·
[IoT fingerprinting survey](https://arxiv.org/pdf/2510.09700)

## 2. Protection — the Wi-Fi attacks only monitor mode can see

Layer-2 attacks live in 802.11 **management frames**; a wired/managed view is blind to
their opening moves. The AWUS in monitor mode is what makes them visible.

| attack | signature gamekeeper watches for |
|---|---|
| **deauth flood** | many `wlan.fc.type_subtype == 0x0c` frames in a short window (often the prelude to an evil twin forcing reconnects) |
| **evil twin / rogue AP** | a beacon advertising *your* SSID from a BSSID/channel you've never seen |
| **ARP spoofing** | one MAC answering for many IPs, or a gratuitous-ARP storm rebinding the gateway |

Sources: [Rogue-AP detection & evasion](https://arxiv.org/html/2512.10470v1) ·
[WIDS / management-frame monitoring](https://securedebug.com/mastering-wi-fi-hacking-techniques-and-defenses-an-ultra-extensive-guide-to-wireless-network-security/)

## 3. Optimized capture (the "every x")

From the aircrack-ng field guidance:

- **`airmon-ng check kill` first.** Stray processes (NetworkManager, wpa_supplicant) flip
  the card back to managed mode and steal channel control — the #1 reason monitor mode
  "doesn't work."
- **Dwell, then hop.** Channel-hopping gives a fast overview but you miss traffic mid-hop.
  Dwell on your AP's channel(s) for the attacks that target *you*; hop only to discover
  rogue APs elsewhere.
- **Always save a pcap** (`-w`) so anything flagged can be opened in Wireshark for a
  second look.
- **Passive by default.** gamekeeper's device scan reads the kernel neighbour table (zero
  packets sent); the active `nmap -sn` sweep is opt-in because it's louder.

Sources: [airodump-ng field guide](https://www.blackhillsinfosec.com/hunt-for-weak-spots-in-your-wireless-network-with-airodump-ng/) ·
[RTL8812AU monitor mode](https://github.com/aircrack-ng/rtl8812au)

## 4. Lure — low-interaction honeypot + DNS sinkhole

- **Honeypot, observe-only.** Decoy ports answer with a terse banner, log the prober, and
  close. It never executes or reflects client input — low interaction means low risk and
  low noise, and it cleanly separates "things that probe decoys" (no legitimate reason)
  from normal traffic. Repeat probers become ban candidates.
- **DNS sinkhole (Pi-hole pattern).** Answer blocklisted domains with `0.0.0.0`, forward
  the rest upstream. Point the router's DHCP DNS at this host to cover the whole LAN.

## 5. Respond — bans, gated and lockout-safe

A ban is a *recommendation* until a human applies it. Two rails: **never** ban the
gateway / this host / a `trust=known` device (self-lockout protection), and **apply only
on `--apply` with privilege**. The dashboard surfaces candidates; the human confirms.

This mirrors saddlerFitter's discipline — **reads open, writes gated, human in the loop.**
