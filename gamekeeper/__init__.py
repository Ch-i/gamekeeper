"""gamekeeper — know who's on your land, and keep it safe.

A modular network situational-awareness and defence tool for a network you own or are
authorised to monitor. Parts:

- **discover / fingerprint** — who's on the net, labelled (vendor, hostname, device type).
- **monitor** — Wi-Fi WIDS over an AWUS in monitor mode: deauth floods, evil-twin / rogue
  APs, ARP spoofing (the 802.11 management-frame attacks a wired view can't see).
- **sinkhole** — a Pi-hole-style DNS blocklist + a low-interaction honeypot that lures and
  logs probing bots.
- **defense** — turn probing/scanning behaviour into a (human-gated, self-lockout-safe)
  firewall ban.
- **report** — an LLM behaviour report per device; pairs with saddlerFitter's harness when
  present, else the local `claude` CLI.
- **web** — a clean dashboard tying it together.

Every capability feature-detects its tools and privileges, and writes are gated. Use it
only on networks you own or are explicitly authorised to monitor.
"""
__version__ = "0.1.0"
