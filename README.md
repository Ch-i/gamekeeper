# gamekeeper

**Know who's on your land, and keep it safe.** A modular network situational-awareness and
defence tool: see and label every device on your network, catch probing bots, and watch
for the Wi-Fi attacks a normal view can't see — with a clean dashboard and a human in the
loop.

> **Authorised use only.** Use gamekeeper exclusively on a network you own or are explicitly
> authorised to monitor. Monitor-mode sniffing, honeypots, and bans are powerful; they're
> here for *your* defence.

It pairs with [saddlerFitter](https://github.com/Ch-i/saddlerFitter): gamekeeper watches the
network, saddlerFitter brings the consensus LLM harness — together, network defence + code
defence.

## The parts (modular — each feature-detects its tools)

| module | what it does | needs |
|---|---|---|
| **discover / fingerprint** | who's on the net, labelled — vendor (OUI), hostname, device type, randomized-MAC detection | nothing (stdlib + `ip neigh`); `nmap` for deep scan |
| **web** | a clean dashboard: device grid with inline labels + trust, activity feed, probes, bans | nothing |
| **monitor** | Wi-Fi WIDS over an AWUS in monitor mode — deauth floods, evil-twin / rogue APs, ARP spoofing | AWUS + `airmon-ng`/`iw` + `tshark` |
| **sinkhole** | a Pi-hole-style DNS blocklist + a low-interaction honeypot that lures and logs probing bots | nothing (high ports); privilege for `:53`/well-known |
| **defense** | turn repeat probers into a firewall ban — **gated** and **self-lockout-safe** | `nft`/`iptables` + privilege to apply |
| **report** | an LLM behaviour report per device — pairs with saddlerFitter, else the local `claude` CLI, else an evidence bundle | optional LLM |

Why it's built this way — fingerprint signals, WIDS signatures, the optimized capture
strategy, and the safety rails — is documented in
[`gamekeeper/knowledge/STRATEGY.md`](gamekeeper/knowledge/STRATEGY.md), grounded in
published research.

## Install

Python 3.10+. Core discovery + dashboard are **pure standard library** — no pip deps.

```bash
pip install -e .          # exposes the `gamekeeper` command
# or run from the tree:  python3 -m gamekeeper.cli ...
```

Optional tools unlock modules as you add them: `nmap` (deep scan), `aircrack-ng` + `tshark`
(Wi-Fi WIDS), `nftables` (bans).

## Quickstart

```bash
gamekeeper scan                       # who's on the net, labelled
gamekeeper scan --active              # + nmap ping-sweep (louder, finds quiet hosts)
gamekeeper label 192.168.1.42 "Jhoseph MacBook" --trust known
gamekeeper serve                      # the dashboard at http://127.0.0.1:8278
gamekeeper watch --interval 300       # every 5 min: log arrivals / departures / anomalies

gamekeeper honeypot                   # decoy services; logged probes become ban candidates
gamekeeper ban list                   # repeat probers (and existing bans)
gamekeeper ban plan 203.0.113.7       # generate a firewall rule (not applied)
gamekeeper monitor --setup            # the exact AWUS monitor-mode setup steps
gamekeeper report 192.168.1.42        # LLM behaviour report (pairs with saddlerFitter)
```

## Safety posture

- **Passive by default** — the device scan reads the kernel neighbour table and sends no
  packets; the active sweep is opt-in.
- **Writes are gated** — a ban is a recommendation until you apply it; gamekeeper refuses to
  ban the gateway, this host, or a `trust=known` device (self-lockout protection).
- **Honeypot is observe-only** — decoys log probers and never execute or reflect input.
- **Loopback by default** — the dashboard binds `127.0.0.1`.

## License

[MIT](./LICENSE).
