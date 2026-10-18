# Case notes — ARP cache poisoning / MITM

**Capture:** `pcaps/arp_spoof.pcap`
**ATT&CK:** T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning · **Security+:** 2.4, 4.1
**Verdict:** True positive — active ARP poisoning intercepting the victim's gateway traffic.

---

## 1. Triage

Layer-2 problems hide until you look at ARP, so I filtered `arp` straight away.
Wireshark had already painted several packets with its yellow expert note:
**"duplicate IP address configured (10.10.0.1)"**. That note alone is often the
whole case — one IP must map to one MAC on a LAN.

## 2. Confirmation

Filtered to replies and listed the IP→MAC bindings:

```
arp.opcode == 2
```
```bash
tshark -r pcaps/arp_spoof.pcap -Y "arp.opcode==2" \
  -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u
```

The gateway IP **10.10.0.1** is claimed by two MACs:

| MAC | Replies | Interpretation |
|-----|--------:|----------------|
| `00:1c:73:aa:00:01` | 13 | the real gateway |
| `de:ad:be:ef:00:66` | 25 | the **attacker**, answering more often to win the cache |

- **Unsolicited replies:** `arp.opcode == 2 && eth.src == de:ad:be:ef:00:66`
  → 45 "is-at" replies with no preceding "who-has" within 2 s. Legitimate ARP is
  request/response; a stream of unsolicited replies is a poisoner keeping the
  victim's cache overwritten.
- The attacker also impersonates the **victim** (`10.10.1.11`) to the gateway —
  it claims both ends, which is the full bidirectional MITM.
- **Follow the stolen traffic:** the victim's HTTP to `www.example.com` now has
  destination MAC = the attacker's, then reappears relayed toward the real
  gateway. The attacker is forwarding (so the victim notices nothing) while
  reading everything in between.

## 3. IOCs

| Type | Value |
|------|-------|
| Attacker MAC | `de:ad:be:ef:00:66` |
| Spoofed IPs | `10.10.0.1` (gateway), `10.10.1.11` (victim) |
| Victim | `10.10.1.11` |
| Signature | 1 IP → 2 MACs; 45 unsolicited `is-at`; relayed frames with attacker MAC |

## 4. Assessment & response

A MITM on the gateway path exposes every cleartext credential and session the
victim sends (see case 04 — this is exactly how an attacker harvests HTTP Basic
auth they could not otherwise see). Severity: **critical**.

**Recommended response**
1. Find the switch port behind `de:ad:be:ef:00:66` (MAC address table) and
   disable it; physically locate and remove the device.
2. Treat all of the victim's credentials and sessions during the window as
   compromised — force rotation.
3. Enable **Dynamic ARP Inspection** + **DHCP snooping** on access switches; pin
   the gateway with a static ARP entry on critical hosts.
4. Add a monitoring rule for "IP with >1 MAC" and unsolicited-reply floods.
