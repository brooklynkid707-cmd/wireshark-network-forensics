# Case notes — DNS tunnelling / exfiltration

**Capture:** `pcaps/dns_tunnel.pcap`
**ATT&CK:** T1071.004 Application Layer Protocol: DNS · T1048 Exfil Over Alternative Protocol · **Security+:** 2.4, 4.4
**Verdict:** True positive — data tunnelled over DNS TXT queries to an attacker-controlled domain.

---

## 1. Triage

DNS is supposed to be low-volume background noise, so a busy DNS view is itself
a flag. **Statistics > DNS** showed an unusual count of **TXT** queries — real
clients mostly ask for A/AAAA. I filtered:

```
dns.flags.response == 0 && dns.qry.type == 16
```

and saw a stream of grotesquely long query names, each different, all under
`t1.exfil-example.net`.

## 2. Confirmation

Three independent properties, all present here:

- **Length:** `frame.len > 250 && dns` — names run to the 253-byte limit with
  40-character labels. A real hostname is a dozen characters.
- **Entropy:** the subdomain is base32-looking gibberish. `netforensics` measures
  **4.70 bits/char** mean Shannon entropy (English host labels sit ~2.5–3.0);
  encoded/compressed data trends toward maximal entropy.
- **No repeats:** 60 queries → **60 unique subdomains**. Normal resolvers cache,
  so the same names recur. A tunnel never repeats because each query *is* a new
  chunk of outbound data.

```bash
# unique subdomains under the suspect parent:
tshark -r pcaps/dns_tunnel.pcap -Y 'dns.qry.name contains "exfil-example.net"' \
  -T fields -e dns.qry.name | sort -u | wc -l          # -> 60
# all TXT:
tshark -r pcaps/dns_tunnel.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.type \
  | sort | uniq -c                                       # -> 60 "16"
```

Example query (from the tool's output):
`zexxdmm2uu3symy5umdodevojixpsi3bxflhuzet.bke2gbshrc7e6j6mejyyp2723jxmpj.t1.exfil-example.net`

## 3. IOCs

| Type | Value |
|------|-------|
| Tunnel domain | `t1.exfil-example.net` (and parent `exfil-example.net`) |
| Internal client | `10.10.1.12` |
| External resolver | `198.51.100.53` |
| Signature | 60 unique TXT subdomains, 40-char labels, entropy 4.7, ~1.7 q/s |

## 4. Assessment & response

Data is leaving the network inside DNS, which egress firewalls usually permit
unconditionally. This is both C2 and exfiltration. Severity: **high**.

**Recommended response**
1. Sinkhole/block `exfil-example.net` at the resolver; force all clients through
   internal resolvers and block direct outbound 53 (the client used an external
   resolver — that alone should have been blocked).
2. Investigate `10.10.1.12` for the tunnelling process (iodine/dnscat2/custom).
3. Estimate data loss from query volume × payload-per-query.
4. Add detection: unique-subdomain rate per parent domain, long-label and
   high-entropy query alerts in the DNS logs/SIEM.
