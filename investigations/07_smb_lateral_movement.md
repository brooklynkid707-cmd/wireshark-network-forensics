# Case notes — SMB lateral movement

**Capture:** `pcaps/smb_lateral.pcap`
**ATT&CK:** T1021.002 Remote Services: SMB/Windows Admin Shares · T1570 Lateral Tool Transfer · **Security+:** 2.4, 4.1
**Verdict:** True positive — a workstation spraying SMB across the subnet and reaching ADMIN$ (PsExec-style).

---

## 1. Triage

Workstations talk SMB to a couple of file servers, repeatedly — not to *each
other*, and not to dozens of peers. **Statistics > Conversations > TCP**
filtered to port 445 showed one source, **10.10.1.11**, fanning out to a long
list of `10.10.1.x` workstation addresses in seconds. Isolated the new sessions:

```
tcp.dstport == 445 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

## 2. Confirmation

- **Fan-out:** 31 SYNs to **25 distinct hosts** inside the 60-second window —
  the breadth is the signature of automated spreading, not normal file access.
- **Authentication attempts:** `smb2.cmd == 1` (SESSION_SETUP) → 6 follow-ups
  where the spray "landed".
- **Admin-share access:** `smb2.cmd == 3` (TREE_CONNECT) reaching **`ADMIN$`** —
  the write-anywhere administrative share PsExec/wmiexec use to drop and launch a
  service. Workstation-to-workstation `ADMIN$` is never legitimate user activity.

```bash
# distinct targets from the source:
tshark -r pcaps/smb_lateral.pcap \
  -Y "ip.src==10.10.1.11 && tcp.dstport==445 && tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.dst | sort -u | wc -l           # -> 25
# admin-share tree connects:
tshark -r pcaps/smb_lateral.pcap -Y 'smb2.cmd==3' -T fields -e ip.dst -e smb2.tree
```

## 3. IOCs

| Type | Value |
|------|-------|
| Source (patient zero) | `10.10.1.11` |
| Targets | `10.10.1.20`–`10.10.1.44` (25 hosts) |
| Shares touched | `ADMIN$` |
| Signature | 25 SMB peers in 60 s, SESSION_SETUP + TREE_CONNECT to ADMIN$ |

## 4. Assessment & response

A single host authenticating to the admin share of 25 peers is hands-on-keyboard
lateral movement or a worm — the classic precursor to ransomware deployment.
Severity: **critical**.

**Recommended response**
1. Immediately isolate `10.10.1.11` (network quarantine) and the reached hosts.
2. Treat the credential used for the SMB sessions as compromised; disable and
   rotate it; check for a privileged/service account.
3. Hunt the 25 targets for newly created services, scheduled tasks and dropped
   binaries (the PsExec payload).
4. Harden: block workstation-to-workstation SMB (host firewall), restrict admin
   shares, enable SMB signing, deploy LAPS. Add detection for SMB fan-out and
   workstation-to-workstation `ADMIN$`/`C$` tree connects.
