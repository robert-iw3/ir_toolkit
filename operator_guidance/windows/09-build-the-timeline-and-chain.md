# 09 · Build the Timeline & Chain of Events

*You have confirmed threats and indicators scattered across host, disk, network, and memory. Now
assemble them into one ordered story: patient zero → foothold → actions → now.*

---

## The situation

Individual findings don't tell you what happened — the **sequence** does. A timeline turns a bag
of IOCs into a narrative you can act on and defend: how they got in, what they touched, whether
they moved to other hosts, and what they took. This is also where you catch anything you missed
(a gap in the story means a finding you haven't found yet).

---

## Step 1 — Normalize everything to UTC

Different artifacts record time differently. Before you can order them, put them on one clock.

- Convert every timestamp to **UTC**, using the host clock offset you recorded in step 00.
- Note any **clock skew** (host time vs true time) — a skewed host makes events look like they
  happened at the wrong moment relative to other systems.
- Label each entry as **activity time** (when the thing happened) vs **detection time** (when a
  tool noticed) — they're often hours or days apart.

## Step 2 — Lay the events on one line

Pull the time-stamped facts you've gathered into a single chronological list:

| Source (step) | Contributes |
|---|---|
| Event logs (05) | Logons, process creation, service installs, task creation, log clears |
| Execution history (05) | First-run times from Prefetch/Amcache/ShimCache |
| File timestamps (06) | Created/modified of dropped files (watch for timestomping) |
| Memory (08) | Process create times, injected-region evidence, live C2 |
| Network (04, 08) | When beaconing started, exfil transfers |

```
2026-07-01T14:02Z  Phishing email opened                 (mail log)
2026-07-01T14:03Z  winword.exe → powershell -enc ...     (Event 4688 + decoded in memory)
2026-07-01T14:03Z  stage2.exe written to AppData\Roaming (file create + Amcache first-run)
2026-07-01T14:05Z  Beacon to 45.x.x.x:8443 begins        (memory netscan; CS config sleep=30s)
2026-07-01T14:20Z  New local admin "svc_help" created    (Event 4720/4732)
2026-07-01T18:40Z  AnyDesk installed                     (7045 + RMM triage)
2026-07-02T02:10Z  Security log cleared                  (Event 1102)  ← anti-forensics
```

## Step 3 — Draw the kill chain

Map the ordered events onto attacker phases. This exposes gaps: if you have execution but no
initial access, you're missing the entry vector — go back and look.

```
Initial Access → Execution → Persistence → Priv-Esc → Defense Evasion →
    Credential Access → Discovery → Lateral Movement → C2 → Exfiltration → Impact
```

Tag each confirmed finding with its ATT&CK technique (T1566 phishing, T1059 PowerShell, T1547
persistence, T1055 injection, T1003 cred access, T1071 C2…). A Mermaid graph — each TP finding a
node, ordered along the chain, C2 branching off — makes it readable for non-analysts.

## Step 4 — Enrich indicators with OSINT — *safely*

Now (not earlier) research your confirmed IOCs to understand the adversary and scope the campaign.
**Safely** is the operative word, because careless lookups tip off the attacker or leak the case.

**Do:**
- Look up **file hashes** (not the files) on VirusTotal / threat-intel — a hash reveals nothing
  to the attacker and tells you the family.
- Use **passive/offline** sources first: your staged offline GeoIP for IP→country (no DNS/whois
  that the adversary's infra could log), passive DNS, AlienVault OTX.
- For URLs/domains, prefer **urlscan.io / tria.ge / VT** *search* over live-visiting the C2.

**Don't:**
- ❌ **Upload the sample** to a public sandbox if it might be targeted/contain victim data — a
  public VT upload is world-readable and tells the actor their tool is burned.
- ❌ `nslookup`/`curl`/browse the **live C2** from a corporate IP — that's a beacon that says "we
  found you."
- ❌ Put internal identifiers (real IPs, usernames, hostnames) into third-party tools. Redact first.

## Step 5 — Decide scope: one host or a campaign?

Cross-reference your confirmed indicators against other hosts and your SIEM:
- Does the same hash / C2 IP / mutex / named pipe appear on other machines? → **campaign**, widen
  the investigation.
- Do the implicated **accounts** (step 07) appear in logons elsewhere? → lateral movement; those
  credentials are burned everywhere, not just here.

---

## Where you are, and what's next

You have the whole story: entry, actions, spread, and a confirmed list of what must be removed and
what must be blocked/rotated. Only now — evidence secured, story understood — do you start
*changing* the box.

➡️ Next: [10-eradicate.md](10-eradicate.md)

*Toolkit parallel: **Reporting** — `generate_reports.{py,ps1}` emits `Timeline.md` (activity vs
detection time, normalized via `_clock.json`), `Attack_Graph.md` (Mermaid kill chain), and
`correlate_campaign.py` for cross-host indicators. OSINT-safe enrichment is the analyst hand-off
(`WORKFLOW-INVESTIGATION-WINDOWS.md`).*
