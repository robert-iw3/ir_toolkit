# 11 · Restore & Recover

*The threat is gone. Now return the host to a known-good, fully-functional state — and make sure
it stays clean.*

---

## The situation

The box is still in the locked-down containment posture from step 02, with IR firewall rules and
disabled services. Recovery means handing a *trustworthy, working* machine back to the business —
not one that's either still crippled by your containment or quietly re-infectable. Move
deliberately; a rushed restore that leaves the entry vector open just restarts the incident.

---

## Step 1 — Confirm you're actually clean first

Don't restore connectivity to a box you haven't re-verified. Re-run the fast checks from steps
04–05 one more time:
- No malicious process running, no beacon to the (now-blocked) C2.
- No persistence recreated itself since eradication.
- No unexpected new accounts or logons.

If anything reappeared, **stop** — you missed a persistence tail. Back to step 05/06.

## Step 2 — Restore the firewall to known-good (minus the C2 blocks)

Return the pre-incident rules you exported in step 02, but **keep the confirmed-C2 outbound blocks
from step 10 in place**. Known-good rules back; known-bad still blocked.

```powershell
# Re-import the pre-incident firewall state you saved in step 02...
netsh advfirewall import "E:\IR-CASE\evidence\firewall_before.wfw"

# ...then re-apply the C2 blocks (import may have removed them). Verify both:
Get-NetFirewallRule -DisplayName "IR-Block-C2-*" | Select-Object DisplayName, Enabled, Action
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

Remove the temporary IR access rule (e.g. `IR-Allow-Admin-WinRM`) once you no longer need it.

## Step 3 — Close the entry vector (or it happens again)

Eradication removed the *implant*; recovery must remove the *way in*. From your timeline (step 09),
the initial access dictates the fix:

| Entry vector | The fix that actually prevents recurrence |
|---|---|
| Phishing → macro/LNK | Block the sender/attachment type; user awareness; disable Office macros from internet |
| Exploited public service | Patch it; take it off the internet until patched |
| Stolen/weak credentials | Enforce MFA; the rotation you did in step 10 |
| Malicious RMM install | Application control/allow-listing; remove the RMM |
| Vulnerable driver (BYOVD) | Add to the Microsoft vulnerable-driver blocklist / WDAC policy |

## Step 4 — Patch, harden, and re-enable protections

- Apply outstanding OS and application patches.
- Confirm Defender/EDR real-time protection is **on** and tamper protection restored (you undid the
  attacker's changes in step 10 — verify they took).
- Re-enable any logging/audit the attacker disabled, and consider turning on the auditing you
  *wished* you'd had (e.g. process-creation command-line logging, LSASS SACL).

## Step 5 — Decide: clean host, or rebuild?

Be honest, and write down the reasoning:
- **Return to service** if eradication was surgical, confidence is high, and there was no
  kernel/DA-level compromise.
- **Rebuild from known-good media** if there was rootkit/BYOVD, domain-admin/DC involvement, or you
  can't *prove* you found every foothold. Restore data from a backup taken **before** the
  compromise window (your step 09 timeline tells you when that was).

## Step 6 — Watch it for a while

Recovery isn't "done" the moment the box is back — it's done when it *stays* clean.
- Keep the C2 blocks and heightened monitoring for a defined window.
- Optionally leave an **egress watch** running to catch a dormant second-stage that beacons later
  (a "low and slow" implant may sleep for days).
- Re-check in 24–72 hours: any reconnect attempt, any recreated persistence, any of the rotated
  accounts used from an odd source.

---

## Where you are, and what's next

The host is healthy, hardened, monitored, and the door it came through is closed. One thing remains
— and it's the part that protects everyone *next* time: writing it all down so the evidence, the
decisions, and the lessons survive past your memory.

➡️ Next: [12-report-and-retrospective.md](12-report-and-retrospective.md)

*Toolkit parallel: **Phase 5 — Restore.** The automation restores the `.wfw` known-good rules while
preserving `IOCs.json` C2 blocks, verifies against a sha256 manifest, and its
`Eradication_rollback_*.jsonl` makes every change reversible.*
