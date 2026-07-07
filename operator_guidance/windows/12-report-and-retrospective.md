# 12 · Report & Retrospective

*The technical work is done. This step is what makes it matter to anyone but you — and what makes
the organization harder to breach next time.*

---

## The situation

An investigation nobody can read, verify, or learn from is half an investigation. The report turns
your evidence and decisions into something management can act on, the next responder can trust, and
(if it comes to it) a court can accept. The retrospective turns this one incident into lasting
defensive improvement. Neither needs to be a novel — clear and complete beats long.

---

## Part A — The incident report

Write for **two audiences at once**: an executive who needs the "what happened and are we okay"
in a paragraph, and a technical peer who needs the evidence to verify your work. Lead with the
former; back it with the latter.

A solid report has these sections:

| Section | What goes in it |
|---|---|
| **Executive summary** | 3–5 sentences: what happened, impact, current status, what's needed. No jargon. |
| **Severity & scope** | How bad, how many hosts/accounts, data affected, still-active? |
| **Timeline** | Your step-09 chronology, UTC, activity-time vs detection-time. |
| **Attack narrative / kill chain** | The story mapped to ATT&CK — initial access → impact. |
| **True-positive findings** | Each confirmed threat with its evidence (the *proof*, not the claim). |
| **Adjudication funnel** | How many raw findings → how many confirmed. Shows rigor and that nothing was dropped blindly. |
| **Remediation actions** | Everything from steps 10–11, with the rollback journal. |
| **IOC appendix** | Hashes, C2 endpoints, accounts, techniques — machine-readable (`IOCs.json`). |
| **Recommendations** | The entry-vector fix + hardening (feeds Part B). |

> **Evidence, not assertion.** For every True Positive, show *why*: the signature status, the path,
> the parent process, the memory region, the C2 correlation. "It was malicious" is an opinion;
> "unsigned binary in AppData, injected into explorer.exe, beaconing to a confirmed CS server whose
> config sleep matched the observed 30s interval" is proof.

## Part B — Seal the evidence (chain of custody)

Make your evidence tamper-evident so it holds up later. Produce a manifest of every artifact with
its hash, who collected it, and when (UTC) — the hashes you took along the way (steps 00, 03, 10)
are the inputs.

```powershell
# Hash every artifact in the case into a manifest
Get-ChildItem E:\IR-CASE\evidence -Recurse -File |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv E:\IR-CASE\_manifest.csv -NoTypeInformation

# Record the seal: operator identity + timestamp; keep the manifest hash separate/signed
"$env:USERNAME sealed $(Get-Date -Format o) UTC" | Out-File E:\IR-CASE\_custody.txt
```

Store the sealed evidence per your retention policy. If there's any chance of legal action, don't
delete anything and follow legal's guidance on handling.

## Part C — The retrospective (the part that pays forward)

Once the fire is out, review the incident objectively — **blameless**, focused on systems and
gaps, not people. Ask:

- **Kill-chain coverage:** which stages did we detect, and which did we miss? (The attacker who
  beaconed for a week before you saw it exposes a detection gap.)
- **Dwell time:** how long from initial access to detection? To eradication? Those numbers are your
  program's report card.
- **What worked / what didn't:** which tool or log caught it? Which one *should* have and didn't?
- **Visibility gaps:** was there auditing you wished you'd had (command-line logging, LSASS SACL,
  egress monitoring)? Turn it on now.
- **Process gaps:** did containment take too long? Was the RoE unclear? Was memory captured in
  time?

Turn each answer into a concrete action with an owner: a new detection rule, a logging change, a
patch/hardening standard, a user-training item, a runbook fix.

## Part D — Close the loop: preventive controls so the vector can't recur

**This is the point of the whole exercise.** Detection (Part E) catches it *faster next time*;
prevention makes sure **there is no next time for this vector.** Eradication (step 10) removed the
implant and restore (step 11) closed the immediate hole — but the retrospective is where you turn
the *root cause* into a **durable, org-wide security control** so the same door can't be reopened
on this host or any other.

**Drive it from the root cause you established in your timeline (step 09).** The entry vector
dictates the control — and the control must be *preventive* (stops the technique), not just
*detective* (notices it):

| Root-cause vector | Preventive control that removes the vector | Scope it to |
|---|---|---|
| Phishing → macro/LNK/HTA | Block macros from the internet by policy; block risky attachment types at the gateway; ASR rules ("Office child process", "obfuscated scripts") | Whole tenant, not one mailbox |
| Stolen / sprayed / reused credentials | **MFA everywhere**, disable legacy auth, conditional access, password/lockout policy | All accounts, esp. admins |
| Exploited internet-facing service | Patch + remove from internet / put behind VPN or WAF; vuln-mgmt SLA | The service class, everywhere |
| Malicious RMM install | **Application allow-listing** (WDAC/AppLocker); block unsanctioned RMM at the proxy | Fleet-wide |
| Vulnerable driver (BYOVD) | Microsoft vulnerable-driver blocklist / WDAC policy | All hosts |
| Lateral movement over SMB/RDP | Network segmentation, host firewall east-west deny, LAPS, tiered admin, disable SMBv1 | The whole flat network |
| Excessive local admin / privilege | Least privilege, remove standing admin, just-in-time elevation | The role, org-wide |

**Make each preventive control a tracked deliverable — not a paragraph in a report:**
- Assign an **owner** and a **due date**; a control nobody owns never ships.
- Roll it out **fleet-wide, not just the victim host** — the attacker chose a *technique*, and every
  host with the same weakness is the next victim.
- **Verify it actually blocks the technique** — test that the macro is now blocked, the legacy-auth
  sign-in now fails, the RMM install is now denied. An untested control is a hope, not a control.
- Feed the gap back into **standards** (hardening baseline, golden image, onboarding checklist) so
  new systems are born with the control and the vector never re-enters the environment.

> **The feedback loop, in one line:** *incident → root-cause vector → preventive control →
> fleet-wide rollout → verified → baked into the baseline.* If your report ends at "we removed the
> malware," you've fixed a symptom and left the vector open. The organization only gets stronger
> when each incident permanently closes the door it came through.

## Part E — Feed it back into detection

Your confirmed IOCs and TTPs are also detection fuel (the *faster-next-time* half of the loop):
- Push hashes, C2 domains/IPs, and named-pipe/mutex patterns into the SIEM/EDR as **new detections**.
- If it was a campaign (step 09), sweep the whole estate for those indicators.
- Turn the *behavior* you saw (this beacon's timing, this persistence trick) into a detection so the
  next variant — new hash, same technique — still trips an alert even after the IOCs go stale.

Prevention and detection are complementary: prevention aims to make the vector impossible; detection
is your safety net for when a control is missing, bypassed, or brand-new. A mature program ships
**both** out of every incident.

---

## You've completed the loop

You took an alert you couldn't explain and walked it all the way through: triage → contain →
collect → adjudicate → memory → timeline → eradicate → restore → report. You did every step by
hand, so you now understand *why* each one exists and *what* the automation is doing on your
behalf.

That understanding is the whole point. Run the automated
[WORKFLOW-WINDOWS.md](../../WORKFLOW-WINDOWS.md) next and it will read like a set of old friends —
and when it produces something surprising, you'll know exactly how to check it by hand.

➡️ Other platforms (same spine, different evidence world): [../linux/](../linux/) ·
[../aws/](../aws/) · [../azure/](../azure/) · [../gcp/](../gcp/)

*Toolkit parallel: **Reporting** — `generate_reports.{py,ps1}` emits `Incident_Report.md`,
`Retrospective.md`, `Timeline.md`, `IOCs.json`, `Principals.json`, and the attack graph;
`evidence_custody.py --verify` seals/validates the manifest; `correlate_campaign.py` handles the
cross-host sweep. Optional `llm_incident_review.py` drafts an advisory review.*
