# Windows — the manual operator workflow

You just got an alert. This is the by-hand path from *"something is off and I can't nail it
down"* to *"the threat is gone, the box is trustworthy again, and I can prove what happened."*

Every step here is something the automated toolkit does for you in
[WORKFLOW-WINDOWS.md](../../WORKFLOW-WINDOWS.md). Doing it manually once is how you learn to
read what the automation produces — and how to keep going when the automation can't.

## The order (follow it top to bottom)

| # | Step | The question it answers |
|---|------|-------------------------|
| [00](00-mindset-and-first-principles.md) | **Mindset & first principles** | How do I not destroy the evidence or tip off the attacker before I even start? |
| [01](01-triage-the-alert.md) | **Triage the alert** | Is this real, and how bad — do I even open an investigation? |
| [02](02-contain-without-destroying-evidence.md) | **Contain** | How do I stop the bleeding without erasing what I need to see? |
| [03](03-capture-volatile-memory.md) | **Capture volatile memory** | What evidence disappears the instant this box reboots? |
| [04](04-snapshot-live-system-state.md) | **Snapshot live state** | What is running, talking, and logged in *right now*? |
| [05](05-persistence-and-execution-history.md) | **Persistence & execution history** | How does it survive a reboot, and what has run on this box before? |
| [06](06-hunt-the-host.md) | **Hunt the host** | Where is the attacker hiding — injection, drivers, COM, pipes, RMM, files? |
| [07](07-adjudicate-findings.md) | **Adjudicate** | Which of my findings are real, and can I *prove* it? |
| [08](08-memory-forensics.md) | **Memory forensics** | What is in RAM that never touched disk — and which process is the implant? |
| [09](09-build-the-timeline-and-chain.md) | **Timeline & chain of events** | What actually happened, in what order, from patient zero to now? |
| [10](10-eradicate.md) | **Eradicate** | How do I remove all of it, reversibly, without missing a persistence tail? |
| [11](11-restore-and-recover.md) | **Restore & recover** | How do I return the box to known-good and make sure it stays clean? |
| [12](12-report-and-retrospective.md) | **Report & retrospective** | How do I write it down so the next responder — and the org — can trust it? |

## Two ways to walk this

- **Fast triage (a few hours):** 01 → 02 → 04 → 05 → 06 → 07. Live host, no memory image. Good
  enough to confirm/deny and scope a commodity infection.
- **Full forensic (serious/APT):** the whole chain, and **never skip 03 (memory)**. Sophisticated
  actors live in RAM. A disk-and-logs-only investigation cannot see fileless malware, injection,
  or live C2 — it is incomplete *by construction*.

## What you need on hand

- **Admin** on the target, and ideally a separate **analyst workstation** to analyze the memory
  image (never analyze on the possibly-compromised host).
- A **USB kit** or trusted share with: Sysinternals Suite, a memory acquisition tool
  (WinPmem / Magnet RAM Capture / FTK Imager), and — for depth — MemProcFS or Volatility 3,
  YARA, and the mwcp config parsers.
- A place to write evidence that is **not the compromised disk** (external drive / share). Assume
  the host's disk is untrustworthy and may be watched.

## The golden rule

**Collect first, judge second, act last.** Snapshot everything read-only, decide with evidence,
and only then change the box. Every irreversible action (kill, delete, reboot, re-image) waits
until the evidence is safely off the host.

➡️ Start: [00-mindset-and-first-principles.md](00-mindset-and-first-principles.md)
