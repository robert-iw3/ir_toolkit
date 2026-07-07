# 00 · Mindset & First Principles

*Read this once before you touch anything. It is the difference between an investigation and
an accident.*

---

## The situation

You are about to work on a machine that **may be watched by the person who compromised it.**
Everything you do — every command, every file you drop, every reboot — is a decision that can
either preserve evidence or destroy it, and either stay quiet or announce "the defenders are
here." Slow down for ten minutes now.

---

## Five principles that never change

### 1. Order of volatility — capture what vanishes first, first

Evidence has a shelf life. This is the order it dies in:

```
RAM (gone at reboot) ▶ network connections & running processes ▶ temp files & caches ▶
    disk files ▶ event logs (attacker can wipe) ▶ backups/archives
```

**Memory is the top of the ladder and it is a one-shot.** Reboot or power-off and it is gone
*forever* — along with any fileless malware, injected code, live C2 socket, and cleartext
credential that only ever lived in RAM. If the incident is serious, memory comes before almost
everything else (step 03).

### 2. Collect first, judge second, act last

The single most common rookie mistake is *reacting* — killing the suspicious process, deleting
the file, rebooting "to be safe." Each of those destroys evidence and may trip a dead-man's
switch. **Snapshot read-only, get the evidence off the box, decide with proof, then act.**

### 3. Don't tip off the adversary

A present attacker who sees you investigating may wipe logs, detonate ransomware, or burn their
access and vanish (taking the evidence trail with them). Until you have contained and collected:
- Don't block their C2 outright (you lose *where* they call home — see step 02).
- Don't rename/delete their tools one at a time.
- Prefer read-only observation. Loud, irreversible moves come *after* collection.

### 4. Every verdict is earned, not felt

You will find dozens of "suspicious" things. Suspicion is a starting point, not a conclusion.
Walk each finding up the ladder with evidence:

```
False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive
```

- **A valid signature does not clear a file** if it runs from `AppData\Roaming` or `Temp` — that
  earns **Indeterminate**, not clearance.
- **Unsigned does not convict** a file — plenty of legit software is unsigned. A *bad* signature
  (revoked/tampered) is the strong signal, not merely-absent.
- **Weak signals stay weak alone.** High file entropy, or a binary in ShimCache that no longer
  exists, are *pivot leads* — elevate them only when something else corroborates.

> **Suppress only what is physically impossible to be a threat. Never blindside an
> investigation to reduce noise.** Everything else surfaces *with context* and the analyst calls
> it.

### 5. Chain of custody — if you can't prove it, it didn't happen

Evidence you might act on (or testify to) must be **hashed, dated, and attributed.** For every
artifact you pull:
- Record **who** collected it, **when** (in **UTC**), and from **which host**.
- Hash it immediately and keep the hash separate from the file.
- Work on **copies**; never analyze the only original.

```powershell
# Hash any artifact the moment you collect it
Get-FileHash -Algorithm SHA256 .\evidence\memory_HOST.raw | Tee-Object .\evidence\memory_HOST.sha256
```

---

## Set up your workspace before you start

```powershell
# On the ANALYST side or an external drive — never the suspect's own disk as primary
$Case = "IR-$(Get-Date -Format yyyyMMdd)-HOSTNAME"
New-Item -ItemType Directory "E:\$Case\evidence","E:\$Case\notes" -Force

# Note your clock offset vs UTC — you will normalize every timestamp to UTC later
w32tm /query /status
Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"   # record this in your notes
```

Keep a running **notes file** (`notes\log.md`): timestamp every command you run and every
decision you make. This becomes your timeline and your custody record for free.

---

## Rules of engagement (get these answered before you act)

Beginners especially: **you are not authorized to do whatever you want on someone else's
machine.** Confirm before containment/eradication:

- **Authorization** — do you have written authority to contain/modify this host?
- **Business impact** — is this a domain controller, a database, a life-safety system? Isolation
  may cause an outage worse than the intrusion.
- **Legal/regulatory hold** — is data on this host regulated (PII/PHI/PCI)? That changes whether
  you keep egress open (step 02) and how you handle the disk.
- **Who else needs to know** — legal, management, the SOC, possibly law enforcement.

---

## Where you are, and what's next

You now know how to move without breaking the scene. Everything after this assumes these five
principles. Go find out whether you even have an incident.

➡️ Next: [01-triage-the-alert.md](01-triage-the-alert.md)

*Toolkit parallel: these principles are baked into the automation — read-only collection,
`_clock.json` (clock context), `_custody_*.json` (custody seal), and the verdict ladder in
`Get-FindingContext.ps1`. Here you are doing by hand what the toolkit does structurally.*
