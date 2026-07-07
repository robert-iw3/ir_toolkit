# Linux — the manual operator workflow

The by-hand path from *"something is off and I can't nail it down"* to *"the threat is gone, the
host is trustworthy again, and I can prove what happened"* — on Linux.

Same phase spine as [Windows](../windows/README.md); the *mindset* is identical (order of
volatility, collect-before-judge, the verdict ladder), only the evidence sources change — `/proc`,
journald/auditd, systemd/cron, kernel modules, and Linux-native fileless techniques.

## The order (follow it top to bottom)

| # | Step | The question it answers |
|---|------|-------------------------|
| [00](00-mindset-and-first-principles.md) | **Mindset & first principles** | How do I not destroy evidence or tip off the attacker before I start? (Linux specifics) |
| [01](01-triage-the-alert.md) | **Triage the alert** | Is this real, and how bad — do I even open an investigation? |
| [02](02-contain-without-destroying-evidence.md) | **Contain** | Stop the bleeding: inbound deny, the outbound risk call, and blocking lateral movement — via `ufw`/`firewalld`/`nft`. |
| [03](03-capture-volatile-memory.md) | **Capture volatile memory** | What vanishes at reboot — fileless payloads, the kernel's true state? (AVML + the symbol problem) |
| [04](04-snapshot-live-system-state.md) | **Snapshot live state** | What's running, talking, and logged in *right now*? (`/proc` ground truth) |
| [05](05-persistence-and-execution-history.md) | **Persistence & execution history** | How does it survive a reboot, and what has run here? (systemd/cron/keys/journal) |
| [06](06-hunt-the-host.md) | **Hunt the host** | Where is it hiding — fileless, LD_PRELOAD, kmod rootkit, SUID, webshell, container escape? |
| [07](07-adjudicate-findings.md) | **Adjudicate** | Which findings are real, and can I prove it? (package provenance instead of Authenticode) |
| [08](08-memory-forensics.md) | **Memory forensics** | What's in RAM that never touched disk — injected threads, rootkit hooks, the real C2? (Volatility 3 `linux.*`) |
| [09](09-build-the-timeline-and-chain.md) | **Timeline & chain of events** | What happened, in what order, from patient zero to now? |
| [10](10-eradicate.md) | **Eradicate** | Remove all of it, reversibly, without missing a persistence tail? |
| [11](11-restore-and-recover.md) | **Restore & recover** | Return the host to known-good and keep it clean? |
| [12](12-report-and-retrospective.md) | **Report & retrospective** | Document it, and close the loop with preventive controls so the vector can't recur? |

## Two ways to walk this

- **Fast triage:** 01 → 02 → 04 → 05 → 06 → 07. Live host, no memory image. Confirms/denies and
  scopes a commodity infection.
- **Full forensic (serious/APT):** the whole chain, and **never skip 03 (memory)** — Linux malware
  lives in RAM (`memfd`, deleted-but-running, kernel rootkits) and a disk-only look is blind to it.

## What you need on hand

- **root** on the target (checks degrade gracefully as a normal user — note when they run degraded).
- A separate **analyst box** for memory analysis, and the target's **exact kernel version + debug
  symbols** (the ISF) — the #1 Linux-memory gotcha (step 03/08).
- **External evidence media** (exFAT/ext4, not FAT32) — never treat the suspect disk as primary.
- Your kit: **AVML**, **Volatility 3** + `dwarf2json`, **YARA**, and the config parsers.

## The golden rule

**Collect first, judge second, act last.** Snapshot read-only, decide with evidence, and only then
change the box. Every irreversible action waits until the evidence is safely off the host.

➡️ Start: [00-mindset-and-first-principles.md](00-mindset-and-first-principles.md)

*Toolkit parallel: this whole guide is the by-hand version of `WORKFLOW-LINUX.md` /
`Invoke-IRCollection-Linux.sh` / `Invoke-Eradication-Linux.sh` and the `playbooks/linux/` modules.*
