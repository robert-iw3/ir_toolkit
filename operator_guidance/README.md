# Operator Guidance — the manual, by-hand DFIR workflow

The rest of this toolkit **automates** incident response: one command collects, scores,
adjudicates, hunts memory, and eradicates. This directory does the opposite on purpose.

**Here you do every step by hand.** Same phases, same evidence, same decisions — but you
type the commands, read the raw output, and make the call yourself. The goal is not speed.
The goal is *understanding*: when you have run the manual sequence a few times, the
automated toolkit stops being a black box and becomes something you can trust, tune, and
override.

> If you want the job done fast, run the automation ([WORKFLOW-WINDOWS.md](../WORKFLOW-WINDOWS.md)).
> If you want to *become the analyst who wrote the automation*, work through this guide.

---

## Who this is for

**Everyone.** Each step is written in three layers so you can read at your level:

- **Beginner** — plain-language "what is this and why do I care" up top, and a copy-pasteable
  command that just works.
- **Intermediate** — how to read the output, what "normal" vs "suspicious" looks like, and the
  decision that moves you to the next step.
- **Advanced** — the deeper "going further" notes: edge cases, anti-forensics, where attackers
  hide from this exact check, and how the automation generalizes it.

You never have to read a layer above your comfort. But it is all there when you are ready.

---

## The lifecycle (this is the spine of every platform)

```
  ALERT ─▶ TRIAGE ─▶ CONTAIN ─▶ COLLECT ─▶ ANALYZE/ADJUDICATE ─▶ MEMORY ─▶ TIMELINE ─▶ ERADICATE ─▶ RESTORE ─▶ REPORT
    │         │          │           │              │                 │          │             │           │          │
  "something  │       stop the     snapshot      turn raw          the only    build the    remove the  return to   write it
   is off"   is it    bleeding     everything    findings into     evidence    chain of     threat,     known-good  down so the
             real?    without      without       verdicts you      that never  events;      reversibly  and verify  next person
                      destroying   judgment      can defend        touches     prove the                            can trust it
                      evidence                                     disk        story
```

Two rules hold across the whole chain:

1. **Order of volatility (RFC 3227).** Capture the evidence that disappears first, first:
   memory → live network/process state → disk artifacts → logs. A reboot destroys RAM
   *forever*. You get one shot.
2. **The verdict ladder.** Nothing is "malware" or "clean" on a hunch. Every finding earns a
   verdict with evidence behind it:

   ```
   False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive
   ```

   A validly-signed Microsoft binary running from `AppData\Roaming` is **Indeterminate**, not
   cleared. "Likely True Positive" is the signal that says *look here first* — it does not
   skip the analyst's confirmation.

---

## Platforms

Start with **Windows** — it teaches the mindset that carries to the rest. The other platforms
follow the same phase spine, adapted to their evidence sources.

| Platform | Folder | Evidence world |
|---|---|---|
| **Windows** | [windows/](windows/) | Endpoint: memory, registry, event logs, services, on-disk artifacts |
| **Linux** | [linux/](linux/) | Endpoint: `/proc`, journald/auditd, systemd/cron, kernel modules, memory |
| **AWS** | [aws/](aws/) | Control plane: CloudTrail, IAM, GuardDuty, EC2/EBS/S3 |
| **Azure** | [azure/](azure/) | Control plane: Entra ID, Activity/Sign-in logs, Defender XDR |
| **GCP** | [gcp/](gcp/) | Control plane: Cloud Audit Logs, IAM, SCC |

Cloud shifts the "host" from a machine to an *identity and its control plane* — but the
questions ("is it real, contain it, collect, adjudicate, time-line, eradicate, report") do
not change.

---

## How to use this guide

1. Read [windows/00-mindset-and-first-principles.md](windows/00-mindset-and-first-principles.md)
   once. It is the ground rules — evidence handling, order of volatility, not tipping off the
   adversary. Ten minutes that make everything after it safer.
2. Then follow the numbered files **in order**. Each one ends by telling you when you are done
   and what the next step is, so the whole thing reads as one continuous investigation.
3. Each step names its **toolkit parallel** — the automated script that does the same job — so
   you can cross-reference the by-hand version against the automation any time.

You are about to get an alert you can't explain. Turn to
[windows/01-triage-the-alert.md](windows/01-triage-the-alert.md) and start there.
