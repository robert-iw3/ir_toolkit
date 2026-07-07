# 08 · Memory Forensics (Linux)

*Analyze the image from step 03 on your analyst box. This is where fileless payloads, injected
threads, hidden kernel modules, and live C2 become undeniable — and Indeterminates become verdicts.*

Why memory is imperative: [../windows/08-memory-forensics.md](../windows/08-memory-forensics.md).
Below is the Linux toolchain and the plugins that answer each question.

---

## Step 0 — Build the symbol table, then load the image

Linux memory analysis needs an **ISF matching the target kernel** (the version you recorded in step
03). This is the step people skip and then wonder why every plugin returns nothing.

```bash
# Generate the ISF from the target kernel's debug symbols (once), then point Volatility at it
dwarf2json linux --elf /path/to/vmlinux-<ver>-with-debug > symbols/<distro>-<ver>.json
# (The toolkit's --stage-symbols bakes this offline.)

# Confirm Volatility can read the image with those symbols
python3 vol.py -f evidence/memory.lime banners.Banners     # sanity: shows the kernel banner
```

---

## The questions memory answers (Volatility 3 `linux.*`)

### Q1 — What processes really existed? (hidden-process hunt)

```
linux.pslist     (processes from the task list)
linux.psscan     (carved from memory — finds UNLINKED/hidden tasks)
linux.pstree     (parent/child tree)
```

**Read it:** a task in `psscan` but not `pslist` was hidden by a rootkit — near-conclusive. Confirm
the impossible-parentage and deleted-exe suspicions from step 04.

### Q2 — Injected code & malicious threads

```
linux.malfind      (anonymous executable/RWX regions with code — injection/shellcode)
linux.proc_maps    (a process's memory map — spot rwx anon regions, unbacked exec)
linux.pscallstack  (kernel-stack anomalies — a thread executing from a suspicious frame)
```

**Read it:** RWX anonymous regions holding code in a process that shouldn't have them = injection.
Cross-reference a flagged thread (TID) against the live thread inventory from step 06 — a TID
flagged by **both** the memory kernel-stack walk *and* live enumeration is a corroborated injected
thread (suspend that thread specifically in step 10, don't kill the whole process). Beware benign
JIT (JVM/V8/.NET) — it makes exec memory legitimately; look for the C2 socket + no parent story.

### Q3 — Network & the real C2

```
linux.sockstat / linux.netstat   (sockets from memory, including ones the live host hid)
```

**Read it:** connections to public IPs the live `ss` (step 04) didn't show, tied to your suspect
task = C2. Add confirmed endpoints to your IOC list.

### Q4 — Rootkit ground truth (kernel-level)

This is uniquely a memory job — a loaded rootkit lies to the live OS but not to raw memory:

```
linux.check_syscall   (syscall-table hooks — hijacked entries)
linux.check_afinfo    (network-op struct hooks)
linux.lsmod / linux.hidden_modules / linux.check_modules   (modules incl. ones hidden from lsmod)
linux.tty_check       (keystroke-logging tty hooks)
```

**Read it:** a hooked syscall entry, or a module in `hidden_modules`/`check_modules` that `lsmod`
didn't show, is a kernel rootkit — strong evidence and a re-image trigger (step 11).

### Q5 — Commands, env, and open handles per PID

```
linux.psaux        (full argv per process — the decoded command)
linux.envars       (environment — LD_PRELOAD injection shows here)
linux.lsof         (open files/handles — /etc/shadow, /dev/mem, another proc's mem = cred access)
linux.bash         (recovered bash history from memory — even if the on-disk histfile was wiped)
```

`linux.bash` is a gift: it recovers shell history from RAM even when the attacker set
`HISTFILE=/dev/null` or truncated the file.

---

## Verify EVERY flagged PID — a hit is a lead, not a verdict

For each flagged task, build a dossier (carve the region → strings/FLOSS, YARA, capabilities) and
decide from the whole picture — same table logic as Windows:

| Dossier shows | Verdict |
|---|---|
| Anon exec region **and** recovered C2 to **real adversary infra** | **CONFIRMED** — its footprint is your eradication scope |
| Recovered domains are the vendor's own SaaS; **0** injected regions | **Benign FP** — record why |
| Exec memory but it's a **JIT runtime** with a legit parent, no C2 | **Benign JIT** |
| "IOCs" trace to files *this analyst session* handled | **Self-reference** — not a host indicator |

> **The same two traps apply:** the memory-capture tool's own process holds ambient RAM strings
> (not its C2), and string/config parsers over interpreter (Python/JVM) memory produce noise
> candidates, not proof. **An indicator is confirmed only after you attribute it to a non-tooling
> task AND real infrastructure.**

## The status trap

If the primary adjudication said "0 confirmed" but memory flagged tasks, the case is **OPEN, not
clean.** You're done only when every flagged task has an evidence-backed verdict, written down with
the *why*.

---

➡️ Next: [09-build-the-timeline-and-chain.md](09-build-the-timeline-and-chain.md)

*Toolkit parallel: **Step 2** — `Analyze-Memory-Linux.sh` → `analyze_memory_linux.py` runs these
`linux.*` plugins; `memory_enrich.py` carves + enriches per PID; `thread_inventory.py` corroborates
injected threads (memory + live) for surgical eradication.*
