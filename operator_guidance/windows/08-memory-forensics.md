# 08 · Memory Forensics

*Open the image you captured in step 03. This is where fileless malware, injected code, live C2,
and hidden processes finally become visible — and where "Indeterminate" findings become verdicts.*

---

## The situation

You're on your **analyst workstation** now (never the victim host), working from a **copy** of the
memory image whose hash you verified. RAM is the only evidence source that shows what the live OS
was hiding and what never touched disk. Two engines do the heavy lifting:

- **MemProcFS** — mounts the image as a *browsable filesystem* (a virtual drive). Great for
  beginners: you literally walk folders of processes. Works natively on AFF4.
- **Volatility 3** — command-line plugin framework, the forensics standard for raw/dmp images.

Use whichever you staged. The *questions* below are identical either way.

---

## Step 0 — Load the image

```powershell
# MemProcFS — mount as drive M:
E:\tools\memprocfs\MemProcFS.exe -device E:\IR-CASE\evidence\memory_HOST.raw -mount M:
#   → browse M:\name\  (processes by name),  M:\pid\ ,  M:\sys\ , registry, handles, etc.

# Volatility 3 — run plugins against the image
python3 vol.py -f E:\IR-CASE\evidence\memory_HOST.raw windows.info
```

---

## The six questions memory answers

### Q1 — What processes really existed? (hidden-process hunt)

The live OS can be lied to by a rootkit; memory cross-references kernel structures and catches
processes hidden from the API.

```
Volatility:  windows.pslist    (processes from the active list)
             windows.psscan    (processes carved from memory — finds UNLINKED/hidden ones)
             windows.pstree    (parent/child tree)
```

**Read it:** compare `pslist` vs `psscan`. **A process in `psscan` but not `pslist` was hidden** —
that alone is near-conclusive. Confirm the impossible-parentage you suspected in step 04.

### Q2 — Is there injected / unbacked executable code? (the big one)

This is what disk-based tools *cannot* find: executable memory that **no file backs**, or a
private region marked RWX holding shellcode.

```
Volatility:  windows.malfind    (injected/RWX private regions + a hex/disasm preview)
             windows.ldrmodules (DLLs loaded but NOT in the module lists = reflective/manual map)
```

**Read it:** `malfind` hits showing `MZ`/`PAGE_EXECUTE_READWRITE` in a process that shouldn't have
them (browser, `explorer.exe`, `svchost.exe`) = injection. `ldrmodules` gaps = a DLL hidden from
the loader. **Carve the region to a file** for deeper analysis (config extraction below).

> **Beware benign JIT.** Browsers, .NET, and Java legitimately create executable memory (just-in-
> time compilation). "Shellcode threads" with **zero** injected regions and **zero** recovered
> IOCs are usually benign JIT — confirm before convicting.

### Q3 — What was it talking to? (network + the real C2)

```
Volatility:  windows.netscan   (sockets/connections from memory — includes closed/hidden ones)
```

**Read it:** established connections to public IPs the live `netstat` (step 04) *didn't* show, tied
to your suspect PID. These are your C2 endpoints — add confirmed ones to your IOC list.

### Q4 — What did the obfuscated commands actually say?

The decoded form of that `-enc` blob lives in RAM.

```
Volatility:  windows.cmdline   (full command line per process)
             + string extraction / FLOSS on a carved region
```

### Q5 — What secrets are sitting decrypted in RAM?

Credentials encrypted on disk are cleartext in memory. Note *what* is exposed (which accounts) so
you know what to rotate in step 11 — you don't need to harvest them, just scope the exposure.

### Q6 — Persistence & services as memory saw them

```
Volatility:  windows.svcscan   (services incl. ones hidden from the SCM)
             windows.handles / windows.dlllist  (what a suspect PID had open / loaded)
```

---

## Verify EVERY flagged PID — a hit is a lead, not a verdict

This is the discipline that separates real analysis from box-checking. For **each** process the
scans flagged, build a dossier and decide from the *whole picture*:

```
For a suspect PID:  carve its injected region(s) → run capa (capabilities),
                    FLOSS (deobfuscated strings), and the mwcp config parsers on the carved bytes.
```

| What the PID's dossier shows | Verdict |
|---|---|
| Injected exec region **and** recovered C2/wallet resolving to **real adversary infra** (bonus: an mwcp config-parse confirms a beacon config) | **CONFIRMED** — its memory footprint *is* your eradication scope |
| Recovered domains are all the vendor's own SaaS; **0** injected regions/handles | **Benign FP** — record why |
| "Shellcode threads" but **0** injected regions and **0** IOCs | Usually **benign JIT** — confirm the thread starts are JIT stubs |
| Region is **file-backed** by a signed system DLL | **Benign** — a rule grazed a loaded library (verify its signature) |
| Recovered "IOCs" trace to files *this analyst session* handled (case reports, rules) | **Self-reference** — not a host indicator |

> **Two traps that create false C2:**
> 1. The **memory-capture tool's own process** holds ambient strings from all of RAM — those are
>    unattributed, not its C2.
> 2. **mwcp/config parsers are noisy over .NET/PowerShell memory** — a `[MATCH]` that's really a
>    CLR namespace string (`System.IO`) or a Microsoft telemetry domain (`aka.ms`) is **parser
>    noise, not evidence.** Treat every parser hit as a *candidate requiring confirmation*.
>
> **An indicator is confirmed only after you attribute it to a *non-tooling* process AND real
> infrastructure.** Don't let candidates pollute your IOC list, or eradication (step 10) will try
> to block legitimate infrastructure.

---

## The status trap (memorize this)

If your primary adjudication (step 07) said "0 confirmed" but memory flagged TP-class PIDs, **the
case is OPEN, not clean.** A green summary while a flagged PID sits unexplained is exactly how a
real implant hides. **You are not done until every flagged PID has an evidence-backed verdict** —
written down, with the *why*, so the next responder can trust it.

---

## Where you are, and what's next

Memory has upgraded your Indeterminates to real verdicts and handed you the implant's true C2 and
config DNA. You now have confirmed threats and confirmed indicators scattered across host, disk,
network, and RAM. Time to assemble them into a single story.

➡️ Next: [09-build-the-timeline-and-chain.md](09-build-the-timeline-and-chain.md)

*Toolkit parallel: **Phase 3** — `Analyze-Memory.ps1 -Adjudicate` (MemProcFS via
`memory_forensic.py`, or Volatility 3 `vadyarascan`), **Phase 3b** `memory_enrich.py` (per-PID
capa/FLOSS/mwcp/GeoIP carve + verdict), and **Phase 3c** the ML/correlation second-pass QA.*
