# YARA Findings Analysis Workflow (Windows + Linux)

How the IR Toolkit scans memory with YARA, **what context it gathers per hit**, and the explicit
logic — with worked examples — for deciding whether a match is **benign** or a **true positive
without a doubt**. The guiding rule throughout: **context only escalates or annotates, it never
silently clears** (no blindspots). A match is *contextualised*, never *deleted*.

See [readme.md](readme.md) for the adjudication philosophy, [WORKFLOW-LINUX.md](WORKFLOW-LINUX.md)
and [WORKFLOW-WINDOWS.md](WORKFLOW-WINDOWS.md) for the per-platform memory pipelines.

---

## Why a raw YARA hit is not a verdict

YARA matches **bytes**. A rule named `ELF_Mirai` or `Cobalt_Strike` firing tells you those bytes are
present in memory — **not** that the malware is running. The same bytes legitimately appear in:

- a **loaded library / interpreter** (a compiler holds every CPU-architecture name; Python's string
  table holds "download", "exec", "socket"…),
- a **cached file** sitting in the page cache,
- another **YARA rule's own definition** loaded by a scanner,
- **free/unallocated pages** left over from a long-dead process.

So the toolkit never reports a bare hit. It gathers the **location and nature** of each match and
attaches it to the finding, because *where* a rule matched is what separates noise from a real
implant.

---

## The scan pipeline (both platforms)

```mermaid
flowchart TD
    R[/"YARA rule packs
    Elastic · ReversingLabs · Neo23x0 · abuse.ch"/]:::artifact
    R --> C["① CURATE by content
    drop non-applicable rules + compile an OS canary"]:::tool
    C --> T["② TRIAGE scan
    Linux: native full-image · Windows: per-process (vmmpyc)"]:::step
    T --> Q{"canary fired?
    any match?"}:::decision
    Q -->|canary never fired| U["UNTRUSTED
    '0 matches' is NOT clean — re-scan"]:::phase
    Q -->|no match, canary OK| CLEAN["trusted clean"]:::step
    Q -->|match| E["③ ENRICH per hit
    PID · region · perms · path · strings · breadth"]:::step
    E --> D{"region anon + exec?"}:::decision
    D -->|yes| TP["TRUE POSITIVE (injected/unbacked)
    corroborate: malfind/VAD · C2 · parent · persistence"]:::tool
    D -->|file-backed| V["verify backing file
    Linux: hash/package · Windows: Authenticode+hash"]:::step
    V --> O[/"Incident report — Memory forensics & YARA
    + adjudication funnel"/]:::artifact
    TP --> O

    classDef prep  fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
    classDef phase fill:#1e3a5f,stroke:#60a5fa,color:#e2e8f0,rx:20
    classDef tool  fill:#1e293b,stroke:#64748b,color:#cbd5e1
    classDef step  fill:#0f172a,stroke:#334155,color:#94a3b8
    classDef artifact fill:#14532d,stroke:#22c55e,color:#dcfce7
    classDef decision fill:#451a03,stroke:#f97316,color:#fed7aa
```

### ① Curate by content + compile a canary
Rules are filtered by **what they reference**, not by filename:

- **Linux** (`linux_yara.py`): drop rules importing `pe`/`dotnet`/`macho` or built from
  Windows-API/registry strings → ~9,600 packs become ~400 genuinely-Linux rules (`--yara-broad`
  re-adds generic ones). Externals (`filename`, `filepath`, …) are declared so file-scan rules
  compile instead of failing the whole set.
- **Windows** (`memory_yara.py`): drop non-Windows rules; declare externals; compile with `yarac64`.

A **canary rule** is compiled in (ELF magic on Linux, MZ/DOS-stub on Windows). If the canary never
matches, the engine never inspected memory — so **"0 matches" is reported as UNTRUSTED, not clean**.
This is the single most important integrity check: it makes a silent scan failure loud.

> Historical bug this prevents: passing raw rule source to Volatility's `--yara-file` compiled with
> *no* externals, so one rule referencing `filename` failed the **entire** compile → the scanner ran
> with **zero** rules → reported a false "clean." The canary turns that into an explicit UNTRUSTED.

### ② Triage scan
- **Linux native (default):** `yara-python` mmaps the whole image, one pass — **full physical
  coverage** (kernel + free pages), fast, but no PID yet.
- **Windows:** MemProcFS (`vmmpyc`, C-backed) scans **per-process** directly — fast + already
  attributed.

### ③ Enrich per hit (the disambiguator)
For every match the toolkit records:

| Field | Linux source | Windows source | What it tells you |
|---|---|---|---|
| **PID + process** | per-process worker (`vmayarascan` via library) | vmmpyc per-process | attribution |
| **Region** | VMA `anon` vs `file` | VAD `Private` vs `Image`/`Mapped` | unbacked/injected vs mapped-from-disk |
| **Perms** | `vma.get_protection()` → `rwx`/`r-x`/`r--` | VAD protection → `RWX`/`RX`/`R` | **W+X / exec = injection territory** |
| **Backing path** | `LinuxUtilities.path_for_file` | mapped image path | *which* on-disk file (verify it) |
| **Matched strings** | `match.strings[*].identifier` | same | generic anchor vs specific behaviour |
| **Breadth** | distinct PIDs per rule | distinct PIDs per rule | shared-lib bytes vs injection campaign |

On Linux this is a **two-phase** flow: the fast triage says *what* is present, then a per-process
worker (Volatility driven as a library — init the image once, loop tasks in-process) **follows up
automatically on the hits** to attribute + enrich them. Windows is already per-process so it enriches
in the single pass. Both stream a rolling `_yara_results_<stamp>.jsonl` and write a
`_yara_results_<stamp>.json` summary, surfaced in the report's **Memory forensics & YARA** section.

---

## ④ The decision logic

Apply in order. The point is to **earn** a verdict from evidence, and to be honest about when you
can't reach "without a doubt."

```
                      ┌─────────────────────────────────────────────┐
   YARA hit ─────────▶│ canary fired for this scan/process?         │
                      └───────────────┬─────────────────────────────┘
                              no │            │ yes
                                 ▼            ▼
                       UNTRUSTED        ┌───────────────────────────────┐
                    (re-scan; do not    │ region == anon AND perms exec?│
                     treat as clean)    └──────┬────────────────────────┘
                                          yes  │           │ no
                                               ▼           ▼
                                   ┌────────────────┐  ┌───────────────────────────────┐
                                   │ TRUE POSITIVE  │  │ region == file/image (on disk)│
                                   │  (injected/    │  └──────┬────────────────────────┘
                                   │  unbacked exec)│        │
                                   └───────┬────────┘  ┌─────▼──────────────────────────┐
                                           │           │ verify backing file:           │
                              corroborate  │           │  hash/package (Linux)          │
                              (malfind/VAD,│           │  Authenticode+hash (Windows)   │
                               C2, parent, │           └───────────┬────────────────────┘
                               persistence)│         clean         │   tampered/unsigned/unknown
                                           ▼           ▼           ▼
                                     TP — DECLARE    BENIGN-     SUSPICIOUS — escalate,
                                                     with-       keep investigating
                                                     context
```

### Rule A — Trust gate (always first)
If the canary did **not** fire for the scan (Linux global) or for the process (per-process), the
result is **UNTRUSTED**. "0 matches" means nothing. Raise the timeout / fix the engine / re-scan.

### Rule B — Anonymous + executable ⇒ true positive *without a doubt*
A match in **unbacked, executable** memory has no legitimate on-disk origin — it is code that was
**written into memory at runtime**: process injection, reflective DLL/`.so` loading, a Cobalt Strike
beacon, shellcode. This is automatically **escalated to Critical** and typed *"Injected Code (memory
YARA)"*. The combination *region=anon/Private + perms include `x` + a malware-family rule* is as close
to certain as memory forensics gets.

> Make it airtight by **corroborating** on the same PID: `linux.malfind` / Windows VAD-injection
> already flags anon-exec regions; add external C2 (`sockstat`/netstat), an anomalous parent, or a
> persistence hook and you have an undeniable, multi-signal true positive. The toolkit's correlation
> engine emits `Correlated Memory Threat` exactly when a YARA hit converges with another signal on one
> PID.

### Rule C — File-backed ⇒ verify the file, don't assume
A match in a **file-backed** region (`file` on Linux, `Image`/`Mapped` on Windows) means the rule hit
the bytes of a file on disk. That is *usually* benign (a rule grazing a loaded library) **but not
always** — a **trojanised binary** or a **patched DLL** is exactly a real attack that lives in a
file-backed mapping. So the rule is: **identify the file and verify it.**

- **Linux:** is the path a packaged file? `dpkg -S <path>` / `rpm -qf`, compare against the package's
  hash. `/usr/bin/python3.13`, `/usr/lib/.../libLLVM.so` owned by an installed package and unmodified
  → benign.
- **Windows:** is the image **Authenticode-signed** by the expected vendor and its hash known-good?
  Signed Microsoft/`%SystemRoot%` DLL, valid signature → benign. Unsigned, in `%TEMP%`, hash unknown,
  or signature invalid → **suspicious**, keep going.

### Rule D — Matched-string specificity
Look at **which strings fired**. Generic *anchors* (ELF magic `$elf_magic`, MZ header, CPU-arch names
`$arch`, broad keyword strings) → the rule is matching structure/common text → low-confidence on its
own. **Specific** strings (a hard-coded C2 URL, a unique mutex, a known key schedule, a builder
watermark) → high-confidence, even before location analysis.

### Rule E — Breadth
One rule matching **many unrelated processes** usually means it matched **shared bytes** (a library or
interpreter loaded everywhere) → likely benign — **but** an `LD_PRELOAD` / AppInit / injected-into-
everything campaign also looks like this, so it is a *note*, never a clearance. One rule in **one
unusual** process is more concerning than the same rule across every GUI app.

---

## Worked examples

### Linux — BENIGN (proven), from a real `reports/ubuntu-main` scan
```
ELF_Mirai  — PID 4225 (Xwayland), 4357 (ibus-x11), 4358 (mutter-x11)
   region = file / r-x
   path   = /usr/lib/x86_64-linux-gnu/libLLVM.so.20.1
   strings= $arch $archx $arch3 ...   (CPU-architecture names)
```
**Decision:** Rule B → no (file-backed, not anon). Rule C → `libLLVM.so` is a packaged, unmodified
library. Rule D → only generic *arch-name* strings fired — Mirai checks target CPU arch, and LLVM (a
compiler) literally contains every arch name. Rule E → matched every GUI process because they all load
Mesa/LLVM. **Verdict: benign false positive, with proof** — surfaced and annotated ("verify
hash/package"), not deleted.

```
TH_Generic_MassHunt_Linux_Malware  — PID 1825 networkd-dispat, 2039 firewalld, 2387 unattended-upgr
   region = file / r--    (read-only, NOT executable)
   path   = /usr/bin/python3.13
   strings= $dl1 $exec3 $net1 $priv1 ...   (download/exec/network/priv keywords)
```
**Decision:** read-only, file-backed, in the **Python interpreter** these daemons run on; the rule's
keyword strings matched Python's static string table. **Benign**, proven by location + read-only perms.

### Linux — TRUE POSITIVE shape (what a real hit looks like)
```
Linux_Trojan_Gafgyt — PID 1337 (sh)
   region = anon / rwx          ← unbacked, writable+executable
   path   = (none)
   strings= $c2_host $cmd_handler   ← specific behaviour strings
   + linux.malfind flags the same RWX region · + sockstat shows 1337 → 185.x.x.x:443
```
**Decision:** Rule B fires (anon + exec) → Critical "Injected Code." Corroborated by malfind + external
C2 on the same PID → `Correlated Memory Threat`. **True positive without a doubt — declare and
eradicate.**

### Windows — BENIGN
```
Cobalt_Strike_Beacon — PID 6120 (chrome.exe)
   region = Image / RX
   path   = C:\Program Files\Google\Chrome\Application\chrome.dll  (Authenticode: Google, valid)
   strings= $sleep_pattern  (generic)
```
**Decision:** file-backed Image, **validly signed** Google binary, only a generic string → benign FP.
Annotate ("signed, hash known-good"), do not clear blindly — re-confirm the signature is valid.

### Windows — TRUE POSITIVE
```
Cobalt_Strike_Beacon — PID 5308 (SecHealthUI.exe)
   region = Private / RWX        ← injected, no backing image
   path   = (none)
   strings= $beacon_config $checkin_uri   ← specific
   + VAD-injection flag on the same region · + parent is winword.exe · + beacon to relay.example-c2:443
```
**Decision:** Private+RWX (injected) + specific Cobalt config strings + injected-VAD + macro-style
parent + C2 = undeniable. **True positive — declare.**

### Windows — from a real-world run of this tool (what was found + what proves it)

***Windows Defender (full & offline scan) found nothing, along with Trend Micro "Maximum" Security.***

***Do you really trust your (insert buzzword here) EDR/AV software? lol***

A live `Analyze-Memory.ps1` run over a captured memory image of a suspected-compromise host produced
**104 YARA matches across 102 processes**. Raw, that is undifferentiated noise. The per-hit VAD
context separates the real implants from rule grazes **with no analyst guesswork** — and the report
renders it inline. Here is what was found and what proves it.

**The four true positives — rule strings in ANONYMOUS (unbacked) memory:**
```
REDLEAVES_CoreImplant_UniqueStrings — PID 13680 (ShellExperienceHost)   region = anon / rw-
WiltedTulip_Windows_UM_Task         — PID 3464  (svchost.exe)           region = anon / rw-
CoinMiner_Strings                   — PID 13816 (msedgewebview2)        region = anon / rw-
LOLBin_Mshta_Scriptlet              — PID 13680 (ShellExperienceHost)   region = anon / rw-
```
**What proves it:** the matched strings live in **anonymous, unbacked memory** — there is no on-disk
file they could have been read from, so they are the implant's own runtime strings, not a signature
grazing a loaded module. REDLEAVES (APT10) and WiltedTulip are **family-specific** rules (Rule D), and
a specific family rule firing in unbacked memory is a true positive. *(Perms here are `rw-`, not
`rwx`; the **anon/unbacked location + family-rule specificity** is what's decisive. An `anon + rwx`
hit would additionally trip Rule B and be auto-typed "Injected Code (memory YARA)" → Critical.)*

**The noise — the SAME rule, FILE-BACKED on signed DLLs (the ~100× `LOLBin_BITS_Drop` cluster):**
```
LOLBin_BITS_Drop — PID 620  (svchost.exe)   file-backed -wx C:\...\shlwapi.dll  -- verify signature
LOLBin_BITS_Drop — PID 11272(iCloudCKKS)    file-backed -wx C:\...\zlib1.dll    -- verify signature
LOLBin_BITS_Drop — PID 11020(msedge.exe)    file-backed -wx C:\...\SHLWAPI.dll  -- verify signature
   ... ~100 hits, nearly all file-backed on Microsoft/vendor-signed system DLLs
```
**What proves it benign:** one rule fired across ~100 processes (Rule E — breadth) and almost every
hit is **file-backed on a signed system DLL** (Rule C) — the rule's BITS strings live inside
`shlwapi.dll` / `zlib1.dll`, which load nearly everywhere. Verify those DLL signatures and the cluster
clears as false positive.

**Takeaway for the analyst:** without enrichment this host reads as "104 YARA matches" — flat and
unactionable. With the VAD context, the **four real implants (all `anon`)** stand out at a glance
against the **~100 file-backed false positives**, and the proof (region / perms / backing file) is on
the same line in the report. That is the difference between a 2-hour triage and a 2-minute one.

---

## Quick reference

| Signal | Benign-leaning | TP-leaning |
|---|---|---|
| **Region** | `file` / `Image` / `Mapped` | `anon` / `Private` |
| **Perms** | `r--`, `r-x` (non-writable) | `rwx` / `W+X` |
| **Backing file** | packaged + unmodified / signed + known hash | none, or unsigned/tampered/`%TEMP%` |
| **Matched strings** | generic anchors (magic, arch, keywords) | specific (C2 URL, mutex, config) |
| **Breadth** | one rule across many shared-lib loaders | one rule in one unusual process |
| **Corroboration** | no other signal on the PID | malfind/VAD-inject + C2 + parent + persistence |
| **Canary** | fired (trusted) | fired (trusted) — *never trust a hit from an UNTRUSTED scan* |

**Bottom line:** anonymous executable memory + a specific malware-family string + at least one
corroborating signal on the same PID = **true positive without a doubt**. File-backed + generic strings
+ a verified-clean packaged/signed file = **benign** — but always *verified*, never *assumed*, and
always still surfaced with its context for the adjudicator and analyst.
