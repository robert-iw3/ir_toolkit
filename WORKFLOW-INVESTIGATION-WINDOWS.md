# Investigation Workflow - from toolkit output to the chain of events

**This is the hand-off.** The platform workflow ([WORKFLOW-WINDOWS.md](WORKFLOW-WINDOWS.md))
**collects, analyzes, and enriches** - it gathers everything the host and its memory hold and ties it
to real infrastructure. **This guide is what a IR/FR analyst then does with that output** to piece
together *what actually happened*. The toolkit does the mechanical work; the analyst does the
reasoning. (For Linux hosts, see the companion
[WORKFLOW-INVESTIGATION-LINUX.md](WORKFLOW-INVESTIGATION-LINUX.md).)

For the rule-by-rule logic of turning a YARA byte-match into a benign/true-positive verdict, see
[WORKFLOW-YARA.md](WORKFLOW-YARA.md); this guide is the broader "now build the story" layer above it.

### In plain terms

An investigation answers four questions: **What got in? How? What did it do? Where did it call home?**
The toolkit has already gathered the clues - mostly from the computer's **memory (RAM)**, where modern
malware runs without ever saving a file to disk. This guide walks through reading those clues **in a
logical order** to tell the story end to end - and, just as importantly, how to look into the
attacker's servers **safely, without tipping them off**.

You do **not** need to be at the affected computer; everything here is reasoning over files the toolkit
already produced. The flow follows the natural arc of an investigation:

> **be safe → find the malware → see what it is → list where it called → locate those servers → build the story → report it**

> The walkthrough below is sanitised from a **real-world analysis** used as the test case. Network
> indicators are **defanged** (`hxxp`, `[.]`) - inert at rest. No victim data is shown.

---

## What the toolkit hands you

After the memory/enrichment stage, the per-host folder (`reports\<HOST>\`) contains:

| Artifact | What it gives the analyst |
|---|---|
| `Memory_Enrichment.md` / `_*.json` | Per-PID footprint: confirmed/recovered/unverified hosts, IPs **with offline country**, implant config DNA (beacon templates, User-Agent, bot params, worm markers, mutex, miner config), handles (dropped files, persistence, mutexes), carved regions |
| `IOCs.json` | Machine-readable indicator set (C2 endpoints carry a per-IP `country`) for blocking + eradication |
| `YARA_Pivot_Report.md` / `_TP.json` | Memory YARA hits ranked by true-positive confidence - the open leads to verify first |
| `Attack_Graph.md` | The memory-derived chain (lineage, regions, C2) |
| `tools\binja\data\<id>\` | Carved injected regions (`.bin` + sidecar) for deep RE in Binary Ninja |

Everything below is reasoning over those files. **You should not have to re-run the host** - the data
is already gathered.

### Which part of the tool produces what - and what you do with it

The toolkit does the extraction (left); the analyst does the reasoning (right). Each step below maps to
one row:

| The tool does this (automatic) | ...and produces | The analyst then... |
|---|---|---|
| **YARA memory scan** (`memory_forensic.py`) | per-process malware-pattern hits, each with its region + matched string | **Step 1** - confirm real vs coincidence |
| **Pivot + ranking** (`generate_reports`) | `YARA_Pivot_Report.md` - hits ranked true-positive-first | start with the ranked leads |
| **Config-DNA sweep** (`memory_enrich.py`) | beacon templates, User-Agent, worm/mutex/miner config | **Step 2** - read the implant's behaviour |
| **IOC sweep + structural validation** (`memory_enrich.py`) | web addresses sorted into confirmed / recovered / unverified, + URLs | **Step 3** - triage real leads, OSINT the rest |
| **Offline geo** (`memory_enrich.py` + `tools/geoip`) | each IP tagged with its country (no network) | **Step 4** - first-pass infrastructure attribution |
| **Region carve** (`-Carve` -> `tools/binja/data/`) | injected code as raw `.bin` + sidecar | hand to a reverse-engineer if needed |
| *(nothing - this is the human part)* | - | **Step 5** - order it all into the chain of events |

So the tool **gathers and labels**; the analyst **interprets and sequences**. The rest of this guide
walks those steps in order.

---

## Golden rule: investigate passively

> **Never touch the live infrastructure from a host.** Do **not** paste a recovered URL/IP into a
> browser, `curl`, `nslookup`, or `ping` it - that alerts the operator and can re-trigger the payload.
> Submit the **defanged** indicator to OSINT services instead:
> - **urlscan.io** and **tria.ge** (Hatching Triage) - detonate URLs / samples in a sandbox
> - **VirusTotal** - file / URL / domain / IP reputation + related samples
> - **AlienVault OTX** and **IBM X-Force Exchange** - campaign / pulse context
> - **Shodan.io** - what an IP is actually hosting (ports, banners, certs)
>
> Pivot on the data those services return, never on the live host.

---

## Step 1 - triage the recovered hosts (the IOC logic)

The enrichment classifies every captured host so you chase signal, not noise:

- **Confirmed domains** (structurally valid TLD) - your actionable set: `flashupd[.]com`,
  `fhu77e[.]co`, `ip[.]aq138[.]com`, `pastebin[.]com`, `xcnpool[.]1gh[.]com`, `pubupl[.]com`,
  `uninstall[.]mysafesavings[.]com`, ...
- **Recovered at the parse boundary** - in raw memory two strings run together with no delimiter;
  `uninstall.mysafesavings.comMicrosoft` was trimmed back to the real `uninstall[.]mysafesavings[.]com`
  (recovered, not invented).
- **Unverified - "not resolvable, verify"** (kept, never asserted as an IOC, never deleted):
  `kipesoftin`, `mtsvc9`, `micr`, `uol[.]conhecaa`, `wmd9e[.]a3i1`, `substrate.office`. Run each through
  urlscan/VirusTotal before dismissing - it may be an uncommon-TLD domain, not just an over-capture.

> **Why this matters:** nothing is suppressed, but the high-confidence set is separated from the noise,
> so you start from real domains and consciously decide which "unverified" leftovers to chase.

---

## Step 2 - tie the IPs to infrastructure (offline geo)

Each recovered IP carries an **offline** country tag (db-ip Lite in `tools\geoip\`; no DNS/whois/API):

| IP (defanged) | Country (offline) | Seen pulling |
|---|---|---|
| `1[.]234[.]66[.]143` | KR (South Korea) | `/svchost.exe` (second-stage payload) |
| `78[.]140[.]220[.]175` | RU (Russia) | beacon |
| `94[.]23[.]172[.]164` | CZ (Czechia) | `/dupdatecheckerf` |

Geo is a **first-pass lead**: the country a DB reports can differ from the provider's registration -
confirm hosting/ownership in **Shodan** / **X-Force** before drawing attribution conclusions.

---

## Step 3 - read the implant (config DNA recovered from memory)

IOC reconstruction is not just hosts. The sweep pulls the implant's own configuration strings, which
tell you its **behaviour** and give you the strongest hunt pivots:

- **HTTP-bot beacon templates** - `/bad.php?w=%u&i=%s`, `/task2.php?w=%u&i=%S&n=%u%` (printf-style URI
  templates the bot fills on each check-in -> it's an HTTP bot).
- **Bot telemetry params** - `bid=%08x` (per-install bot ID), `campaign=`, `uptime=%d`, `rnd=%d`.
- **Spoofed User-Agent** - `opera/6 (windows nt %u.%u; u; langid=%x; %s)x64` - a templated, rare UA to
  blend into web traffic. A *fantastic* network-hunt pivot (search proxy logs for this exact UA).
- **Worm self-spread (T1091)** - `autorun.inf` / RECYCLER drop / `attrib -s -h` / `xcopy` markers: it
  copies itself to removable media (explains lateral spread).
- **Single-instance mutex** - `1BA6BD98D9` (host-survey IOC + the implant's lock).
- **Cryptominer config** - `stratum+tcp://xcnpool[.]1gh[.]com:7333 -u <wallet>.SERVER%RANDOM% -p x`,
  wallet `CJJkVz...` (T1496) - monetizes idle cycles, injected into a separate signed process.

---

## Step 4 - work the YARA Pivot Report from top to bottom

Open `YARA_Pivot_Report.md` before anything else. The report does the initial collapse for you: it
ranked all YARA-hit processes by **true-positive confidence** and separated them into tiers. In the
test case this image produced **104 processes with at least one YARA hit**. After confidence scoring,
**10 were true-positive-class** — the other 94 were noise from one generic rule firing file-backed on
signed system DLLs (see below).

### Confidence tiers (how the pivot report ranks them)

| Tier | Label | What drives it |
|:-----|:------|:---------------|
| >= 6 | Likely True Positive | Named family rule AND co-occurring injection evidence (shellcode thread, injected exec region) |
| 4-5 | Likely True Positive | Named family rule alone, OR 3+ distinct rules on one PID |
| 3 | Likely True Positive | Generic rule that co-occurs with injection evidence from another module |
| 0 | Investigate | Lone generic rule only, no supporting injection evidence |

Work the list from the top. Do not process investigate-tier PIDs until all Likely-TP PIDs are resolved.

### The true positives from this run

Full rule logic is in [WORKFLOW-YARA.md](WORKFLOW-YARA.md). The discriminator each time is
**matched string + region type**, not the rule name alone.

**Highest confidence - named family rule AND injection evidence (Confidence 6):**

| PID | Process | Rule | Co-occurring signal | Matched evidence |
|:----|:--------|:-----|:--------------------|:-----------------|
| 13816 | msedgewebview2 | `CoinMiner_Strings` | 16 shellcode threads, all starting at same address | `stratum+tcp://<pool>:7333 -u <wallet> -p x`, `Vidar.AM` adjacent in anon exec region |

16 threads all starting at the same address means that address is the implant's thread entry point.
The identical address across all threads is what eliminates JIT coincidence — legitimate JIT stubs do
not produce 16 threads with the identical start address; an injected dispatch stub does.

**Named APT/malware family rule (Confidence 4-5):**

| PID | Process | Rule(s) | Matched evidence | Verdict |
|:----|:--------|:--------|:-----------------|:--------|
| 13680 | shell experience host | `REDLEAVES_CoreImplant_UniqueStrings`, `LOLBin_Mshta_Scriptlet`, `LOLBin_BITS_Drop` | `red_autumnal_leaves_dllmain.dll` + RTTI `CmdRedirector` / `MappingSlave` / `GHttp` / `SIComm` in anon region | **Confirmed** - APT10 RedLeaves core implant |
| 3464 | svchost.exe | `WiltedTulip_Windows_UM_Task` | `svchost64.swp",checkUpdate` (payload + export), `Msfpayloads_msf_5` adjacent | **Confirmed** - scheduled-task persistence, Metasploit-built |

Three distinct rules corroborating PID 13680 is near-certain even before reading the matched strings.
`REDLEAVES_CoreImplant_UniqueStrings` was written on confirmed APT10 samples — it does not FP on
legitimate Windows code.

**Generic rule elevated by injection evidence (Confidence 3):**

| PID | Process | Rule | Co-occurring injection evidence |
|:----|:--------|:-----|:-------------------------------|
| 2532 | sihost.exe | `LOLBin_BITS_Drop` | 2 x private anonymous exec VADs (Module 3) |
| 2536 | OneDrive.Sync | `LOLBin_BITS_Drop` | 2 x private anonymous exec VADs + PPID spoof (Module 17) |
| 3776 | StartMenuExperienceHost | `LOLBin_BITS_Drop` | 2 x private anonymous exec VADs |
| 3932 | OneApp.IGCC.WinService | `LOLBin_BITS_Drop` | 4 x private anonymous exec VADs |
| 3956 | IgoAudioService | `LOLBin_BITS_Drop` | 4 x private anonymous exec VADs |
| 4012 | IntelAudioService | `LOLBin_BITS_Drop` | 5 x private anonymous exec VADs |
| 5740 | SearchHost.exe | `LOLBin_BITS_Drop` | 2 x private anonymous exec VADs |

`LOLBin_BITS_Drop` alone is noise (see below). These seven PIDs are actionable because each has
private anonymous exec VADs from Module 3 — executable memory with no backing file. The YARA rule
matching BITS strings inside that anonymous region means the injected shellcode called into BITS, not
that the legitimate binary did.

### The noise - same rule, file-backed on signed DLLs

The remaining 94 investigate-tier entries are all `LOLBin_BITS_Drop` hitting processes with
**no co-occurring injection evidence**. In every case the match is **file-backed** on a
Microsoft-signed library (`shlwapi.dll`, `CRYPT32.dll`, `wintrust.dll`, `zlib1.dll`) — the rule's
target strings are present in libraries that load into almost every Windows service process. Verify the
signer with `Get-AuthenticodeSignature`; if it is Microsoft Windows, close as rule FP.

> **The lesson:** the matched **string + region type** is the discriminator, not the rule name.
> A family rule in **anonymous unbacked** memory is a true positive; the same rule **file-backed on a
> signed DLL** is a graze. The YARA Pivot Report surfaces this distinction automatically in the
> confidence tier — a lone generic rule stays at confidence 0 regardless of how many processes it hits.

> **Why memory analysis is non-negotiable.** In this test case the responder had already taken
> precautions *before* running the toolkit - the host was **isolated**, on-disk persistence was
> **cleared** (scheduled tasks, autorun/Run keys, user AppData), and a **full offline AV scan came
> back clean**. The implant was *still resident in RAM* and only the memory pass found it. Disk and AV
> alone would have called this host clean.

### Escalating confirmed PIDs to the enrichment pipeline

Once a PID is confirmed true-positive-class from the pivot report:

1. Run `memory_enrich.py` against the confirmed PID list (or use `Analyze-Memory.ps1 -Adjudicate`
   which chains this automatically). This extracts per-PID footprint: dropped files, registry
   persistence, mutexes, named pipes, loaded modules, C2 endpoints, and carves the injected region
   for offline reverse-engineering.
2. Output lands in `Memory_Enrichment_*.json` and is merged into `IOCs.json` with per-IP country
   tags via the offline GeoIP database.
3. Re-run `generate_reports.py` after enrichment to populate `Attack_Graph.md` with the confirmed
   chain and produce an `Incident_Report.md` that separates TP findings from unadjudicated noise.
4. The carved injected regions (`.bin` + sidecar) land in `tools\binja\data\` for deep RE if needed.

---

## Important: this is a reconstructed floor, not the whole story

Two things limit how complete the picture can be - say so explicitly in any report:

1. **Memory is a snapshot of one boot.** Process-create times are the last boot's session start, not
   when the malware was introduced; reboots reset them and auto-start malware reloads each time.
2. **Pre-collection cleanup destroys evidence.** Because on-disk persistence and dropper files were
   removed *before* the image was taken, parts of the chain below are **reconstructed from strings that
   survived in memory**, not directly observed on disk. The real extent may be **larger** - earlier
   stages, cleared artifacts, and (given the USB-worm capability) **other hosts** may not appear here.

> **Best practice the next responder should follow: acquire the memory image FIRST, then remediate.**
> Capturing before cleanup is what preserves the full chain. Treat the reconstruction below as "at
> least this happened," not "only this happened."

---

## Step 5 - reconstruct the chain (order indicators by role)

Order what you have into delivery -> execution -> persistence -> payload/C2:

1. **Delivery** - `hxxps://pastebin[.]com/raw/2STTYftz` hosts a VBScript stage-1. *Detonate it in
   tria.ge / urlscan, do not open it on a host.*
2. **Execution - squiblydoo (T1218.010)** - the script abuses `regsvr32` to run a COM scriptlet,
   bypassing application allow-listing:
   ```vbscript
   objShell.run "regsvr32.exe /s /u /i:%ProgramData%\Programdata.tmp scrobj.dll", 0
   ```
3. **Persistence (T1053.005)** - it installs a scheduled task that re-runs the payload every 40 minutes:
   ```vbscript
   objShell.run "schtasks /create /sc minute /mo 40 /tn AttRupee /tr ""%ProgramData%\MyApp.vbs"" /F", 0
   ```
4. **Payload + C2** - the implant pulls `hxxp://1[.]234[.]66[.]143/svchost.exe` (KR) and beacons to
   `hxxp://flashupd[.]com/mp3/in`, `hxxp://fhu77e[.]co/muztafa/lobby/get_json.php`,
   `hxxp://ip[.]aq138[.]com/get`, `hxxp://78[.]140[.]220[.]175/` (RU),
   `hxxp://94[.]23[.]172[.]164/dupdatecheckerf` (CZ); a second process coin-mines to
   `stratum+tcp://xcnpool[.]1gh[.]com:7333`.

**The actual story.** A user ran a paste-hosted script that abused `regsvr32` (squiblydoo) to bypass
application allow-listing, set a 40-minute scheduled task (`AttRupee`) for persistence, and injected a
**REDLEAVES-class HTTP bot/worm** into a signed Windows process. The bot beacons to fake-update / JSON
C2 across **KR, RU, and CZ** infrastructure, reports `bid`/`campaign` telemetry behind a **spoofed
Opera User-Agent**, fetches a second-stage `svchost.exe`, and **self-propagates over USB**. In
parallel a **cryptominer** in a second process mines under the operator's wallet. None of this is
obvious on disk - it was reconstructed entirely from RAM, then tied to real infrastructure offline.

---

## Step 6 - corroborate, then act, then report

1. **Corroborate** each indicator in the OSINT services (the spoofed User-Agent and beacon URIs are
   especially searchable in urlscan / VirusTotal / OTX). Promote an `unverified` host only once OSINT
   backs it.
2. **Act** - feed the confirmed set into `IOCs.json` (it carries the per-IP country) for egress
   blocking and `Invoke-Eradication.ps1` (analyst-gated). For deep RE, open the carved regions from
   `tools\binja\data\` in the isolated Binary Ninja container.
3. **Report** - Preserve the memory image, the IOC list, and the generated reports as evidence.

---

*The platform workflows gather and enrich the evidence; this guide is the analyst's reasoning that
turns it into the chain of events. Start at Step 1 with the enrichment output already in hand.*
