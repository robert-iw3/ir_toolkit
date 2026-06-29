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
| `Memory_Enrichment.md` / `_*.json` | Per-PID footprint: confirmed/recovered/unverified hosts, IPs **with offline country**, implant config DNA (beacon templates, User-Agent, bot params, worm markers, mutex, miner config), handles (dropped files, persistence, mutexes), carved regions, DC3-MWCP binary parsing results |
| `IOCs.json` | Machine-readable indicator set (C2 endpoints carry a per-IP `country`) for blocking + eradication; `memory_eradication.mutexes[]` carries both heuristic-classified and mwcp-confirmed mutex names |
| `Timeline_Correlation.md` | **Confirmed-TP attack timeline** — all true-positive artifacts ordered by earliest known timestamp, grouped by ATT&CK phase, with Mermaid attack chain diagram. USB device correlation for entry vector assessment. |
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
| **DC3-MWCP binary parsing** (`memory_enrich.py` + `tools/mwcp/`) | mutex names, C2 addresses, passwords, filenames extracted from carved binary regions by family-specific and generic parsers | compare against handle-enumerated mutexes to **verify or add** indicators; overlapping IOCs are tagged `mwcp-verified` |
| *(nothing - this is the human part)* | - | **Step 5** - order it all into the chain of events |

So the tool **gathers and labels**; the analyst **interprets and sequences**. The rest of this guide
walks those steps in order.

> **Optional tools (staged with `Build-OfflineToolkit.ps1`):**
> `-IncludeCapa`  → capability fingerprint + ATT&CK on carved regions
> `-IncludeFloss` → deobfuscated strings (stack/decoded/tight) from carved regions
> `-IncludeMWCP`  → DC3-MWCP malware config parser + generic mutex/C2 extractors (all families)
> `-IncludeGeoIP` → offline IP-to-country (no network calls)

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

> **Named-pipe enumeration can wedge the network stack.** The toolkit's named-pipe scanner
> (`Get-NamedPipeName`) lists pipe names via `FindFirstFile`/`FindNextFile` **without opening or
> connecting to any pipe** — this is safe. Do NOT use `Get-ChildItem \\.\pipe\` (the PowerShell
> provider path), which opens each pipe for metadata and can wedge core networking service RPC
> endpoints, taking DNS, TCP sockets, and WinHTTP offline mid-collection.
>
> If network connectivity drops after a collection run, run `playbooks\Repair-NetworkStack-Win11.ps1`
> (elevated) — it snapshots current adapter/route state, restarts core networking services in
> least-destructive order, resets Winsock and TCP/IP, and prompts for reboot. The repair is fully
> auditable and reversible. Pass `-EnforceOutboundOnly` to lock to outbound-only while the
> investigation continues, or `-IncludeIPv6Reset` if IPv6 is also affected.

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

### Mutex corroboration — three-layer analysis

Mutex names are some of the strongest implant fingerprints because malware creates them to prevent
duplicate execution. The toolkit surfaces them through three independent layers:

**Layer 1 — Runtime handle enumeration (highest coverage)**
`memory_enrich.py` reads every open handle in the confirmed-TP PIDs from the memory image.
Handle-based detection finds mutexes the binary creates **at runtime** — not visible to static
string scanning because the name may be constructed on the stack, XOR-decoded, or allocated
dynamically.

Classification logic for suspicious vs. benign handles:

| Mutex pattern | Verdict | Signal strength |
|:------------|:--------|:----------------|
| Bare hex token (`1BA6BD98D9`, 6-20 hex chars) | **Suspicious — high confidence** | Classic malware instance lock; legitimate software uses readable names |
| `SM0:PID:session:WilStaging_*` | **Suspicious** | APT camouflage: threat actors specifically use WilStaging-format names to blend with Windows internals; NOT a benign WIL mutex when found in implicated processes |
| `SM0:PID:session:WilError_*` | **Benign** | Documented WIL error-tracking mutex; common in any WIL-using host process |
| `SmartScreen*`, `Global\MSCTF.*`, `DBWin*` | **Benign** | Windows security component and UI sync objects |
| Long undelimited string (`x9pv45dxghk`) | **Heuristic — needs attribution** | Some Windows DLLs legitimately produce these; flag for analyst verification against the owning process |

Mutexes flowing into `IOCs.json` → `memory_eradication.mutexes[]` are the eradication scope.
Every mutex in that list was classified suspicious by at least Layer 1 or confirmed by Layer 3.

**Layer 2 — Binary parsing: GenericMutex + GenericC2 + PowerShellDecoder + LNKParser (all families)**
When `Build-OfflineToolkit.ps1 -IncludeMWCP` has staged DC3-MWCP, `memory_enrich.py` runs it
against every carved shellcode/PE region. Four generic parsers run against **any** carved binary
regardless of malware family:
- `GenericMutex` — scans for `CreateMutex`/`OpenMutex` API proximity + bare hex tokens in all strings
- `GenericC2` — extracts IP:port combos, URLs, domains, registry persistence paths
- `PowerShellDecoder` — decodes `-EncodedCommand` base64 payloads embedded in scripts, HTA, LNK, PE
- `LNKParser` — extracts command-line arguments from LNK shortcut files (payload lives in Arguments field)

These produce results for commodity malware with hardcoded plaintext strings. For sophisticated
implants using runtime-generated mutex names or **encrypted-at-rest** payloads (e.g. Ekko XOR sleep
obfuscation in CobaltStrike), Layer 1 (handle enumeration) remains the primary capture path.

Validated on live captured memory (271 VAD regions across 3 target PIDs):
- 81/271 regions returned findings from GenericMutex + GenericC2
- No C2 addresses recovered from encrypted beacon regions — expected when payload uses sleep-time XOR obfuscation (Ekko-class); C2 IPs are encrypted at snapshot time. Layer 1 (IOC sweep) is the capture path for this case, not Layer 2.
- High FP rate for GenericMutex on file-backed DLL pages — API function names near CreateMutex calls are structural artifacts, not malware-created mutex names. Heuristic gate filters these before output.

**Layer 3 — Family-specific parser (highest precision)**
If a DC3-MWCP family-specific parser matches the carved binary (CobaltStrike, Emotet, QakBot, etc.),
it extracts the full malware configuration: mutex names, C2 addresses, beacon intervals, user-agents,
and encryption keys. Results are tagged `[mwcp-confirmed]` in `Memory_Enrichment.md` and promoted
to the eradication mutex list bypassing the heuristic gate.

`CobaltStrikeConfig` parser (`mwcp_parsers/CobaltStrikeConfig.py`) extracts C2 host/port, HTTPS/HTTP/SMB beacon type, sleep + jitter, Malleable C2 User-Agent, Host header (domain fronting), spawn-to process, named pipe, and RSA public key.

**Ekko sleep obfuscation caveat:** beacons using Ekko-class sleep XOR encrypt the *entire injected region* (including the CS config block) with a separate key while sleeping. A snapshot taken during sleep produces 0 CS config hits — the CS XOR magic is obscured by a second encryption layer. This is not a parser failure; it is expected. CS config is recoverable from:
- Snapshots taken during active beacon execution (between Ekko sleep cycles)
- On-disk stager DLLs/EXEs before memory injection
- Post-capture memory pages where the beacon woke up before the snapshot completed

C2 infrastructure is still recoverable via Layer 1 (IOC sweep) during active network communication regardless of Ekko state.

**IOC verification:** when mwcp also finds an IP or domain already in the IOC sweep, that IOC is
tagged `mwcp-verified` — the binary config and the in-memory string sweep independently recovered
the same indicator, which eliminates the risk that the sweep was picking up benign cached data.

---

**Egress Monitor — active beacon capture and config extraction**

> **Risk notice:** leaving outbound open during the observation window tolerates continued exfil.
> Only enable when the intelligence value outweighs the data exposure risk. For data-sensitive hosts,
> isolate the network stack first and skip egress observation (`-NoEgressMonitor`).

The advanced egress monitor (`playbooks/threat_hunting/egress_monitor/`) is deployed automatically
when `Invoke-IRCollection.ps1` runs without `-NoEgressMonitor`. Stage it first:
```powershell
Build-OfflineToolkit.ps1 -IncludeMemProcFS -IncludeMWCP -IncludeEgressMonitor
```

**Full chain:**

1. **Enrich first.** Run `memory_enrich.py` (via `-CaptureMemory` or `Analyze-Memory.ps1`) to
   identify suspicious PIDs (anonymous exec VAD, ETW-TI absence). The flagged PIDs are passed to
   the egress monitor as `--flagged-pid` so any external connection triggers immediate action
   (Layer 0 — no pattern analysis needed).

2. **Deploy monitor.** `Invoke-IRCollection.ps1` starts `Start-EgressMonitor.ps1 -Start`, which
   deploys the self-contained daemon to `%ProgramData%\IRToolkit\egress-<id>\` and registers a
   scheduled task running `egress_monitor.py`. Duration is `-EgressWindowHours` (default 24h,
   max 72h).

3. **Beacon fires.** The daemon polls `proc.maps.net()` (MemProcFS) or `Get-NetTCPConnection`
   (fallback) every 5 seconds. On beacon wake, the connection is classified by `beacon_classifier.py`
   using four independent layers: process-context flag, non-browser process heuristic, periodicity
   analysis (CV + IQR-based, covers 0–99% jitter and sleeps up to 3 days), and family hints.

4. **Immediate VAD carve.** On `CONFIRMED_BEACON` or flagged-PID connection: all private executable
   anonymous VAD regions are carved via `proc.memory.read()` and written to `tools/binja/data/`.

5. **mwcp config extraction.** `mwcp_scan.py` runs `CobaltStrikeConfig`, `GenericC2`, and
   `PowerShellDecoder` against carved regions. On successful extraction: C2 host/URI, UserAgent,
   HostHeader (domain fronting), SpawnTo process, PipeName (SMB), KillDate.

6. **Persistence hunt.** SpawnTo and PipeName drive a targeted search of registry Run keys,
   scheduled tasks, and named pipes — not a generic sweep.

7. **Blackhole C2 IP.** Once config is extracted and beacon confirmed, outbound to the C2 IP is
   blocked via `netsh advfirewall`. All families supported: CobaltStrike, Sliver, Havoc, BruteRatel,
   AsyncRAT, Meterpreter, generic periodic beacons, and long-dwell APT implants.

8. **Evidence log.** Every event — CONNECTION, BEACON_DETECTED, CARVE_COMPLETE, BLACKHOLE_APPLIED,
   MONITOR_STOPPED — is appended to `egress_evidence.jsonl`. Call `-Collect` to review.

**Retrieve results after window:**
```powershell
Start-EgressMonitor.ps1 -Collect -IncidentId <id>
Start-EgressMonitor.ps1 -Status  -IncidentId <id>
```
Carved regions and mwcp output are in `%ProgramData%\IRToolkit\egress-<id>\carved_<proc>_<pid>\`.
**If the beacon config was not extracted** (beacon was sleeping with Ekko XOR at all capture moments):
carved regions are preserved for offline RE. See `planning/cs-config-capture-strategies.md`
for approaches including on-disk stager scan, YARA-triggered carve, and ETW-triggered capture.

---

### New memory module findings (Modules 20–22)

These modules were added alongside the core 19-module engine. They run after YARA and appear in the
same `Memory_Findings_*.json` output file.

**Module 20 — Direct Syscall Execution (T1055.004)**

`High` finding: thread in a private anonymous executable VAD outside ntdll contains 3+ `syscall`
opcode bytes (`0x0F 0x05`). This is the Hell's Gate / Halo's Gate / SysWhispers pattern — shellcode
issues system calls directly to bypass user-mode API hooks installed by EDR sensors.

*Corroboration required:* JIT-compiled processes (pwsh.exe, dotnet, CrossDeviceService) legitimately
emit syscall opcodes in CLR-compiled code. The module already excludes `JIT_HEAVY_PROCS`. For any
remaining hit outside a JIT host, corroborate with Module 3 (anonymous exec VAD in the same PID)
and Module 12 (ntdll stub integrity). Three signals converging = confirmed hook evasion.

**Module 21 — Process Ghosting / Deleted Image (T1055.015)**

`High` finding: a file-backed executable VAD whose backing file no longer exists on disk at snapshot
time. The attacker used `NtCreateUserProcess` with `FILE_DELETE_ON_CLOSE` — the PE was mapped into
memory then the on-disk file was deleted before any AV scanner could see it. The process runs from
memory only.

*Action:* carve the VAD immediately (Section 10 of the follow-on guide). The carved `.bin` is the
**only copy of that binary** — once the process exits, it is gone. Tag as a priority RE artifact.

**Module 22 — ETW-TI Provider Health (T1562.006)**

`Critical` finding when the `Microsoft-Windows-Threat-Intelligence` ETW provider (GUID
`F4E1897C-BB5D-5668-F1D8-040F4D8DD344`) is absent or disabled. This provider is the kernel
telemetry channel that feeds most EDR sensors with process-create, memory-write, and thread-create
events. An attacker who removes it **blinds all EDR sensors simultaneously** — a high-sophistication
defensive evasion technique requiring kernel-level access.

*Immediate response:* isolate and escalate. A host where this provider was deliberately disabled is
likely under active kernel-level control. Standard user-mode memory analysis is insufficient — treat
as a potential rootkit scenario and consider re-imaging.

---

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

1. **Corroborate** each indicator in OSINT services (spoofed User-Agent, beacon URIs, and mutex
   names are all searchable in urlscan / VirusTotal / OTX / Shodan). Promote an `unverified` host
   only once OSINT backs it. For mutex names, submit the bare hex token and any family strings from
   the enrichment output to identify the implant family.

2. **Verify IOCs against the binary** — if `Build-OfflineToolkit.ps1 -IncludeMWCP` was run, check
   `Memory_Enrichment.md` for:
   - **`mwcp CONFIRMED mutexes`** — the binary parser independently extracted these names from the
     compiled binary, not just from runtime handles. Include in incident report with `[mwcp-confirmed]`.
   - **`mwcp VERIFIED IOCs`** — IPs/domains found by both the memory sweep and the binary parser.
     Two independent extraction methods agreeing = highest confidence; these go to the block list first.
   - **`mwcp NEW C2`** — indicators found only in the binary config, not in the memory sweep.
     Promote immediately to the IOC blocking list — these may be backup C2 channels not yet contacted.

3. **File scan + mwcp** — if the EDR file hunt (`-ScanFileless`) flagged suspicious executables
   on disk, run mwcp against those files. A flagged on-disk file whose mwcp output matches the
   enrichment's mutex or C2 footprint closes the chain: memory implant → dropper on disk → binary
   config extraction. This is the strongest possible corroboration — all three detection layers
   (memory handles, binary parsing, on-disk scanning) converge on the same indicators.

4. **Behavior-based corroboration** — cross-reference the EDR cmdline scan output with what the
   enrichment found:
   - `VSS Deletion` or `Recovery Disable` during the same session as a confirmed memory implant = the
     attacker is in the impact phase; escalate and contain immediately
   - `Archive Staging` to a path where enrichment found file-drop handles = exfil in progress
   - `DoH Beacon` on a non-browser process = C2 hiding from DNS logs; only the memory IOC sweep
     recovered the real destination
   - `AppCertDLLs Injection` or `Accessibility Feature Hijack` alongside a confirmed memory implant =
     the attacker has installed boot-persistent foothold; document for the eradication plan

5. **Act** - feed the confirmed set into `IOCs.json` for egress blocking and `Invoke-Eradication.ps1`
   (analyst-gated, dry-run first). For deep RE, open carved regions from `tools\binja\data\` in the
   isolated Binary Ninja container.

6. **Report** - Preserve the memory image, the IOC list, and all generated reports as evidence.
   `Timeline_Correlation.md` and its Mermaid attack chain diagram are ready to embed directly in any
   incident report as the attack chronology visualization.

---

*The platform workflows gather and enrich the evidence; this guide is the analyst's reasoning that
turns it into the chain of events. Start at Step 1 with the enrichment output already in hand.*
