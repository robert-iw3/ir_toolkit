# Windows Threat Hunting & Forensics Toolkit

A self-contained set of PowerShell and Python tools for endpoint threat hunting,
forensic collection, and incident adjudication on Windows hosts. Every detection
emits findings in one canonical schema — `Timestamp / Severity / Type / Target /
Details / MITRE` — so output from any script flows into the same adjudication and
reporting pipeline.

Design intent: **forensic visibility first, behavior-based detection, downgrade not exclude.**
The tools look at mechanisms and tactics — not tool names or vendor strings — then use
severity tiers and context to keep signal-to-noise high. Run from an **elevated** prompt;
most collectors also support **offline** mode against mounted hives / captured images.

---

## The workflow

```
  1. HUNT                2. COLLECT DEPTH        3. ADJUDICATE          4. REPORT
  EDR_Toolkit.ps1        Get-Persistence...      Get-FindingContext     Analyze-EDRReport
  (+ memory image)       Get-RemoteAccess...     (TP vs FP, hard        (fleet baseline,
                         Get-USBDeviceHistory    evidence per finding)  SIEM export)
                         Invoke-*Parser
                         Analyze-Memory
                         memory_enrich.py
                         (+ mwcp file scan)
```

---

## Scripts

### Primary hunter
| Script | Purpose |
| :--- | :--- |
| **EDR_Toolkit.ps1** | The main live-host hunter. Detects hidden processes, LOLBin execution (behavior-based: staging paths + LOLBin names), reflective DLL injection, fileless persistence (WMI / Run keys / IFEO / AppCertDLLs / AppInit / Active Setup / Port Monitor / COM hijack / Accessibility feature hijack), BYOVD drivers, scheduled-task abuse, ETW/AMSI tampering, PendingFileRename (MoveEDR), BITS jobs (behavior-only, no name/CDN allowlists), suspicious network connections/listeners/named pipes (GUID structural detection), DoH beacons, SMTP exfiltration, FTP/SCP raw transfer, WSL execution, VSS deletion, recovery disable (bcdedit), archive staging, credential hive dumps, credential vault enumeration, browser credential access, and on-disk evasion (entropy, timestomping, ADS, magic-byte/extension mismatch). Optional DC3-MWCP pass (`-ScanMWCP`) extracts malware config from flagged files. Maps every hit to MITRE ATT&CK and exports CSV / JSON / HTML. See **Hunt modules** below. |

### Adjudication & reporting
| Script | Purpose |
| :--- | :--- |
| **Get-FindingContext.ps1** | Wave 2. For every base finding it resolves the concrete artifact behind it (PID → live process + parent + egress, CLSID → registry server, path/name → on-disk file) and proves True vs False Positive with SHA256, Authenticode signer, path trust, and version info. It does not guess from names. |
| **Analyze-EDRReport.ps1** | Fleet analysis. Ingests JSON reports from many endpoints, applies a universal Windows baseline to strip OS noise, and exports clean actionable alerts for SIEM. |

### Depth collectors (live or offline)
| Script | Purpose |
| :--- | :--- |
| **Get-PersistenceSnapshot.ps1** | Pure-PowerShell persistence-breadth + security-tamper snapshot using only built-in binaries. Covers IFEO, Winlogon, AppInit/AppCert, LSA packages, BootExecute, netsh helpers, Active Setup, all-user Run keys; flags WDigest cleartext, LSASS PPL off, UAC/Defender/PS-logging disabled. Stages raw evidence (`.evtx`, task XML, firewall, audit policy) for the parsers below. |
| **Get-RemoteAccessTriage.ps1** | Targets interactive-remote-control compromise: RMM/remote-access tooling, ClickFix / fake-update lures, browser artifacts, and active sessions. |
| **Get-USBDeviceHistory.ps1** | Read-only removable-media timeline. Reconstructs every USB-storage device ever connected (vendor/serial/label, first/last-connect, removal) and correlates against an infection time to identify the entry-vector device. |

### Artifact parsers (consume collector output)
| Script | Purpose |
| :--- | :--- |
| **Invoke-AmcacheParser.ps1** | Turns Amcache / ShimCache execution evidence into findings (ran from user-writable/suspicious/network paths, LOLBin names outside System32, unsigned non-Microsoft binaries). |
| **Invoke-EventLogAnalysis.ps1** | Turns collected event-log CSVs into findings (4688 process creation, 4625 brute force, 4648 explicit creds, 4698/4702 tasks, 4720 account create, 1102 log cleared, 7045 services, 4104 PS script block, 4656/4663 LSASS access, 4624 RDP logon). |

### Memory analysis
| Script / Module | Purpose |
| :--- | :--- |
| **Analyze-Memory.ps1** | Orchestrator. Runs offline memory analysis on a captured `.raw` / `.mem` / `.aff4` image on the **analyst** machine and emits findings in the canonical schema. |
| **memory_forensic.py** | Core engine (MemProcFS vmmpyc API). 22-module detection pipeline. See **Memory detection modules** table below. |
| **memory_yara.py / memory_yara_worker.py** | YARA scan of process memory. Worker runs as an isolated subprocess with crash isolation; DOS-stub canary rule verifies the engine actually inspected memory. Filters non-Windows rules and strips non-ASCII before compilation (`yarac64`). |
| **memory_enrich.py** | Per-true-positive footprint extractor: handles (dropped files, persistence, mutexes, pipes), C2 endpoints with offline geo, process lineage, carved injected regions, capa capability fingerprint, FLOSS deobfuscated strings, and **DC3-MWCP binary config extraction** (mutexes, C2, credentials from carved regions). Produces `Memory_Enrichment.md`, updated `IOCs.json`, `Timeline_Correlation.md` (attack chain by ATT&CK phase), and `Attack_Graph.md`. |
| **vad_query.py** | One-shot vmmpyc VAD lookup: resolves a thread start address to its VAD type (`anon_exec`/`image`/`unmapped`) for Module 5 triage without re-running the full analysis. |

#### Memory detection modules

| # | Module | Detection | MITRE |
|:--|:-------|:----------|:------|
| 1 | LOLBin cmdlines | Encoded commands, IEX, WebClient downloads, `-WindowStyle Hidden` | T1059.001, T1027 |
| 2 | Hidden processes | DKOM / PEB-unlink artifacts via vmmpyc state field | T1014, T1055 |
| 3 | Injected memory | Private executable VAD (no backing image); per-process cap prevents JIT hosts from crowding out real injection findings; cap-hit emits visible Medium finding | T1055, T1055.012 |
| 4 | External network | Established / listening connections to non-RFC1918 IPs | T1071, T1021 |
| 5 | Shellcode threads | Thread start address classified by VAD type: `anon_exec`=High (TP), `image`=Medium (needs corroboration), `unmapped`=Low (unloaded DLL FP). Use `vad_query.py` for manual triage. | T1055.003 |
| 5b | Manual-map / stomping | MZ magic in anonymous exec region; image-backed VAD with explicit RWX protection | T1055.004, T1055.001 |
| 6 | Parent-child anomalies | High-risk children (cmd, powershell, mshta, rundll32...) from unexpected parents; includes `wsl.exe`/`bash.exe` parents (Linux-side execution evades Windows hooks) | T1059, T1204, T1202 |
| 7 | Process path spoofing | System binary running from non-System32 path | T1036.005 |
| 8 | Offensive tooling | Mimikatz, Cobalt Strike, Metasploit, BloodHound, PsExec patterns | T1588, T1059 |
| 9 | Suspicious listeners | User processes listening on ports ≥ 1024 on non-loopback interfaces | T1071, T1571 |
| 10 | Kernel drivers | BYOVD-class driver names (RTCore64, WinRing0, cpuz, GDRV...) | T1068, T1543.003 |
| 11 | Registry Run persistence | Staging-area paths (High) and non-standard-directory paths (Medium) in live HKLM/HKCU Run keys — not LOLBin-names-only | T1547.001 |
| 12 | ntdll stub integrity | Syscall stubs where the `mov r10,rcx` preamble is replaced with jump/hook (SysWhispers, HellsGate, EDR hook bypass) | T1106, T1562, T1055 |
| 13 | Dormant beacon / W^X | High-entropy private RW regions — sleep-masked beacon at rest. Reports CV%, adjacent exec presence, MZ remnant, head-bytes | T1027, T1055, T1027.013 |
| 14 | Thread-pool / Ekko | ntdll thread-pool workers co-located with a High-severity beacon region (Ekko / Foliage sleep-obfuscation pattern) | T1055.004, T1106 |
| 15 | PEB cmdline pointer | `PEB.ProcessParameters→CommandLine.Buffer` falls outside all mapped VADs (Argue-style post-launch PEB tamper) | T1055.012, T1036 |
| 16 | CLR execute-assembly | ECMA-335 `BSJB` CLI metadata signature in private exec region of a non-managed host (Donut / execute-assembly) | T1620, T1055 |
| 17 | PPID orphan / spoof | Parent PID absent from process list, or forged via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` | T1134.004, T1134 |
| 18 | COM VTable hijacking | Image-backed data section with pointers resolving into anonymous executable regions | T1574, T1055 |
| 19 | YARA memory scan | Staged rule sets scanned per-process in a crash-isolated subprocess; canary rule verifies scanner actually read process memory | T1055, T1027 |
| 20 | Direct syscall execution | `syscall` opcode (`0x0F 0x05`) at density ≥ 3 in private exec VAD outside ntdll — Hell's Gate / SysWhispers hook evasion. JIT hosts excluded. | T1055.004 |
| 21 | Process ghosting | Image-backed executable VAD whose backing file no longer exists on disk — `NtCreateUserProcess` + `FILE_DELETE_ON_CLOSE` | T1055.015 |
| 22 | ETW-TI health check | `Microsoft-Windows-Threat-Intelligence` provider (GUID `F4E1897C-...`) absent or disabled — EDR sensor blinding | T1562.006 |

> **Note on Module 3 cap:** the global 30-region cap was replaced with a per-process cap
> (5 for non-JIT, 30 for JIT hosts). When a process hits its cap, a Medium `Injected Memory
> Cap Reached` finding is emitted — the analyst knows more regions exist and can re-run with
> a raised cap. The old silent log-warning is gone.

> Memory tooling requires staged binaries — see the header of `Analyze-Memory.ps1` for
> `Build-OfflineToolkit.ps1` staging flags.

---

## Usage

Run the hunter from an **elevated (Administrator)** PowerShell prompt.

**1. Full memory + fileless scan (fast — no disk crawl)**
```powershell
.\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers `
    -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename `
    -ScanBITS -ScanCOM -ScanNetwork
```

**2. Deep target-directory scan with YARA + mwcp config extraction**
```powershell
# Requires -IncludeYaraRules and -IncludeMWCP staging
.\EDR_Toolkit.ps1 -TargetDirectory "C:\" -Recursive -ScanADS -QuickMode `
    -ScanYara -ScanMWCP -SeverityFilter Critical,High
```
> YARA rules are compiled without BOM (PS 5.1 compatible) and pre-filtered to strip
> non-ASCII rule files that break yara64.exe.

**3. Silent WinRM deployment (JSON for SIEM)**
```powershell
Invoke-Command -ComputerName SRV-WEB-01 -FilePath ".\EDR_Toolkit.ps1" `
    -ArgumentList @("-ScanProcesses","-ScanFileless","-Quiet","-OutputFormat","JSON")
```

---

## EDR_Toolkit.ps1 parameters

### Hunt modules
| Parameter | Detects |
| :--- | :--- |
| `-ScanProcesses` | Hidden processes (API vs WMI), behavior-based LOLBin cmdlines (encoded PS, staging-area paths, Squiblydoo, msiexec remote MSI, wmic process-create, installutil/cmstp/odbcconf), VSS deletion, bcdedit recovery disable, archive staging, WSL execution/parent-spawn, credential hive dumps (reg save SAM/SECURITY), credential vault enumeration (cmdkey/vaultcmd), browser credential access (non-browser process accessing Chrome/Firefox profile paths), DoH beacons (non-browser HTTPS to known DoH resolver IPs), SMTP exfiltration (non-mail process on port 25/587), FTP/SCP raw transfer. |
| `-ScanInjection` | Reflective DLLs and foreign modules via real `Process.Modules` enumeration (module-not-on-disk, unsigned DLL outside Windows paths). |
| `-ScanFileless` | WMI event subscriptions (filter/consumer/binding correlation), Run/RunOnce (LOLBin + staging-path + non-standard-dir), Winlogon, BootExecute, AppCertDLLs, Active Setup StubPath, startup folders, LSA packages, browser credential file staging, Accessibility feature IFEO hijack, port monitor DLL (non-system32), unquoted service paths. |
| `-ScanRegistry` | IFEO debuggers (all binaries; accessibility binaries = Critical), AppInit_DLLs, IFEO GlobalFlag, suspicious Services (staging paths + LOLBin), unquoted service paths. |
| `-ScanTasks` | Scheduled tasks: binary-not-on-disk, SYSTEM task with user-writable binary, UNC execution, LOLBin actions. |
| `-ScanDrivers` | Loaded kernel drivers vs BYOVD list by **SHA256 hash** (rename-resistant) and name; path-aware unsigned check. |
| `-ScanBITS` | Suspicious BITS jobs by **behavior** only (staging-area destination = High; executable URL without staging = Medium). Display name and CDN hostname are NOT used as allowlists — both are attacker-controlled. |
| `-ScanCOM` | COM hijacking via `CLSID\InProcServer32`. |
| `-ScanETWAMSI` | Disabled ETW channels, weaponized log rotation, WER disabled, AMSI tampering. |
| `-ScanPendingRename` | `PendingFileRenameOperations` targeting security tools (MoveEDR-style delete-on-reboot). |
| `-ScanNetwork` | Non-browser outbound HTTPS to DoH resolver IPs (DoH beacon), non-mail SMTP connections (exfil), trusted outbound procs **downgraded** not skipped, GUID-format named pipes (structural C2 detection), unexpected listeners. |

### File scanning
| Parameter | Description |
| :--- | :--- |
| `-TargetDirectory <Path>` | Root for file-based hunts (entropy, timestomping, magic-byte mismatch). |
| `-Recursive` | Crawl all subdirectories. |
| `-ScanADS` | Hunt NTFS Alternate Data Streams. |
| `-ScanYara` | YARA signature scan against flagged files. Rules pre-filtered: non-ASCII files stripped (PS 5.1 / yara64 compatibility), Linux/macOS/abusech rules excluded, canary self-test validates engine. Requires `-IncludeYaraRules` staging. |
| `-ScanMWCP` | **DC3-MWCP malware config extraction** against High/Critical flagged files. Runs after YARA. GenericMutex + GenericC2 parsers cover all families; family-specific parsers extract full config when the family is known. Results roll into EDR report as `mwcp Config Extraction` findings. Requires `-IncludeMWCP` staging. Uses bundled MemProcFS Python (no system Python dependency). |
| `-QuickMode` | Restrict to recently-touched files (default 90 days). |
| `-QuickModeDaysBack <N>` | QuickMode recency window (default 90). |

### Global & filtering
| Parameter | Description |
| :--- | :--- |
| `-AutoUpdateDrivers` | Fetch the latest vulnerable-driver list from `loldrivers.io`. |
| `-ReportPath <Path>` | Output directory (default: current dir). |
| `-ExcludePaths <String[]>` | Folders to skip during disk scans. |
| `-SeverityFilter <String[]>` | Restrict output, e.g. `Critical,High`. |
| `-OutputFormat <String[]>` | `All` \| `JSON` \| `CSV` \| `HTML`. |
| `-Quiet` | Suppress console output and progress bars. |
| `-TestMode` | Inject simulated findings to validate SIEM ingestion. |

Output is a timestamped report package plus a Top-10 findings summary on the console.

---

## Detection design principles

All detections follow the same rules:

1. **Detect mechanisms, not tool names.** Staging-path destination is the BITS signal — not the job display name. Browser profile directory access is the credential-theft signal — not a specific filename.
2. **Downgrade not exclude.** Trusted outbound processes (Teams, OneDrive) are downgraded one severity tier, not skipped — C2 injected into them must still be visible.
3. **Hardcoded strings only when that string IS the attack mechanism.** `autocheck autochk *` is the only legitimate BootExecute value. `AppCertDLLs` registry key presence is always an attack signal. WilStaging-format mutex names are APT camouflage — flag them.
4. **No scope cuts for performance.** The per-process anonymous exec cap (5 non-JIT, 30 JIT) replaces the old global 30 cap. A cap-hit produces a visible finding, not a silent log line.

---

## Known operational notes

- **Named-pipe enumeration:** the toolkit's `Get-NamedPipeName` uses `FindFirstFile`/`FindNextFile` (safe). Do NOT substitute `Get-ChildItem \\.\pipe\` — the PS provider opens each pipe for metadata and can wedge core networking service RPC endpoints, taking DNS and TCP offline. If connectivity drops after a collection run, use `planning\Repair-NetworkStack-Win11.ps1` (elevated).
- **Memory analysis requires MemProcFS Python 3.12 embeddable** (staged via `-IncludeMemProcFS`). The bundled Python is at `tools/memprocfs/python/python.exe` and is also used by `-IncludeMWCP` file scan — no system Python installation required.
- **YARA rule compilation:** rules are written without BOM (PS 5.1 compatible) and pre-screened to strip non-ASCII source files before compilation. The self-test canary confirms the engine matched before any results are trusted.

---

## Development

Active development lives in **`dev/`** — `dev/src/` holds the numbered modules,
`dev/Build-Toolkit.ps1` concatenates them into the deployable `EDR_Toolkit.ps1`
(and `dev/Release/EDR_Toolkit_Deploy.ps1`). Pester tests live in `test/windows/`.
**Edit `dev/src/`, not the compiled output**, then rebuild and re-run the tests.

Test workflow:
```powershell
cd dev
pwsh -Command "Invoke-Pester ..\..\..\test\windows\ -Output Minimal"
pwsh -File .\Build-Toolkit.ps1
```
