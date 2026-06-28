# Windows Threat Hunting & Forensics Toolkit

A self-contained set of PowerShell and Python tools for endpoint threat hunting,
forensic collection, and incident adjudication on Windows hosts. Every detection
emits findings in one canonical schema — `Timestamp / Severity / Type / Target /
Details / MITRE` — so output from any script flows into the same adjudication and
reporting pipeline.

Design intent: **forensic visibility first.** The tools look at everything an
analyst would need, then use severity tiers and context (not scope cuts) to keep
the signal-to-noise ratio high. Run from an **elevated** prompt; most collectors
also support an **offline** mode against mounted hives / captured images.

---

## The workflow

```
  1. HUNT            2. COLLECT DEPTH        3. ADJUDICATE          4. REPORT
  EDR_Toolkit.ps1    Get-Persistence...      Get-FindingContext     Analyze-EDRReport
  (+ memory image)   Get-RemoteAccess...     (TP vs FP, hard        (fleet baseline,
                     Get-USBDeviceHistory    evidence per finding)  SIEM export)
                     Invoke-*Parser
                     Analyze-Memory
```

---

## Scripts

### Primary hunter
| Script | Purpose |
| :--- | :--- |
| **EDR_Toolkit.ps1** | The main live-host hunter. Detects hidden processes, LOLBin execution, reflective DLL injection, fileless persistence (WMI / Run keys / IFEO / AppInit / COM hijack), BYOVD drivers, scheduled-task abuse, ETW/AMSI tampering, PendingFileRename (MoveEDR), BITS jobs, suspicious network connections/listeners/named pipes, and on-disk evasion (entropy, timestomping, ADS, magic-byte/extension mismatch). Maps every hit to MITRE ATT&CK and exports CSV / JSON / HTML. See **Hunt modules** below. |

### Adjudication & reporting
| Script | Purpose |
| :--- | :--- |
| **Get-FindingContext.ps1** | Wave 2. For every base finding it resolves the concrete artifact behind it (PID → live process + parent + egress, CLSID → registry server, path/name → on-disk file) and proves True vs False Positive with SHA256, Authenticode signer, path trust, and version info. It does not guess from names. |
| **Analyze-EDRReport.ps1** | Fleet analysis. Ingests JSON reports from many endpoints, applies a universal Windows baseline to strip OS noise, and exports clean actionable alerts for SIEM. |

### Depth collectors (live or offline)
| Script | Purpose |
| :--- | :--- |
| **Get-PersistenceSnapshot.ps1** | Pure-PowerShell persistence-breadth + security-tamper snapshot using only built-in binaries (runs on a fully isolated host). Covers IFEO, Winlogon, AppInit/AppCert, LSA packages, BootExecute, netsh helpers, Active Setup, all-user Run keys; flags WDigest cleartext, LSASS PPL off, UAC/Defender/PS-logging disabled. Also stages raw evidence (`.evtx`, task XML, firewall, audit policy) for the parsers below. |
| **Get-RemoteAccessTriage.ps1** | Targets interactive-remote-control compromise: RMM/remote-access tooling, ClickFix / fake-update lures, browser artifacts, and active sessions — the gap that process/persistence hunts miss. |
| **Get-USBDeviceHistory.ps1** | Read-only removable-media timeline. Reconstructs every USB-storage device ever connected (vendor/serial/label, first/last-connect, removal) and correlates against an infection time or payload first-run to identify the entry-vector device. |

### Artifact parsers (consume collector output)
| Script | Purpose |
| :--- | :--- |
| **Invoke-AmcacheParser.ps1** | Turns Amcache / ShimCache execution evidence into findings (ran from user-writable/suspicious/network paths, LOLBin names outside System32, unsigned non-Microsoft binaries). |
| **Invoke-EventLogAnalysis.ps1** | Turns collected event-log CSVs into findings (4688 process creation, 4625 brute force, 4648 explicit creds, 4698/4702 tasks, 4720 account create, 1102 log cleared, 7045 services, 4104 PS script block, 4656/4663 LSASS access, 4624 RDP logon). |

### Memory analysis
| Script | Purpose |
| :--- | :--- |
| **Analyze-Memory.ps1** | Orchestrator. Runs offline memory analysis on a captured `.raw` / `.mem` / `.aff4` image on the **analyst** machine and emits findings in the canonical schema. |
| **memory_forensic.py** | Core engine (MemProcFS API). 19-module detection pipeline spanning live-host and sleep-masked TTPs. See **Memory detection modules** table below. |
| **memory_yara.py / memory_yara_worker.py** | YARA scan of process memory. The worker runs as an isolated subprocess so a native scanner crash on a pathological process cannot kill the analysis; a DOS-stub canary rule verifies the engine actually inspected memory. |
| **memory_enrich.py** | Per-true-positive footprint extractor for eradication scope: handles (dropped files, persistence, mutexes, pipes), modules, C2 endpoints, process lineage, and the carved injected region with recovered IOCs. |

#### Memory detection modules

| # | Module | Detection | MITRE |
|:--|:-------|:----------|:------|
| 1 | LOLBin cmdlines | Encoded commands, IEX, WebClient downloads, `-WindowStyle Hidden` | T1059.001, T1027 |
| 2 | Hidden processes | DKOM / PEB-unlink artifacts via vmmpyc state field | T1014, T1055 |
| 3 | Injected memory | Private executable VAD (no backing image); PE hollowing (zeroed TimeDateStamp / CheckSum / SizeOfImage) | T1055, T1055.012 |
| 4 | External network | Established / listening connections to non-RFC1918 IPs | T1071, T1021 |
| 5 | Shellcode threads | User-mode threads with start address outside all loaded modules; JIT-host threads annotated for corroboration (attack surface overlaps with JMP-AMSI / reflective injection) | T1055.003 |
| 5b | Manual-map / stomping | MZ magic in anonymous exec region; image-backed VAD with explicit RWX protection | T1055.004, T1055.001 |
| 6 | Parent-child anomalies | High-risk children (cmd, powershell, mshta, rundll32...) from unexpected parents | T1059, T1204 |
| 7 | Process path spoofing | System binary running from non-System32 path | T1036.005 |
| 8 | Offensive tooling | Mimikatz, Cobalt Strike, Metasploit, BloodHound, PsExec patterns | T1588, T1059 |
| 9 | Suspicious listeners | User processes listening on ports ≥ 1024 on non-loopback interfaces | T1071, T1571 |
| 10 | Kernel drivers | BYOVD-class driver names (RTCore64, WinRing0, cpuz, GDRV...) | T1068, T1543.003 |
| 11 | Registry Run persistence | LOLBin commands in live HKLM/HKCU Run keys | T1547.001 |
| 12 | ntdll stub integrity | Syscall stubs where the `mov r10,rcx` preamble is replaced with a jump/hook (SysWhispers, HellsGate, EDR hook bypass) | T1106, T1562, T1055 |
| 13 | Dormant beacon / W^X | High-entropy private RW regions — the hallmark of a sleep-masked beacon at rest. Reports byte-distribution CV%, adjacent exec presence, MZ remnant, and first-16-byte hex for triage | T1027, T1055, T1027.013 |
| 14 | Thread-pool / Ekko | ntdll thread-pool workers in a process that also has a High-severity beacon region — the Ekko / Foliage sleep-obfuscation pattern | T1055.004, T1106 |
| 15 | PEB cmdline pointer | `PEB.ProcessParameters→CommandLine.Buffer` falls outside all mapped VADs — Argue-style post-launch PEB tamper | T1055.012, T1036 |
| 16 | CLR execute-assembly | ECMA-335 `BSJB` CLI metadata signature in private exec region of a non-managed host process (Donut / execute-assembly) | T1620, T1055 |
| 17 | PPID orphan / spoof | Parent PID absent from process list, or parent timestamp later than child (forged via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) | T1134.004, T1134 |
| 18 | COM VTable hijacking | Image-backed data section containing pointer(s) that resolve into anonymous executable region(s) | T1574, T1055 |
| 19 | YARA memory scan | Staged rule sets scanned per-process in a crash-isolated subprocess; canary rule verifies scanner actually read process memory | T1055, T1027 |

> Memory tooling requires staged binaries (MemProcFS / YARA) — see the
> header of `Analyze-Memory.ps1` for `Build-OfflineToolkit.ps1` staging flags.

---

## Usage

Run the hunter from an **elevated (Administrator)** PowerShell prompt.

**1. Full memory + fileless scan (fast — no disk crawl)**
```powershell
.\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM -ScanNetwork
```

**2. Deep target-directory scan (file evasion, High/Critical only)**
```powershell
.\EDR_Toolkit.ps1 -TargetDirectory "C:\" -Recursive -ScanADS -QuickMode -SeverityFilter Critical,High
```
> Calling with `-SeverityFilter` as an array requires the call operator (`& .\EDR_Toolkit.ps1 ...`)
> or dot-sourcing — not `pwsh -File`, which passes `Critical,High` as one string.

**3. Silent WinRM deployment (JSON for SIEM)**
```powershell
Invoke-Command -ComputerName SRV-WEB-01 -FilePath ".\EDR_Toolkit.ps1" -ArgumentList @("-ScanProcesses","-ScanFileless","-Quiet","-OutputFormat","JSON")
```

---

## EDR_Toolkit.ps1 parameters

### Hunt modules
| Parameter | Detects |
| :--- | :--- |
| `-ScanProcesses` | Hidden processes (API vs WMI), unusual parents, LOLBin command lines (encoded PS, Squiblydoo, msiexec remote MSI, wmic process-create, installutil/cmstp/odbcconf). |
| `-ScanInjection` | Reflective DLLs and foreign modules via real `Process.Modules` enumeration (module-not-on-disk, unsigned DLL outside Windows paths). |
| `-ScanFileless` | WMI event subscriptions (filter/consumer/binding correlation), Run/RunOnce, Winlogon, BootExecute, startup folders, LSA packages. |
| `-ScanRegistry` | IFEO debuggers, AppInit_DLLs, suspicious Services. |
| `-ScanTasks` | Scheduled tasks: binary-not-on-disk, SYSTEM task with user-writable binary, UNC execution, LOLBin actions. |
| `-ScanDrivers` | Loaded kernel drivers vs BYOVD list by **SHA256 hash** (rename-resistant) and name; path-aware unsigned check. |
| `-ScanBITS` | Suspicious BITS jobs by display name, source URL (non-CDN/IP), and destination path. |
| `-ScanCOM` | COM hijacking via `CLSID\InProcServer32`. |
| `-ScanETWAMSI` | Disabled ETW channels, weaponized log rotation (tiny max-size), WER disabled, AMSI tampering. |
| `-ScanPendingRename` | `PendingFileRenameOperations` targeting security tools (MoveEDR-style delete-on-reboot). |
| `-ScanNetwork` | Outbound connections to public IPs on non-standard ports, unexpected listeners, C2-pattern named pipes. |

### File scanning
| Parameter | Description |
| :--- | :--- |
| `-TargetDirectory <Path>` | Root for file-based hunts (entropy, timestomping, magic-byte mismatch). |
| `-Recursive` | Crawl all subdirectories. |
| `-ScanADS` | Hunt NTFS Alternate Data Streams. |
| `-QuickMode` | Recommended for disk scans: restricts to recently-touched files (full depth, faster). |
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

## Development

Active development lives in **`dev/`** — `dev/src/` holds the numbered modules,
`dev/Build-Toolkit.ps1` concatenates them into the deployable `EDR_Toolkit.ps1`
(and `dev/Release/EDR_Toolkit_Deploy.ps1`). Pester tests live in `test/windows/`.
**Edit `dev/src/`, not the compiled output**, then rebuild and re-run the tests.
