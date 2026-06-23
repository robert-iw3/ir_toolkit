<#
.SYNOPSIS
    PowerShell EDR Toolkit - Fileless & Evasion Hunting
.DESCRIPTION
    Full-spectrum hunt for hidden processes, fileless persistence (WMI, Registry, Tasks, BITS, COM),
    injection, BYOVD, ETW/AMSI tampering, PendingFileRenameOperations, ADS, timestomping, and more.
    Exports structured findings (CSV + styled HTML + JSON) with MITRE ATT&CK mappings.
    Includes -QuickMode (ultra-fast scan) and optional -AutoUpdateDrivers (live pull from loldrivers.io).
    Multi-threaded file hunts with smart exclusions and hashtable caching.
.PARAMETER ScanProcesses
    Hidden processes, unusual parents, suspicious command lines, LOLBins.
.PARAMETER ScanFileless
    Classic WMI + Run keys.
.PARAMETER ScanTasks
    Suspicious Scheduled Tasks.
.PARAMETER ScanDrivers
    Loaded drivers + known vulnerable (BYOVD).
.PARAMETER ScanInjection
    Reflective DLLs, foreign modules, process hollowing indicators.
.PARAMETER ScanADS
    NTFS Alternate Data Streams.
.PARAMETER ScanRegistry
    Expanded registry persistence (IFEO, AppInit_DLLs, Services).
.PARAMETER ScanETWAMSI
    ETW Autologger + AMSI tampering.
.PARAMETER ScanPendingRename
    PendingFileRenameOperations (MoveEDR-style EDR kill).
.PARAMETER ScanBITS
    BITS jobs (modern fileless persistence).
.PARAMETER ScanCOM
    COM hijacking (CLSID InProcServer32).
.PARAMETER TargetDirectory
    Directory for file-based hunts (entropy, cloaking, ADS, timestomping).
.PARAMETER Recursive
    Recursive file scan.
.PARAMETER QuickMode
    Ultra-fast scan: smaller entropy sample + skips large-file checks.
.PARAMETER AutoUpdateDrivers
    Fetch the latest vulnerable driver list from loldrivers.io API.
.PARAMETER ReportPath
    Output directory (default: current working directory).
.PARAMETER ExcludePaths
    Array of specific folder paths to skip during file enumeration.
.PARAMETER SeverityFilter
    Only report findings matching these severities (Critical, High, Medium, Low).
.PARAMETER OutputFormat
    Specific report formats to generate (All, CSV, JSON, HTML).
.PARAMETER Quiet
    Suppress all console output except for critical errors and the final summary.
.PARAMETER TestMode
    Injects dummy findings to validate SIEM ingestion and reporting pipelines.
.NOTES
    Author: Robert Weber
.EXAMPLE

    Usage:

    .\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM -TargetDirectory "C:\" -Recursive -ScanADS -QuickMode -AutoUpdateDrivers

    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Path\To\EDR_Toolkit.ps1" -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM -TargetDirectory "C:\" -Recursive -ScanADS -QuickMode -AutoUpdateDrivers

    Cancelling:

    # Immediate memory cleanup
    $filesToScan = $null
    $queue = $null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Write-Host "Memory cleanup completed." -ForegroundColor Green
#>

[CmdletBinding()]
param (
    [Switch]$ScanProcesses,
    [Switch]$ScanFileless,
    [Switch]$ScanTasks,
    [Switch]$ScanDrivers,
    [Switch]$ScanInjection,
    [Switch]$ScanADS,
    [Switch]$ScanRegistry,
    [Switch]$ScanETWAMSI,
    [Switch]$ScanPendingRename,
    [Switch]$ScanBITS,
    [Switch]$ScanCOM,
    [Switch]$ScanYara,
    [String]$YaraRulesDir,
    [String]$TargetDirectory,
    [Switch]$Recursive,
    [Switch]$QuickMode,
    [int]$QuickModeDaysBack = 90,
    [Switch]$AutoUpdateDrivers,
    [String]$ReportPath = $PWD.Path,
    [String[]]$ExcludePaths = @(),
    [ValidateSet('Critical','High','Medium','Low')]
    [String[]]$SeverityFilter = @('Critical','High','Medium','Low'),
    [ValidateSet('All','CSV','JSON','HTML')]
    [String[]]$OutputFormat = @('All'),
    [Switch]$Quiet,
    [Switch]$TestMode
)

$script:Findings = @()

# Collect the PID ancestry of this EDR process so we can skip our own spawned
# child processes (powershell.exe -Bypass -File EDR_Toolkit.ps1 and its parents).
# Without this, the LOLBin scorer flags the toolkit's own command line.
$script:SelfPids = [System.Collections.Generic.HashSet[int]]::new()
try {
    $selfPid = $PID
    $procMap = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.ProcessId] = $_ }
    $walk = $selfPid
    for ($depth = 0; $depth -lt 6 -and $walk; $depth++) {
        $null = $script:SelfPids.Add($walk)
        $p = $procMap[$walk]; $walk = if ($p) { [int]$p.ParentProcessId } else { 0 }
    }
    # Also skip any powershell process whose command line references toolkit script
    # paths OR known toolkit script names. The path-based check covers absolute paths;
    # the name-based check covers relative invocations (e.g. ".\Invoke-IRCollection.ps1").
    $irPaths = @($PSScriptRoot, $ReportPath) | Where-Object { $_ }
    $irScriptNames = @(
        'Invoke-IRCollection.ps1', 'EDR_Toolkit.ps1', 'EDR_Toolkit_Deploy.ps1',
        'Get-PersistenceSnapshot.ps1', 'Get-RemoteAccessTriage.ps1',
        'Get-FindingContext.ps1', 'Invoke-EventLogAnalysis.ps1',
        'Analyze-EDRReport.ps1', 'Invoke-PrepareDefender.ps1',
        'Analyze-Memory.ps1', '00_Collect-Forensics.ps1'
    )
    foreach ($p in $procMap.Values) {
        $cmd = [string]$p.CommandLine
        if (-not $cmd) { continue }
        $pathMatch = $irPaths | Where-Object { $cmd -like "*$_*" }
        $nameMatch = $irScriptNames | Where-Object { $cmd -like "*$_*" }
        if ($pathMatch -or $nameMatch) {
            $null = $script:SelfPids.Add($p.ProcessId)
        }
    }
} catch {}

$Global:MITRE = @{
    HiddenProcess    = "T1014 (Rootkit)"
    EncodedCommand   = "T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)"
    HighEntropy      = "T1027 (Obfuscated Files or Information)"
    FileCloaking     = "T1014 (Rootkit), T1564 (Hide Artifacts)"
    WMIPersistence   = "T1546.003 (WMI Event Subscription)"
    RegPersistence   = "T1547.001 (Registry Run Keys)"
    ScheduledTask    = "T1053 (Scheduled Task/Job)"
    BYOVD            = "T1562.001 (Impair Defenses) + T1542"
    ProcessInjection = "T1055 (Process Injection)"
    ADS              = "T1564.004 (Hide Artifacts: NTFS ADS)"
    COMHijack        = "T1546.015 (Event Triggered Execution: COM Hijacking)"
    ETWTampering     = "T1562.002 (Disable Windows Event Logging)"
    AMSITampering    = "T1562.001 (Impair Defenses)"
    PendingRename    = "T1562.001 (MoveEDR)"
    Timestomping     = "T1070.006 (Indicator Removal: Timestomping)"
    ServiceTamper    = "T1543.003 (Windows Service)"
    BITSJob          = "T1197 (BITS Jobs)"
    RegIFEO          = "T1546.012 (Image File Execution Options)"
    AppInitDLL       = "T1546.010 (AppInit DLLs)"
}

function Write-Console {
    param([string]$Message, [string]$Color = "Gray")
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

function Add-Finding {
    param([string]$Type, [string]$Target, [string]$Details, [string]$Severity, [string]$Mitre,
          [string]$Source = '')

    if ($Severity -notin $SeverityFilter) { return }

    # Auto-tag findings that originate from the IR Toolkit's own process tree.
    # Allows adjudicator and reports to separate toolkit activity from threat activity.
    if (-not $Source) {
        $targetPid = if ($Target -match 'PID[:\s]+(\d+)') { [int]$Matches[1] } else { 0 }
        if ($targetPid -and $script:SelfPids.Contains($targetPid)) { $Source = 'IR_Toolkit' }
    }

    $obj = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Severity  = $Severity
        Type      = $Type
        Target    = $Target
        Details   = $Details
        MITRE     = $Mitre
        Source    = $Source
    }
    $script:Findings += $obj

    if (-not $Quiet) {
        $color = if ($Severity -eq "Critical") { "Red" } elseif ($Severity -eq "High") { "DarkRed" } elseif ($Severity -eq "Medium") { "Yellow" } else { "Cyan" }
        Write-Host "[!] $Severity Finding: $Type | Target: $Target" -ForegroundColor $color
    }
}

function Invoke-ProcessHunt {
    Write-Console "[*] Hunting for Hidden & Suspicious Processes..." "Cyan"

    $apiProcs = Get-Process -ErrorAction SilentlyContinue
    $apiDict = @{}
    foreach ($p in $apiProcs) { $apiDict[$p.Id] = $p }

    $wmiProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

    # Processes that legitimately hide from the standard Get-Process API via PPL or
    # kernel-level self-protection. Flagging them creates noise with no IR value.
    $coreAllowed = @(
        # NT kernel / session management
        "System Idle Process", "System", "Secure System", "Registry", "Memory Compression",
        "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
        "LsaIso.exe", "NgcIso.exe",
        # Shell / desktop
        "fontdrvhost.exe", "WUDFHost.exe", "dwm.exe", "sihost.exe", "taskhostw.exe",
        "RuntimeBroker.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
        "ctfmon.exe", "explorer.exe", "spoolsv.exe", "svchost.exe", "conhost.exe",
        "SearchIndexer.exe", "SearchHost.exe",
        # Windows Defender / MDE - all use PPL and hide from API intentionally
        "MsMpEng.exe", "MpDefenderCoreService.exe", "NisSrv.exe", "MpCopyAccelerator.exe",
        "MpDlpService.exe", "MpDlpCmd.exe", "MpExtMs.exe", "MpCmdRun.exe",
        "MsSense.exe", "SenseCncProxy.exe", "SenseIR.exe", "MpDlp.exe",
        # Windows Security health UI
        "SecHealthUI.exe", "SecurityHealthHost.exe", "SecurityHealthSystray.exe", "SecurityHealthService.exe",
        # Sysinternals monitoring tools (Sysmon runs as PPL)
        "Sysmon.exe", "Sysmon64.exe",
        # WMI / COM - various worker and host processes
        "WmiPrvSE.exe", "WMIRegistrationService.exe", "WmiApSrv.exe",
        "dllhost.exe",          # COM surrogate - PPL-like isolation is normal
        # Windows Widgets / modern UI app isolation (Store apps use IUM/VTL)
        "WidgetService.exe", "Widgets.exe",
        "ApplicationFrameHost.exe", "WWAHost.exe",
        # Background task and package hosting
        "backgroundTaskHost.exe",
        # Windows Security biometrics / credential UI
        "WinBioPlugInHost.exe", "WinBioDataModelServer.exe",
        "CredentialEnrollmentManager.exe", "CloudExperienceHostBroker.exe",
        # Virtualization / containers
        "vmms.exe", "vmcompute.exe", "VSSVC.exe", "wslservice.exe",
        # Common hardware/vendor services (wildcards handled below)
        "NVDisplay.Container.exe", "nvcontainer.exe", "coreServiceShell.exe",
        "RtkAudUService64.exe", "esif_uf.exe", "PtSvcHost.exe",
        "DtsApo4Service.exe", "jhi_service.exe", "LMS.exe", "RstMwService.exe",
        "TbtP2pShortcutService.exe"
    )
    # Wildcard-matched vendor prefixes (checked separately - exact list above handles most)
    $coreAllowedWildcards = @("igfx*","Asus*","ArmouryCrate*","SamsungMagician*","Intel*","OneApp.IGCC*","Mp*",
                               "iGoSw*","iGoAudio*","IGCC*")

    # Build parent PID -> name map for context-aware LOLBin scoring.
    $parentMap = @{}
    foreach ($p in $wmiProcesses) { $parentMap[$p.ProcessId] = $p.Name }

    # Parents that make PowerShell/script-host child processes immediately suspicious.
    # Legitimate software does not spawn encoded PowerShell from these.
    $highRiskParents = @(
        'winword.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe',  # Office
        'msaccess.exe','mspub.exe','visio.exe',
        'chrome.exe','msedge.exe','firefox.exe','iexplore.exe','opera.exe',    # Browsers
        'acrord32.exe','acrobat.exe',                                          # PDF readers
        'wscript.exe','cscript.exe','mshta.exe',                               # Script hosts
        'teams.exe','slack.exe','discord.exe',                                 # Messaging
        'java.exe','javaw.exe'                                                 # Java
    )

    # Process names that legitimately use encoded commands / hidden windows at scale.
    # Do NOT flag these on -enc or -w hidden alone.
    $lowRiskProcesses = @(
        'svchost.exe','SearchIndexer.exe','SearchHost.exe','WmiPrvSE.exe',
        'msiexec.exe','TiWorker.exe','TrustedInstaller.exe','MpCmdRun.exe',
        'SgrmBroker.exe','AggregatorHost.exe','SecurityHealthService.exe',
        'OneDrive.exe','OneDriveStandaloneUpdater.exe',
        'MicrosoftEdgeUpdate.exe','GoogleUpdate.exe','OfficeClickToRun.exe'
    )

    foreach ($wmi in $wmiProcesses) {
        $name      = $wmi.Name
        $cmdLine   = [string]$wmi.CommandLine
        $parentName = $parentMap[[int]$wmi.ParentProcessId]

        # --- Hidden process detection ---
        $nameAllowed = ($name -in $coreAllowed) -or
                       ($coreAllowedWildcards | Where-Object { $name -like $_ })
        if (-not $apiDict.ContainsKey($wmi.ProcessId) -and -not $nameAllowed) {
            # Re-verify to kill enumeration-race false positives. The Get-Process and
            # WMI snapshots are taken at slightly different times; any process that
            # STARTED in that window is in WMI but not the API snapshot - that is a
            # race, NOT a hidden process. A genuinely hidden (DKOM/rootkit) process is
            # invisible to the standard API *right now* while WMI still confirms it is
            # alive. Only flag when both hold true.
            $stillHidden = $false
            try {
                $null = Get-Process -Id $wmi.ProcessId -ErrorAction Stop
                # API can see it now -> it was a timing artifact, not hidden.
            } catch {
                $alive = Get-CimInstance Win32_Process -Filter "ProcessId=$($wmi.ProcessId)" -ErrorAction SilentlyContinue
                if ($alive) { $stillHidden = $true }   # invisible to API, still alive in WMI = truly hidden
            }
            if ($stillHidden) {
                Add-Finding -Type "Hidden Process" -Target "PID: $($wmi.ProcessId)" `
                    -Details "Hidden from standard API (re-verified). Name: $name" -Severity "High" -Mitre $Global:MITRE.HiddenProcess
            }
        }

        # --- Context-aware LOLBin scoring ---
        if (-not $cmdLine) { continue }
        if ($name -in $lowRiskProcesses) { continue }
        # Skip the EDR toolkit's own processes (orchestrator + child phases).
        if ($script:SelfPids.Contains($wmi.ProcessId)) { continue }

        $score    = 0
        $reasons  = [System.Collections.Generic.List[string]]::new()
        $severity = 'Medium'

        # High-confidence individual indicators (score 2 each)
        if ($cmdLine -match '(?i)-enc\b|-encodedcommand') {
            $score += 2; $reasons.Add('-EncodedCommand')
        }
        if ($cmdLine -match '(?i)\bIEX\b|Invoke-Expression') {
            $score += 2; $reasons.Add('IEX/Invoke-Expression')
        }
        if ($cmdLine -match '(?i)mshta\b') {
            $score += 2; $reasons.Add('mshta')
        }
        if ($cmdLine -match '(?i)certutil.*-decode|certutil.*-urlcache|certutil.*-f') {
            $score += 2; $reasons.Add('certutil decode/download')
        }
        if ($cmdLine -match '(?i)bitsadmin.*/transfer|bitsadmin.*/create') {
            $score += 2; $reasons.Add('bitsadmin transfer')
        }

        # Medium indicators (score 1 each) - require combination
        if ($cmdLine -match '(?i)-w\s+hid|-windowstyle\s+hid') {
            $score += 1; $reasons.Add('-WindowStyle Hidden')
        }
        if ($cmdLine -match '(?i)-nop\b|-noprofile\b') {
            $score += 1; $reasons.Add('-NoProfile')
        }
        if ($cmdLine -match '(?i)DownloadString|DownloadFile|WebClient|Net\.WebClient') {
            $score += 2; $reasons.Add('WebClient download')
        }
        if ($cmdLine -match '(?i)FromBase64String|ToBase64String') {
            $score += 1; $reasons.Add('Base64 conversion')
        }

        # Context multiplier: suspicious parent doubles the score
        if ($parentName -and ($parentName.ToLower() -in $highRiskParents)) {
            $score *= 2
            $reasons.Add("spawned by $parentName")
            $severity = 'Critical'
        } elseif ($score -ge 3) {
            $severity = 'High'
        }

        # Only generate a finding if score meets threshold
        if ($score -ge 3) {
            $detail = "Score=$score Indicators=[$($reasons -join ', ')] CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))"
            Add-Finding -Type "LOLBin Execution" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details $detail -Severity $severity -Mitre $Global:MITRE.EncodedCommand
        }
    }
}

function Invoke-InjectionHunt {
    Write-Console "[*] Hunting for Reflective DLL Injection / Foreign Modules..." "Cyan"
    $procs = Get-Process -ErrorAction SilentlyContinue
    $sigCache = @{}
    foreach ($p in $procs) {
        try {
            $modules = Get-Module -InputObject $p -ErrorAction SilentlyContinue
            foreach ($m in $modules) {
                if ($m.ModuleName -like "*.dll" -and $m.Path) {
                    if (-not (Test-Path $m.Path)) {
                        Add-Finding -Type "Reflective DLL Injection" -Target "$($p.ProcessName) (PID $($p.Id))" `
                            -Details "Module '$($m.ModuleName)' loaded but file does not exist on disk" -Severity "High" -Mitre $Global:MITRE.ProcessInjection
                        continue
                    }
                    if (-not $sigCache.ContainsKey($m.Path)) {
                        $sigCache[$m.Path] = (Get-AuthenticodeSignature -FilePath $m.Path -ErrorAction SilentlyContinue).Status
                    }
                    $sigStatus = $sigCache[$m.Path]
                    if ($sigStatus -ne "Valid" -and $p.ProcessName -notin @("explorer","svchost","lsass","winlogon","services")) {
                        Add-Finding -Type "Suspicious Injected DLL" -Target "$($p.ProcessName) (PID $($p.Id))" `
                            -Details "Unsigned DLL: $($m.Path)" -Severity "High" -Mitre $Global:MITRE.ProcessInjection
                    }
                }
            }
        } catch {}
    }
}

function Invoke-FilelessHunt {
    Write-Console "[*] Hunting for Classic Fileless Persistence..." "Cyan"
    $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    foreach ($consumer in $wmiConsumers) {
        if ($consumer.Name -notmatch "BVTConsumer|SCM Event Log Consumer") {
            Add-Finding -Type "WMI Persistence" -Target "WMI Consumer: $($consumer.Name)" `
                -Details "Suspicious WMI Event Consumer" -Severity "High" -Mitre $Global:MITRE.WMIPersistence
        }
    }
    $runKeys = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            foreach ($property in $entries.PSObject.Properties) {
                if ($property.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                    $val = $property.Value
                    if ($val -match "powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin") {
                        Add-Finding -Type "Suspicious Registry Key" -Target "$key\$($property.Name)" `
                            -Details "LOLBin in Run Key: $val" -Severity "High" -Mitre $Global:MITRE.RegPersistence
                    }
                }
            }
        }
    }
}

function Invoke-AdvancedRegistryHunt {
    Write-Console "[*] Expanded Registry Persistence (IFEO, AppInit_DLLs, Services)..." "Cyan"
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        Get-ChildItem $ifeoPath | ForEach-Object {
            $dbg = Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($dbg.Debugger -match "powershell|cmd|wscript|mshta") {
                Add-Finding -Type "IFEO Debugger Hijack" -Target $_.PSChildName `
                    -Details "Debugger: $($dbg.Debugger)" -Severity "High" -Mitre $Global:MITRE.RegIFEO
            }
        }
    }
    $appinitPaths = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")
    foreach ($p in $appinitPaths) {
        if (Test-Path $p) {
            $val = Get-ItemProperty -Path $p -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
            if ($val.AppInit_DLLs) {
                Add-Finding -Type "AppInit_DLLs Hijack" -Target $p `
                    -Details "AppInit_DLLs: $($val.AppInit_DLLs)" -Severity "High" -Mitre $Global:MITRE.AppInitDLL
            }
        }
    }
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        if ($svc.PathName -match "powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin" -or $svc.PathName -match "\\Temp|\\AppData") {
            Add-Finding -Type "Suspicious Service" -Target "$($svc.Name) ($($svc.PathName))" `
                -Details "Path: $($svc.PathName) | StartMode: $($svc.StartMode)" -Severity "High" -Mitre $Global:MITRE.ServiceTamper
        }
    }
}

function Invoke-BITSHunt {
    Write-Console "[*] Hunting for Suspicious BITS Jobs..." "Cyan"
    # Allow-list covers OS update mechanisms, browser auto-update, and common vendor
    # update frameworks. Flag only jobs whose display name AND source URL don't match.
    $allowedNames = '(?i)Microsoft|Windows.Update|Background.Intelligent|MicrosoftEdge|Edge.Component|' +
                    'Google.Update|Chrome|Firefox|OneDrive|Sysinternals|Defender|Office|Teams|' +
                    'Visual.Studio|WinGet|StoreSvc|Xbox|Nvidia|Intel|AMD'
    $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    foreach ($job in $jobs) {
        if ($job.DisplayName -notmatch $allowedNames) {
            $src = try { ($job.FileList | Select-Object -First 1 -ExpandProperty Source) } catch { '' }
            Add-Finding -Type "Suspicious BITS Job" -Target "Job: $($job.DisplayName)" `
                -Details "URL: $src | State: $($job.JobState)" -Severity "High" -Mitre $Global:MITRE.BITSJob
        }
    }
}

function Invoke-COMHijackHunt {
    Write-Console "[*] Hunting for COM Hijacking..." "Cyan"

    # Real COM hijacking = HKCU entry that shadows (overrides) an HKLM registration,
    # pointing to a DLL in a user-writable location. Scanning HKLM CLSIDs independently
    # produces mostly legitimate software registrations.

    # Step 1: Build HKLM CLSID set for shadow-detection
    $hklmClsids = @{}
    $hklmBase = "HKLM:\Software\Classes\CLSID"
    if (Test-Path $hklmBase) {
        Get-ChildItem $hklmBase -ErrorAction SilentlyContinue | ForEach-Object {
            $hklmClsids[$_.PSChildName] = $true
        }
    }

    # Step 2: Check HKCU CLSIDs - only flag those that shadow an HKLM entry
    # AND point to a user-writable / unsigned DLL
    $hkcuBase = "HKCU:\Software\Classes\CLSID"
    if (Test-Path $hkcuBase) {
        Get-ChildItem $hkcuBase -ErrorAction SilentlyContinue | ForEach-Object {
            $clsid = $_
            $isShadow = $hklmClsids.ContainsKey($clsid.PSChildName)
            $inproc = Join-Path $clsid.PSPath "InProcServer32"
            if (-not (Test-Path $inproc)) { return }

            $dll = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(Default)'
            if (-not $dll) { return }

            # Expand environment variables so path comparisons work
            $dllExpanded = [System.Environment]::ExpandEnvironmentVariables($dll)

            # Skip DLLs in known-good system / vendor paths (signed in-place installs)
            $safePathPattern = '(?i)(system32|syswow64|WinSxS|Program Files|Microsoft\.NET|' +
                               'Windows Defender|Windows\\servicing|ProgramData\\Microsoft|' +
                               'Windows\\SystemApps|WindowsApps|CrossDevice|' +
                               'AppData\\Local\\Microsoft|AppData\\Roaming\\Microsoft)'
            if ($dllExpanded -match $safePathPattern) { return }

            # Check Authenticode - signed DLLs from trusted publishers are not hijacks
            $sigOk = $false
            if (Test-Path -LiteralPath $dllExpanded -ErrorAction SilentlyContinue) {
                $sig = Get-AuthenticodeSignature -FilePath $dllExpanded -ErrorAction SilentlyContinue
                $sigOk = $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft|Windows'
            }
            if ($sigOk) { return }

            $severity = if ($isShadow) { 'High' } else { 'Medium' }
            $detail = "$(if($isShadow){'SHADOWS HKLM - '}else{'HKCU-only - '})InProcServer32: $dll"
            Add-Finding -Type "COM Hijacking" -Target $clsid.PSChildName `
                -Details $detail -Severity $severity -Mitre $Global:MITRE.COMHijack
        }
    }
}

function Invoke-ETWAMSITamperHunt {
    Write-Console "[*] Hunting for ETW / AMSI Tampering..." "Cyan"
    $amsiProv = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path $amsiProv) {
        $count = (Get-ChildItem $amsiProv -ErrorAction SilentlyContinue).Count
        if ($count -eq 0) {
            Add-Finding -Type "AMSI Tampering" -Target "AMSI Providers" `
                -Details "0 providers registered. AMSI is completely blinded!" -Severity "Critical" -Mitre $Global:MITRE.AMSITampering
        }
    }
    $amsiKey = "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings"
    if (Test-Path $amsiKey) {
        $val = Get-ItemProperty -Path $amsiKey -Name "AmsiEnable" -ErrorAction SilentlyContinue
        if ($val.AmsiEnable -eq 0) {
            Add-Finding -Type "AMSI Disabled" -Target "AmsiEnable = 0" `
                -Details "AMSI explicitly disabled in registry" -Severity "Critical" -Mitre $Global:MITRE.AMSITampering
        }
    }
    $auto = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
    if (Test-Path $auto) {
        $sessions = Get-ChildItem $auto -ErrorAction SilentlyContinue
        foreach ($s in $sessions) {
            $enabled = Get-ItemProperty -Path $s.PSPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 0) {
                Add-Finding -Type "ETW Tampering" -Target $s.PSChildName `
                    -Details "Autologger session disabled" -Severity "High" -Mitre $Global:MITRE.ETWTampering
            }
        }
    }
}

function Invoke-PendingRenameHunt {
    Write-Console "[*] Checking PendingFileRenameOperations (MoveEDR)..." "Cyan"
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $val = Get-ItemProperty -Path $key -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($val.PendingFileRenameOperations) {
        Add-Finding -Type "PendingFileRenameOperations" -Target "Session Manager" `
            -Details "Entries present - possible boot-time EDR deletion" -Severity "High" -Mitre $Global:MITRE.PendingRename
    }
}

function Invoke-DriverHunt {
    Write-Host "[*] Hunting Loaded Drivers & Known Vulnerable (BYOVD)..." -ForegroundColor Cyan

    $knownVulnerable = @(
        "capcom.sys", "iqvw64.sys", "RTCore64.sys", "DBUtil_2_3.sys", "TfSysMon.sys",
        "gdrv.sys", "AsrDrv.sys", "AsrDrv101.sys", "AsrDrv102.sys", "AsrDrv103.sys",
        "AsrDrv104.sys", "AsrDrv105.sys", "amifldrv64.sys", "AMIFLDRV.sys",
        "aswArPot.sys", "aswSP.sys", "BdApiUtil64.sys", "ksapi64.sys", "ksapi64_del.sys",
        "NSecKrnl.sys", "TrueSight.sys", "ThrottleStop.sys", "probmon.sys", "IoBitUnlocker.sys",
        "Zemana.sys", "kavservice.sys", "agent64.sys", "AODDriver.sys", "ASUS.sys",
        "ASMMAP.sys", "ASRDRV.sys", "DBUtil.sys", "DBUtil_2_3_0_4.sys",
        "MsIo64.sys", "MsIo64_2.sys", "WinRing0x64.sys", "WinRing0.sys",
        "Truesight.sys", "wsftprm.sys", "BdApiUtil.sys", "K7RKScan.sys",
        "CcProtect.sys", "ProcessMonitorDriver.sys", "Safetica.sys"
    )

    if ($AutoUpdateDrivers) {
        # Try live API first; fall back to staged offline cache if present.
        $lolCache = Join-Path $PSScriptRoot '..\..\..\..\..\tools\loldrivers.json'
        $loaded   = $false
        try {
            Write-Host "[*] Fetching latest vulnerable drivers from loldrivers.io..." -ForegroundColor Cyan
            $apiDrivers = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json" -Method Get -ErrorAction Stop
            $liveList = $apiDrivers | Where-Object { $_.KnownVulnerable } | ForEach-Object { $_.Filename.ToLower() }
            $knownVulnerable = ($knownVulnerable + $liveList) | Select-Object -Unique
            Write-Host "[+] Loaded $($liveList.Count) live vulnerable drivers from loldrivers.io" -ForegroundColor Green
            $loaded = $true
        } catch {
            Write-Host "[-] Could not reach loldrivers.io. Checking offline cache..." -ForegroundColor Yellow
        }
        if (-not $loaded -and (Test-Path $lolCache)) {
            try {
                $cachedDrivers = Get-Content $lolCache -Raw | ConvertFrom-Json
                $cacheList = $cachedDrivers | Where-Object { $_.KnownVulnerable } | ForEach-Object { $_.Filename.ToLower() }
                $knownVulnerable = ($knownVulnerable + $cacheList) | Select-Object -Unique
                Write-Host "[+] Loaded $($cacheList.Count) drivers from offline cache (loldrivers.json)" -ForegroundColor Green
            } catch {
                Write-Host "[-] Offline cache unreadable. Using built-in list only." -ForegroundColor Yellow
            }
        } elseif (-not $loaded) {
            Write-Host "[-] No offline cache found. Using built-in list only." -ForegroundColor Yellow
        }
    }

    $drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
    foreach ($drv in $drivers) {
        if ([string]::IsNullOrWhiteSpace($drv.Name)) { continue }

        $name = $drv.Name.ToLower()
        $isUnsigned = $false
        $sigStatus = "N/A (Virtual Driver)"

        # Check Signature ONLY if the driver has a physical file path on disk
        if (-not [string]::IsNullOrWhiteSpace($drv.Path) -and (Test-Path -Path $drv.Path -ErrorAction SilentlyContinue)) {
            $sig = Get-AuthenticodeSignature -FilePath $drv.Path -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = $sig.Status
                if ($sig.Status -ne "Valid") {
                    $isUnsigned = $true
                }
            }
        }

        # Alert if in vulnerable list OR if it is a physical file that is unsigned
        if ($name -in $knownVulnerable -or $isUnsigned) {
            Add-Finding -Type "Suspicious Kernel Driver" `
                -Target "$($drv.DisplayName) ($($drv.Path))" `
                -Details "Signed: $sigStatus | Vulnerable/Unsigned driver loaded (BYOVD risk)" `
                -Severity "Critical" `
                -Mitre $Global:MITRE.BYOVD
        }
    }
}

function Invoke-ScheduledTaskHunt {
    Write-Console "[*] Hunting Scheduled Tasks for suspicious persistence..." "Cyan"
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }

    foreach ($task in $tasks) {
        $cmdLine = ""
        if ($task.Actions) {
            $cmdLine = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join " "
        }

        # Score-based detection - same principle as process hunt.
        # A scheduled task using PowerShell from System32 is normal (Windows Update, etc.).
        # Flag only when obfuscation OR high-risk LOLBin patterns are present.
        $score   = 0
        $taskSev = 'High'

        if ($cmdLine -match '(?i)-enc\b|-encodedcommand')                          { $score += 3 }
        if ($cmdLine -match '(?i)\bIEX\b|Invoke-Expression')                       { $score += 3 }
        if ($cmdLine -match '(?i)DownloadString|DownloadFile|WebClient')           { $score += 3 }
        if ($cmdLine -match '(?i)mshta\b')                                         { $score += 3 }
        if ($cmdLine -match '(?i)certutil.*-decode|certutil.*-urlcache')           { $score += 3 }
        if ($cmdLine -match '(?i)bitsadmin.*/transfer')                            { $score += 3 }
        if ($cmdLine -match '(?i)-w\s+hid|-windowstyle\s+hid')                     { $score += 1 }
        if ($cmdLine -match '(?i)-nop\b|-noprofile\b')                             { $score += 1 }
        if ($cmdLine -match '(?i)wscript|cscript' -and
            $cmdLine -notmatch '(?i)Windows\\System32\\|Windows\\SysWOW64\\')      { $score += 2 }
        if ($cmdLine -match '(?i)regsvr32|rundll32' -and
            $cmdLine -notmatch '(?i)Windows\\System32\\|Windows\\SysWOW64\\')      { $score += 2 }
        if ($cmdLine -match '(?i)\\Temp\\|\\AppData\\|\\Users\\Public\\')          { $score += 2 }

        if ($score -ge 3) {
            if ($score -ge 5) { $taskSev = 'Critical' }
            Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                -Details "Score=$score Action: $cmdLine" -Severity $taskSev -Mitre $Global:MITRE.ScheduledTask
        }
    }
}

function Invoke-FileHunt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$Recurse,
        [int]$MaxSizeBytes = 52428800,
        [int]$EntropySampleBytes = 1048576,
        [switch]$QuickMode,
        [string[]]$ExcludePaths = @(),
        [switch]$Quiet,
        [int]$MaxThreads = 0,
        [int]$FilesPerChunk = 500,
        [switch]$LowMemoryMode,
        [int]$QuickModeDaysBack = 90   # QuickMode: only scan files touched in last N days
    )

    if ($MaxThreads -le 0) { $MaxThreads = [math]::Min([Environment]::ProcessorCount, 16) }
    if ($LowMemoryMode) {
        $MaxThreads    = [math]::Max(4, [math]::Floor($MaxThreads / 2))
        $FilesPerChunk = [math]::Min(200, $FilesPerChunk)
        $EntropySampleBytes = 131072
        Write-Console "[*] LowMemoryMode enabled - reduced threads/chunks/entropy sample" "Yellow"
    }
    if ($QuickMode) { $EntropySampleBytes = 131072 }

    $QuickModeCutoff = (Get-Date).AddDays(-$QuickModeDaysBack)

    # -- Phase 1: Fast native recursive enumeration -------------------------
    $CleanPath = $Path.TrimEnd('\')
    if ($CleanPath -eq "") { $CleanPath = $Path }

    $BaseExcludedDirs = @(
        # High-noise signed-binary directories - Microsoft-signed, no IR value scanning these
        "$CleanPath\Windows\System32",
        "$CleanPath\Windows\SysWOW64",
        "$CleanPath\Windows\WinSxS",
        "$CleanPath\Windows\servicing",
        "$CleanPath\Windows\assembly",
        "$CleanPath\Windows\Microsoft.NET",
        "$CleanPath\Windows\System32\config",
        "$CleanPath\Windows\System32\DriverStore",
        "$CleanPath\Windows\System32\catroot",
        "$CleanPath\Windows\System32\winevt\Logs",

        # Application installs - legitimate vendor software
        "$CleanPath\Program Files",
        "$CleanPath\Program Files (x86)",

        # High-volume noise with no IR signal
        "$CleanPath\System Volume Information",
        "$CleanPath\ProgramData\Microsoft\Windows\WER",
        "$CleanPath\ProgramData\Microsoft\Windows\SystemData",
        "$CleanPath\ProgramData\Microsoft\Windows\Containers",
        "$CleanPath\ProgramData\Microsoft\Windows\DeliveryOptimization",
        "$CleanPath\ProgramData\Package Cache",

        # Cloud sync folders - remote content, not host artifacts
        "*OneDrive*", "*DropBox*", "*Google Drive*", "*iCloudDrive*", "*Creative Cloud*",

        # Browser caches - massive, almost never contain staged malware on disk
        "*\AppData\Local\Google\Chrome\User Data\Default\Cache*",
        "*\AppData\Local\Microsoft\Edge\User Data\Default\Cache*",
        "*\AppData\Local\Mozilla\Firefox\Profiles*",
        "*\AppData\Local\Packages\*\AC\*",          # UWP app package caches

        # Dev / package manager trees - legitimate, enormous, slow
        "*\node_modules*", "*\.git\objects*", "*\__pycache__*",

        # Windows Defender / AV self-defense tarpits
        "*Microsoft\Windows Defender\Scans*",
        "*Microsoft\Search\Data*",
        "*System32\LogFiles\WMI\RtBackup*",
        "*System32\config\systemprofile*",
        "*Microsoft.PowerShell.Security*",

        # Third-party AV/EDR tarpits
        "*Bitdefender*", "*SentinelOne*", "*CrowdStrike*", "*Symantec*",
        "*Kaspersky*", "*McAfee*", "*Trend Micro*", "*Sophos*", "*ESET*",

        # Vendor uninstaller temp directories - signed vendor files, high-entropy
        # legitimately (compressed payload bundles, NativeAOT, packed JS).
        "*\AppData\Local\Temp\TiUninst*",   # Trend Micro Maximum Security uninstaller
        "*\AppData\Local\Temp\Ti*",          # Trend Micro temp prefix (TmJs*, PrivacyScanner)
        "*\.vscode\extensions\*",            # VS Code extension bundles (Roslyn NativeAOT etc.)
        "*\AppData\Local\Programs\Microsoft VS Code\*"
    )

    $ActiveExclusions = $BaseExcludedDirs + $ExcludePaths

    Write-Console "[*] High-Speed File Hunt in: $Path $(if($QuickMode){'(QuickMode)'}) $(if($LowMemoryMode){'(LowMemory)'})" "Cyan"

    $filesToScan = [System.Collections.Generic.List[string]]::new()
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Path)
    $folderCount = 0

    try {
        while ($queue.Count -gt 0) {
            $currentPath = $queue.Dequeue()
            $folderCount++

            if ($folderCount % 500 -eq 0 -and -not $Quiet) {
                Write-Console "[~] Enumerated $folderCount dirs | $($filesToScan.Count) candidates | $($currentPath.Substring(0,[math]::Min(60,$currentPath.Length)))" "Gray"
            }

            $skip = $false
            foreach ($ex in $ActiveExclusions) {
                if ($currentPath -like $ex -or $currentPath -like "$ex\*") { $skip = $true; break }
            }
            if ($skip) { continue }

            try {
                $di = [System.IO.DirectoryInfo]::new($currentPath)
                $dirAttr = $di.Attributes.ToString()
                if ($dirAttr -match "ReparsePoint|Offline|RecallOnData|RecallOnOpen") { continue }

                if ($Recurse) {
                    foreach ($subDir in $di.EnumerateDirectories()) { $queue.Enqueue($subDir.FullName) }
                }

                foreach ($file in $di.EnumerateFiles()) {
                    if ($file.Extension -match "\.(exe|dll|sys|ps1|bat|vbs|js)$") {
                        $fileAttr = $file.Attributes.ToString()
                        if ($fileAttr -match "Offline|RecallOnData|RecallOnOpen|ReparsePoint") { continue }
                        # QuickMode: skip files untouched before the cutoff date -
                        # old, unmodified files are low-priority in an active incident.
                        if ($QuickMode -and $file.LastWriteTime -lt $QuickModeCutoff -and
                            $file.CreationTime -lt $QuickModeCutoff) { continue }
                        if ($file.Length -le $MaxSizeBytes) {
                            $filesToScan.Add($file.FullName)
                        }
                    }
                }
            } catch {}
        }
    }
    finally {
        if (-not $Quiet) { Write-Progress -Activity "Phase 1/2 - Enumerating Directories" -Completed }
        [System.GC]::Collect()
    }

    Write-Console "[*] Found $($filesToScan.Count) candidate files. Starting parallel scan..." "Gray"
    if ($filesToScan.Count -eq 0) { return }

    # -- Chunking for smoother progress & lower memory pressure -------------
    $chunks = [System.Collections.Generic.List[System.Object[]]]::new()
    for ($i = 0; $i -lt $filesToScan.Count; $i += $FilesPerChunk) {
        $end = [math]::Min($i + $FilesPerChunk, $filesToScan.Count)
        $chunks.Add($filesToScan.GetRange($i, $end - $i).ToArray())
    }

    # Variables passed explicitly into the runspace worker (outer scope is not
    # available across runspace boundaries - must be AddArgument'd).
    $tsSkipPattern = '(?i)(\\Windows\\Installer\\|ProgramData\\Microsoft\\|' +
                     '\\Windows Defender\\|\.cargo\\|\.nuget\\|\.rustup\\|' +
                     '\\AppData\\Roaming\\Code\\|\\AppData\\Local\\Microsoft\\|' +
                     '\\node_modules\\|__pycache__|NuGet\\packages|' +
                     'ProgramData\\Package Cache|Windows\\assembly|' +
                     'ProgramData\\IDPSSensor|ProgramData\\DataSensor)'
    # Extensions that are legitimately high-entropy by design - skip entropy scoring.
    # Minified JS/CSS/TS, source maps, WASM, compiled .NET resource bundles.
    $highEntropyAllowExts = [string[]]@('.js','.jsx','.ts','.tsx','.css','.map','.wasm',
                                        '.json','.min','.bundle','.chunk')

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $jobs = @()

    # -- Worker scriptblock -------------------------------------------------
    $huntingBlock = {
        param([string[]]$fileList, [int]$SampleBytes, [bool]$IsQuickMode, [string]$TsSkipPattern, [string[]]$HighEntropyAllowExts)
        $threadResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($filePath in $fileList) {
            try {
                $file = [System.IO.FileInfo]::new($filePath)

                # High Entropy check - skip extensions that are legitimately high-entropy
                # by design (minified JS/CSS, source maps, WASM, compiled .NET assets).
                $ext = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()
                $skipEntropy = $HighEntropyAllowExts -and $HighEntropyAllowExts.Contains($ext)
                if (-not $skipEntropy -and (-not $IsQuickMode -or $file.Length -le 10485760)) {
                    $bytes = if ($file.Length -gt $SampleBytes) {
                        $fs = [System.IO.File]::OpenRead($filePath)
                        $buf = New-Object byte[] $SampleBytes
                        $fs.Read($buf, 0, $SampleBytes) | Out-Null
                        $fs.Close()
                        $buf
                    } else { [System.IO.File]::ReadAllBytes($filePath) }
                    $fileSize = $bytes.Count
                    if ($fileSize -gt 0) {
                        $byteCounts = New-Object 'int[]' 256
                        foreach ($b in $bytes) { $byteCounts[$b]++ }
                        $entropy = 0.0
                        foreach ($count in $byteCounts) {
                            if ($count -gt 0) {
                                $prob = $count / $fileSize
                                $entropy -= $prob * [math]::Log($prob, 2)
                            }
                        }
                        if ($entropy -ge 7.2) {
                            $threadResults.Add([PSCustomObject]@{Type="High Entropy File"; Target=$filePath; Details="Entropy: $([math]::Round($entropy,2))"; Severity="High"; Mitre="T1027"})
                        }
                    }
                }

                # Timestomping check - epoch/impossible timestamps only.
                # The prior check (CreationTime > LastWriteTime by 30+ days) flagged archive
                # extraction (extraction date > archive timestamp) producing mass FPs.
                # Real timestomping tools set impossible dates: 1601-01-01 (NTFS epoch),
                # 1970-01-01 (Unix epoch), or pre-2003 dates impossible on modern Windows.
                $epochFloor = [DateTime]::new(2003, 1, 1)
                if (($file.CreationTime -lt $epochFloor -or $file.LastWriteTime -lt $epochFloor) -and
                    (-not $TsSkipPattern -or $filePath -notmatch $TsSkipPattern)) {
                    $ct = $file.CreationTime.ToString('yyyy-MM-dd')
                    $wt = $file.LastWriteTime.ToString('yyyy-MM-dd')
                    $threadResults.Add([PSCustomObject]@{
                        Type="Timestomped File"; Target=$filePath
                        Details="Epoch/impossible timestamp (creation=$ct write=$wt) - tool likely backdated to 1601/1970/pre-2003"
                        Severity="Medium"; Mitre="T1070.006"
                    })
                }
            } catch {}
        }
        return $threadResults
    }

    # Launch parallel jobs (simple, reliable style that actually scans)
    try {
        foreach ($chunk in $chunks) {
            $ps = [powershell]::Create().AddScript($huntingBlock).AddArgument($chunk).AddArgument($EntropySampleBytes).AddArgument([bool]$QuickMode).AddArgument($tsSkipPattern).AddArgument($highEntropyAllowExts)
            $ps.RunspacePool = $runspacePool
            $jobs += [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
        }

        # -- Real-time progress - stdout so it travels through the pipe --------
        $totalBatches     = $jobs.Count
        $completedBatches = 0
        $lastLogUpdate    = Get-Date
        $startTime       = Get-Date
        $logInterval     = [TimeSpan]::FromSeconds(15)   # console line every 15 s

        while ($completedBatches -lt $totalBatches) {
            Start-Sleep -Milliseconds 500
            $now = Get-Date
            # @(...) forces an array: under PS 5.1 + Set-StrictMode, a single piped
            # object has no .Count property (throws PropertyNotFoundStrict), which would
            # leave $completedBatches at 0 and loop forever when there's only ONE chunk.
            $completedBatches = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
            $processedFiles   = [math]::Min(($completedBatches * $FilesPerChunk), $filesToScan.Count)
            $pct              = [int][math]::Round((($completedBatches / $totalBatches) * 100), 0)
            $elapsedSecs      = ($now - $startTime).TotalSeconds
            $rate             = if ($elapsedSecs -gt 0) { [math]::Round($processedFiles / $elapsedSecs, 0) } else { 0 }
            $etaSecs          = if ($rate -gt 0) { [int](($filesToScan.Count - $processedFiles) / $rate) } else { -1 }

            if (-not $Quiet -and ($now - $lastLogUpdate) -ge $logInterval) {
                $eta = if ($etaSecs -gt 0) { "$([math]::Round($etaSecs/60,1)) min remaining" } else { 'calculating...' }
                Write-Console "[~] File scan: $processedFiles / $($filesToScan.Count) files | $pct% | $rate files/sec | $eta" "Gray"
                $lastLogUpdate = $now
            }
        }

        foreach ($job in $jobs) {
            $results = $job.PowerShell.EndInvoke($job.Handle)
            if ($results) {
                foreach ($res in $results) {
                    Add-Finding -Type $res.Type -Target $res.Target -Details $res.Details -Severity $res.Severity -Mitre $res.Mitre
                }
            }
        }
    }
    finally {
        if (-not $Quiet) { Write-Progress -Activity "Phase 2/2 - Deep File Scanning" -Completed }
        Write-Console " [Cleanup] Disposing runspaces & forcing GC..." "DarkGray"
        foreach ($job in $jobs) {
            if ($job.PowerShell) { $job.PowerShell.Stop(); $job.PowerShell.Dispose() }
        }
        if ($runspacePool) { $runspacePool.Close(); $runspacePool.Dispose() }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Invoke-YaraFileScan {
    <#
    .SYNOPSIS
        Targeted YARA scan: uses the current $script:Findings to pick the minimal
        relevant rule subset and file list, rather than blasting all rules at all files.
        Two-phase: (1) build target list from suspicious findings, (2) run matched rule
        categories only.  Falls back to full-directory scan if no prior findings exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TargetPath,
        [string]$RulesDir,
        [switch]$Quiet
    )

    # -- 1. Locate yara64.exe --------------------------------------------------
    $yaraExe = $null
    $searchRoot = $PSScriptRoot
    for ($i = 0; $i -lt 6; $i++) {
        $candidate = Join-Path $searchRoot 'tools\yara64.exe'
        if (Test-Path $candidate) { $yaraExe = $candidate; break }
        $parent = Split-Path $searchRoot -Parent
        if (-not $parent -or $parent -eq $searchRoot) { break }
        $searchRoot = $parent
    }
    if (-not $yaraExe) {
        Write-Console "[~] YARA: yara64.exe not found - run Build-OfflineToolkit.ps1 -IncludeMemory." "Yellow"
        return
    }

    if (-not $RulesDir) { $RulesDir = Join-Path (Split-Path $yaraExe -Parent) 'yara_rules' }
    if (-not (Test-Path $RulesDir)) {
        Write-Console "[~] YARA: rules dir '$RulesDir' not found - run Build-OfflineToolkit.ps1 -IncludeYaraRules." "Yellow"
        return
    }

    # -- 2. Build targeted file list from prior findings -----------------------
    # Only scan files that were flagged; fall back to full TargetPath if no file-based findings.
    $suspiciousTypes = @('High Entropy File','Cloaked File','Timestomped File',
                         'Reflective DLL Injection','Suspicious Injected DLL',
                         'Alternate Data Stream','Suspicious Service')
    $suspiciousFiles = @($script:Findings |
        Where-Object { $_.Type -in $suspiciousTypes -and (Test-Path $_.Target -ErrorAction SilentlyContinue) } |
        Select-Object -ExpandProperty Target -Unique)

    if ($suspiciousFiles.Count -gt 0) {
        Write-Console "[*] YARA: targeted scan - $($suspiciousFiles.Count) suspicious file(s) from prior findings." "Cyan"
        $scanTargets = $suspiciousFiles
    } else {
        Write-Console "[*] YARA: no prior file-based findings - scanning full directory '$TargetPath'." "Cyan"
        $scanTargets = @($TargetPath)
    }

    # -- 3. Select rules: ALL staged sets, Windows-applicable -----------------
    # Use the full corpus (elastic + neo23x0 + reversinglabs + local), NOT a subset
    # gated on prior findings - a host can be compromised with zero prior file
    # findings, and the elastic Windows_Trojan rules (the APT signatures) were never
    # selected by the old type-map. Drop Linux/macOS-tagged rules (irrelevant here) and
    # the abuse.ch feed (duplicate rule-ids that fail the combined compile + PE-structure
    # noise) - consistent with the memory scan's exclude_memory_noise.
    $nonWin    = '(?i)(?:^|[\\/_])(linux|macos|osx|android|freebsd|ios)(?:[\\/_.]|$)'
    $noiseFeed = '(?i)[\\/]abusech[\\/]'
    $ruleFiles = [System.Collections.Generic.List[string]]::new()
    Get-ChildItem $RulesDir -Recurse -Include '*.yar','*.yara' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch $nonWin -and $_.FullName -notmatch $nonWin -and $_.FullName -notmatch $noiseFeed } |
        ForEach-Object { $ruleFiles.Add($_.FullName) }

    if ($ruleFiles.Count -eq 0) {
        Write-Console "[~] YARA: no rules found under '$RulesDir'." "Yellow"
        return
    }
    Write-Console "    Rules selected: $($ruleFiles.Count) Windows-applicable rule file(s)." "Gray"

    # -- 4. Write a temporary rule index --------------------------------------
    $tmpRuleIndex = [System.IO.Path]::GetTempFileName() -replace '\.tmp$','.yar'
    $includeLines = $ruleFiles | ForEach-Object { "include `"$_`"" }
    $includeLines | Out-File $tmpRuleIndex -Encoding UTF8

    $yaraBaseArgs = @('-w','-d','filename=','-d','filepath=','-d','extension=','-d','filetype=','-d','owner=')

    # -- 4a. Self-test: prove the engine + rules actually load and match -------
    # yara64 returns 0 matches if the ruleset fails to compile; a canary marker
    # file that MUST match confirms a clean result is real, not a silent dud.
    $canaryRule = [System.IO.Path]::GetTempFileName() -replace '\.tmp$','.yar'
    $canaryFile = [System.IO.Path]::GetTempFileName()
    'rule IRToolkit_File_Canary { strings: $m = "IRTOOLKIT_FILE_CANARY_MARKER" condition: $m }' |
        Out-File $canaryRule -Encoding UTF8
    'IRTOOLKIT_FILE_CANARY_MARKER' | Out-File $canaryFile -Encoding UTF8
    $canaryHit = & $yaraExe @yaraBaseArgs $canaryRule $canaryFile 2>$null
    if ($canaryHit -match 'IRToolkit_File_Canary') {
        Write-Console "    [+] YARA self-test OK (engine matching)." "Green"
    } else {
        Write-Console "    [!] YARA self-test FAILED - engine not matching; file YARA results unreliable." "Red"
    }
    Remove-Item $canaryRule, $canaryFile -Force -ErrorAction SilentlyContinue

    # -- 5. Scan, surfacing compile/scan errors instead of swallowing them -----
    $totalMatches = 0
    foreach ($target in $scanTargets) {
        $isDir    = Test-Path $target -PathType Container
        $yaraArgs = $yaraBaseArgs + $tmpRuleIndex
        if ($isDir) { $yaraArgs += '-r' }
        $yaraArgs += $target

        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            $yaraOutput = & $yaraExe @yaraArgs 2>$errFile
            $errText = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue
            if ($errText -and $errText.Trim()) {
                Write-Console "    [~] YARA warnings: $((($errText -split "`n")[0]).Trim())" "Yellow"
            }
            foreach ($line in @($yaraOutput)) {
                $line = $line.Trim()
                if (-not $line) { continue }
                $parts = $line -split '\s+', 2
                if ($parts.Count -eq 2) {
                    $rule = $parts[0]; $file = $parts[1]
                    Add-Finding -Type "YARA Match" -Target $file `
                        -Details "Rule: $rule" -Severity "High" `
                        -Mitre "T1027 (Obfuscated Files or Information)"
                    $totalMatches++
                }
            }
        } catch {
            Write-Console "    [~] YARA scan error on '$target': $($_.Exception.Message)" "Yellow"
        } finally {
            Remove-Item $errFile -Force -ErrorAction SilentlyContinue
        }
    }

    Remove-Item $tmpRuleIndex -Force -ErrorAction SilentlyContinue

    if ($totalMatches -gt 0) {
        Write-Console "    [!] YARA: $totalMatches match(es) across $($scanTargets.Count) target(s)." "Red"
    } else {
        Write-Console "    [+] YARA: no matches in targeted scan." "Green"
    }
}

function Invoke-ADSHunt {
    Write-Console "[*] Parallel ADS Hunt targeting High-Risk Locations..." "Cyan"

    $HighRiskPaths = @("$env:SystemDrive\ProgramData", "$env:SystemDrive\Users\Public", "$env:SystemDrive\Windows\Temp")
    $users = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    foreach ($u in $users) { $HighRiskPaths += "$u\AppData\Local\Temp"; $HighRiskPaths += "$u\AppData\Roaming"; $HighRiskPaths += "$u\Downloads" }

    $ActiveExclusions = @(
        "$env:SystemDrive\ProgramData\Microsoft\Windows\WER",
        "$env:SystemDrive\ProgramData\Microsoft\Windows\SystemData",
        "$env:SystemDrive\ProgramData\Microsoft\Windows\Containers",
        # VS Code stores extension files with Zone.Identifier ADS - thousands of false positives
        "*\AppData\Roaming\Code\*",
        "*\AppData\Local\Programs\Microsoft VS Code\*",
        # Package manager caches - Zone.Identifier ADS on every downloaded package
        "*\AppData\Local\Microsoft\WinGet\*",
        "*\AppData\Local\Temp\chocolatey\*",
        "*\.cargo\*", "*\.nuget\*"
    ) + $ExcludePaths

    $filesToScan = [System.Collections.Generic.List[string]]::new()
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($p in $HighRiskPaths) { if (Test-Path -LiteralPath $p) { $queue.Enqueue($p) } }

    $folderCount = 0
    while ($queue.Count -gt 0) {
        $currentPath = $queue.Dequeue()
        $folderCount++

        if ($folderCount % 50 -eq 0 -and -not $Quiet) {
            Write-Progress -Activity "Enumerating ADS Folders" -Status "Scanned $folderCount folders..." -PercentComplete -1
        }

        $skip = $false
        foreach ($ex in $ActiveExclusions) { if ($currentPath -like $ex -or $currentPath -like "$ex\*") { $skip = $true; break } }
        if ($skip) { continue }

        try {
            $di = [System.IO.DirectoryInfo]::new($currentPath)
            if (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or ($di.Attributes -band [System.IO.FileAttributes]::Offline)) { continue }
            foreach ($subDir in [System.IO.Directory]::EnumerateDirectories($currentPath)) { $queue.Enqueue($subDir) }
            foreach ($filePath in [System.IO.Directory]::EnumerateFiles($currentPath)) {
                $attrib = [System.IO.File]::GetAttributes($filePath)
                if (-not ($attrib -band [System.IO.FileAttributes]::Offline)) { $filesToScan.Add($filePath) }
            }
        } catch {}
    }
    if (-not $Quiet) { Write-Progress -Activity "Enumerating ADS Folders" -Completed }

    Write-Console "[*] Found $($filesToScan.Count) files in high-risk zones. Batching jobs..." "Gray"
    if ($filesToScan.Count -eq 0) { return }

    $MaxThreads = [Environment]::ProcessorCount
    $ChunkSize = [math]::Ceiling($filesToScan.Count / ($MaxThreads * 2))
    if ($ChunkSize -lt 100) { $ChunkSize = 100 }

    $chunks = [System.Collections.Generic.List[System.Object[]]]::new()
    for ($i = 0; $i -lt $filesToScan.Count; $i += $ChunkSize) {
        $end = [math]::Min($i + $ChunkSize, $filesToScan.Count) - $i
        $chunks.Add($filesToScan.GetRange($i, $end).ToArray())
    }

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $jobs = @()

    $adsBlock = {
        param([array]$fileList)
        $threadResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($filePath in $fileList) {
            try {
                $streams = Get-Item -LiteralPath $filePath -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                foreach ($stream in $streams) {
                    # Zone.Identifier is the standard web-download mark - never malicious on its own.
                    # Only flag non-standard named streams with actual content.
                    if ($stream.Length -gt 0 -and $stream.Stream -notmatch '(?i)Zone\.Identifier|SmartScreen|Identifier') {
                        $threadResults.Add([PSCustomObject]@{
                            Type = "Alternate Data Stream"; Target = $filePath
                            Details = "Stream '$($stream.Stream)' ($($stream.Length) bytes)"
                            Severity = "High"; Mitre = "T1564.004"
                        })
                    }
                }
            } catch {}
        }
        return $threadResults
    }

    try {
        foreach ($chunk in $chunks) {
            $ps = [powershell]::Create().AddScript($adsBlock).AddArgument($chunk)
            $ps.RunspacePool = $runspacePool
            $jobs += [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
        }

        $totalBatches = $jobs.Count
        $completedBatches = 0

        while ($completedBatches -lt $totalBatches) {
            $currentCompleted = 0
            foreach ($job in $jobs) { if ($job.Handle.IsCompleted) { $currentCompleted++ } }

            if ($currentCompleted -gt $completedBatches) {
                $completedBatches = $currentCompleted
                $pct = [math]::Round(($completedBatches / $totalBatches) * 100, 1)
                if (-not $Quiet) { Write-Progress -Activity "ADS Stream Scan" -Status "Processed $pct%" -PercentComplete $pct }
            }
            Start-Sleep -Milliseconds 500
        }

        foreach ($job in $jobs) {
            $results = $job.PowerShell.EndInvoke($job.Handle)
            if ($results) { foreach ($res in $results) { Add-Finding -Type $res.Type -Target $res.Target -Details $res.Details -Severity $res.Severity -Mitre $res.Mitre } }
        }
    } finally {
        if (-not $Quiet) { Write-Progress -Activity "ADS Stream Scan" -Completed }
        Write-Console "    [Cleanup] Disposing of background ADS threads..." "DarkGray"
        foreach ($job in $jobs) { if ($job.PowerShell) { $job.PowerShell.Stop(); $job.PowerShell.Dispose() } }
        if ($runspacePool) { $runspacePool.Close(); $runspacePool.Dispose() }
    }
}

function Export-Reports {
    param([string]$OutDir)
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    if ($script:Findings.Count -eq 0) {
        Write-Host "`n[+] Scan complete. No anomalies detected matching current filters." -ForegroundColor Green
        return
    }
    Write-Host "`n===================================================" -ForegroundColor Green
    Write-Host " TOP 10 FINDINGS SUMMARY " -ForegroundColor White
    Write-Host "===================================================" -ForegroundColor Green
    $script:Findings | Group-Object Type | Sort-Object Count -Descending | Select-Object -First 10 Count, Name | Format-Table -AutoSize

    # === CSV ===
    if ($OutputFormat -contains 'All' -or $OutputFormat -contains 'CSV') {
        $csvPath = "$OutDir\EDR_Report_$timestamp.csv"
        $script:Findings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Console "[+] CSV Report saved to: $csvPath" "Green"
    }

    # === HTML ===
    if ($OutputFormat -contains 'All' -or $OutputFormat -contains 'HTML') {
        $htmlPath = "$OutDir\EDR_Report_$timestamp.html"
        $totalFindings = $script:Findings.Count
        $highCrit = ($script:Findings | Where-Object { $_.Severity -in @('Critical','High') }).Count
        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EDR_HUNTER_SYS | NEURAL LINK</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600;700&display=swap');
        body { font-family: 'Fira Code', monospace; background-color: #050505; color: #e2e8f0; }
        .neon-border-cyan { box-shadow: 0 0 10px rgba(6, 182, 212, 0.5); border: 1px solid #06b6d4; }
        .neon-border-pink { box-shadow: 0 0 15px rgba(236, 72, 153, 0.4); border: 1px solid #ec4899; }
        .neon-text-cyan { text-shadow: 0 0 5px rgba(6, 182, 212, 0.8); }
        .neon-text-pink { text-shadow: 0 0 5px rgba(236, 72, 153, 0.8); }
        .grid-bg {
            background-image: linear-gradient(rgba(6, 182, 212, 0.05) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(6, 182, 212, 0.05) 1px, transparent 1px);
            background-size: 30px 30px;
        }
        .Critical { color: #f43f5e; text-shadow: 0 0 6px #f43f5e; }
        .High { color: #ec4899; text-shadow: 0 0 6px #ec4899; }
        .Medium { color: #eab308; text-shadow: 0 0 4px #eab308; }
    </style>
</head>
<body class="grid-bg min-h-screen p-6">
    <div class="max-w-7xl mx-auto">
        <header class="flex justify-between items-center border-b border-cyan-800 pb-4 mb-6">
            <div>
                <h1 class="text-3xl font-bold text-cyan-400 neon-text-cyan tracking-widest">EDR_HUNTER_SYS</h1>
                <p class="text-xs text-pink-500 mt-1 uppercase tracking-widest">// ACTIVE DEFENSE ENCLAVE</p>
            </div>
            <div class="text-xs bg-black px-3 py-1 rounded-sm border border-cyan-500 text-cyan-400 neon-text-cyan">
                [ UPLINK_SECURE : PENDING ]
            </div>
        </header>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div class="bg-black/60 p-5 rounded-sm neon-border-cyan">
                <h2 class="text-lg font-bold mb-4 border-b border-cyan-800 pb-2 text-cyan-300 uppercase tracking-wide">SCAN SUMMARY</h2>
                <p class="text-5xl font-bold text-white">TOTAL: <span class="text-cyan-400">@TOTAL@</span></p>
                <p class="text-pink-400 mt-2">HIGH/CRITICAL: <span class="font-bold">@HIGHCRIT@</span></p>
            </div>
            <div class="bg-black/60 p-5 rounded-sm neon-border-cyan md:col-span-2">
                <h2 class="text-lg font-bold mb-4 border-b border-cyan-800 pb-2 text-cyan-300 uppercase tracking-wide">ACTIVE DETECTIONS</h2>
                <div class="text-xs text-gray-400 bg-gray-900/80 p-3 rounded-sm h-32 overflow-y-auto border border-gray-800" id="detections-list"></div>
            </div>
        </div>
        <div class="bg-black/80 p-5 rounded-sm neon-border-pink">
            <h2 class="text-lg font-bold mb-4 border-b border-pink-900 pb-2 text-pink-500 neon-text-pink uppercase tracking-wide">ACTIVE DETECTIONS</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="text-cyan-400 bg-black border-b border-cyan-900 text-xs uppercase tracking-wider">
                        <tr>
                            <th class="p-3">TIMESTAMP</th>
                            <th class="p-3">SEVERITY</th>
                            <th class="p-3">TYPE</th>
                            <th class="p-3">TARGET</th>
                            <th class="p-3">DETAILS</th>
                            <th class="p-3">MITRE</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800 text-gray-300">
'@
        # Use StringBuilder - $html += in a loop is O(n²) and hangs on large finding sets
        $sb = [System.Text.StringBuilder]::new($html)
        $htmlFindingsCap = 2000   # cap HTML rows; JSON/CSV always get all findings
        $rowCount = 0
        foreach ($f in $script:Findings) {
            if ($rowCount -ge $htmlFindingsCap) {
                $null = $sb.Append("<tr><td colspan='6' class='p-3 text-yellow-400'>... $($script:Findings.Count - $htmlFindingsCap) additional findings in CSV/JSON reports ...</td></tr>")
                break
            }
            $null = $sb.Append("<tr class='hover:bg-gray-900/50'>")
            $null = $sb.Append("<td class='p-3 whitespace-nowrap text-xs'>$($f.Timestamp)</td>")
            $null = $sb.Append("<td class='p-3 font-bold $($f.Severity)'>$($f.Severity)</td>")
            $null = $sb.Append("<td class='p-3'>$($f.Type)</td>")
            $null = $sb.Append("<td class='p-3 text-cyan-300'>$($f.Target)</td>")
            $null = $sb.Append("<td class='p-3 text-gray-400'>$($f.Details)</td>")
            $null = $sb.Append("<td class='p-3 text-purple-400'>$($f.MITRE)</td>")
            $null = $sb.Append("</tr>")
            $rowCount++
        }
        $html = $sb.ToString()
        $html += @'
                    </tbody>
                </table>
            </div>
        </div>
        <div class="text-center text-xs text-gray-500 mt-8">
            Generated by EDR Toolkit * @TIMESTAMP@
        </div>
    </div>
    <script>
        document.getElementById('detections-list').innerHTML = `
            <div class="text-cyan-300">Total anomalies detected: <span class="font-bold text-white">@TOTAL@</span></div>
            <div class="text-pink-400">High/Critical threats: <span class="font-bold">@HIGHCRIT@</span></div>
            <div class="mt-4 text-xs text-gray-400">Scan completed successfully.</div>
        `;
    </script>
</body>
</html>
'@
        $html = $html -replace '@TOTAL@', $totalFindings
        $html = $html -replace '@HIGHCRIT@', $highCrit
        $html = $html -replace '@TIMESTAMP@', (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $html | Set-Content -Path $htmlPath -Encoding UTF8
        Write-Console "[+] HTML Report saved to: $htmlPath" "Green"
    }

    # === JSON ===
    if ($OutputFormat -contains 'All' -or $OutputFormat -contains 'JSON') {
        $jsonPath = "$OutDir\EDR_Report_$timestamp.json"
        $script:Findings | ConvertTo-Json -Depth 3 | Set-Content -Path $jsonPath
        Write-Console "[+] JSON Report saved to: $jsonPath" "Green"
    }
}

Write-Console "===================================================" "Green"
Write-Console "=========== Windows EDR Hunting Toolkit ===========" "Green"
Write-Console "===================================================" "Green"

if ($TestMode) {
    Write-Host "[*] RUNNING IN TEST MODE: Injecting simulated artifacts to test pipeline routing..." -ForegroundColor Magenta
    Add-Finding -Type "AMSI Tampering" -Target "Simulated Evasion Check" -Details "Only 0 provider(s) registered" -Severity "Critical" -Mitre "T1562.001"
    Add-Finding -Type "High Entropy File" -Target "C:\Temp\TestPayload.exe" -Details "Simulated Entropy: 7.99" -Severity "High" -Mitre "T1027"
    Export-Reports -OutDir $ReportPath
    exit
}

if (-not ($ScanProcesses -or $ScanFileless -or $TargetDirectory -or $ScanTasks -or $ScanDrivers -or $ScanInjection -or $ScanADS -or $ScanRegistry -or $ScanETWAMSI -or $ScanPendingRename -or $ScanBITS -or $ScanCOM -or $ScanYara)) {
    Write-Host "Usage examples:" -ForegroundColor Yellow
    Write-Host " .\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM"
    Write-Host " .\EDR_Toolkit.ps1 -TargetDirectory 'C:\' -Recursive -ScanADS -QuickMode -SeverityFilter Critical,High -OutputFormat JSON -Quiet"
    Exit
}

if ($ScanProcesses)  { Invoke-ProcessHunt }
if ($ScanInjection)  { Invoke-InjectionHunt }
if ($ScanFileless)   { Invoke-FilelessHunt }
if ($ScanRegistry)   { Invoke-AdvancedRegistryHunt }
if ($ScanTasks)      { Invoke-ScheduledTaskHunt }
if ($ScanDrivers)    { Invoke-DriverHunt }
if ($ScanBITS)       { Invoke-BITSHunt }
if ($ScanCOM)        { Invoke-COMHijackHunt }
if ($ScanETWAMSI)    { Invoke-ETWAMSITamperHunt }
if ($ScanPendingRename) { Invoke-PendingRenameHunt }

if ($TargetDirectory) {
    Invoke-FileHunt -Path $TargetDirectory -Recurse:$Recursive `
        -QuickMode:$QuickMode -QuickModeDaysBack $QuickModeDaysBack -Quiet:$Quiet
    if ($ScanADS)  { Invoke-ADSHunt -Path $TargetDirectory -Recurse:$Recursive }
    if ($ScanYara) { Invoke-YaraFileScan -TargetPath $TargetDirectory -RulesDir:$YaraRulesDir -Quiet:$Quiet }
} elseif ($ScanYara) {
    Write-Console "[-] -ScanYara requires -TargetDirectory to be set." "Yellow"
}

Export-Reports -OutDir $ReportPath

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBt1oG1eaXZkXOq
# FGJ9tW9XHUGsyRPYMLcW6Cqts/Pc/KCCFrQwggN2MIICXqADAgECAhBj3Isegven
# qEj21ds5AZieMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjMxNDE2NTlaFw0zMTA2MjMxNDI2NTlaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAM3b6zgkW9zzqQraVSnj+a4zp1l4KkWs2NKNqvPP
# p9Pyjhif7sY2FZyXnXbkKElZkNveSR84IkSBjIBC/9Q2gum1eM9nDmbnj2v5L+Nu
# llMOkOjUC913DYNHmHdk/8FDJwAjl6mtsAWZwTvc7FUpyqGiD09yILSywsivvkDV
# nE/qWzKgMRGflBJreqDUR5o0l0hLhowxG58ywKqElIJpwV+N1ngcfYIpJPO4XEHB
# 6sSe0fkZralmnZdZ+sw6LRUpE7nMxmy6ZktNz51jXnm/oR7N9VbHUBOMtBLAFmny
# CFddkOEV4z4Pz3yC0SOcgJXvoJ3yfPLzug7t5W+kRcNGmrECAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQQFW0G
# zu1Gz5VThEyg9LLMhDsLlDANBgkqhkiG9w0BAQsFAAOCAQEAGVSgMDhKb7EDBXTH
# 3pTUUxUoQNNByOzeSepp+Wq5HpPEO7lS204uZSljF1a6QNjya4SsVE3o4+TR9CJm
# uXqRvesj578tf9DQSl0iflg2rz9UGCXRVTazH8xMWOpt8fMlXbUf3xfYS4Wqena2
# dl5JhRwvaDUmO5EJixsQwTiYS+vS5sG0TzMIT2N0dyCrA4eRinORCiUzTn3zYZe4
# osCBOkhKbaiX6YkjzWhFGEarCNYwAYhleymgIy88BowoBYgwn1vx9G14hS9cEcHp
# d/oHA9RE3wgiiYW2VCYWv+8GWrBv+WCruhrzagOTl6RURC1ctkiRl6MbQ9XENvQF
# HPfs5TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
# BQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zC
# pyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf
# 1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x
# 4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEio
# ZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7ax
# xLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZ
# OjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJ
# l2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz
# 2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH
# 4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb
# 5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ
# 9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuC
# MS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0g
# ADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs
# 7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq
# 3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/
# Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9
# /HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWoj
# ayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMC
# AQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUw
# NzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2U
# tZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWC
# WgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+
# gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DP
# fNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVV
# gtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifi
# nT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x
# 5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HH
# fIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQ
# yogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70Ew
# gWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7Zr
# IGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877
# FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI
# 9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3ess
# BS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qK
# tntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I
# +ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q1
# 7r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+Mt
# ucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9J
# GYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlH
# qhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7G
# ELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlar
# Evf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8Y
# S43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0
# MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2
# IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U
# 1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt
# 281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9R
# aUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd
# 2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25L
# CHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0
# xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVV
# WcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0
# ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/
# DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd7
# 6CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEA
# AaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZ
# UEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB
# /wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgw
# gYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEF
# BQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUq
# rfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWP
# oSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3Im
# ZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhc
# UT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp
# 7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtf
# parz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu
# /CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9
# SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnM
# G3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSe
# y2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9
# xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIFQzCCBT8CAQEwZzBTMRow
# GAYDVQQLDBFJbmNpZGVudCBSZXNwb25zZTETMBEGA1UECgwKSVIgVG9vbGtpdDEg
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEGPcix6C96eoSPbV2zkB
# mJ4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgSVjRpIlISDhxo7pLNtjQsl5+3Ov546uC
# Yj3fVZST2QkwDQYJKoZIhvcNAQEBBQAEggEAhpcVh0zZ7bzsTJnEYWivoRO6k62+
# BCtKfDC0/BCYXF8yvGUNAIXI/8ujWiKHS4rukU3IvHg3Gkc/kW6+EA2qeTkKUmRr
# tFLFpsUVQpu5uvvWxpQz6x7F1zUXiAydRCM/eg4R+tOOhz6H+vecOZ98z0b8l0nu
# Pjm552zBtTYCDf7UNWvl+jC6ZrDQnnWogof0o87MfjKajiLoMRqO76TrxOHaeDeN
# m7xfklO9jMsFArVDwvLh384OuWdPHTugGBh6A2SSXsNNzmL1zcqOtpehH6RmVWUp
# 1XPSTJeilQ3lLy1mtvWi1ksEgrIIdm7hdjcx6lBnpap7b1CtbKx6qc3w4qGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjMxNDI3MTNaMC8GCSqGSIb3DQEJBDEi
# BCC7fiaZ3e0Uwccc7J4Zopz6K8ZqZtQkwNHYdbm2j/4KTjANBgkqhkiG9w0BAQEF
# AASCAgC1UvP71sa3gv1OudZ/ypnNeWfRYzT9kvWFoGWg2pj26YDeBG4uUR5oL77U
# 6wyJz0XTQg5zULsg45bgOUmsDm57IvD9t369ti5277iv/WGZ+Pbf+R4qSFrmAHBw
# r1O16HkKIolQ97VEowaQS+IaSIyuPGTCO/iCD95Ztw3eEuKwGmXRl4soTuKEWmXw
# 6h7vwcbHGziLYQ3jC7W8RNS0CEMnKzZl+vymky/cOfg9Rgzmk1BWS3XvOrBpGq1p
# ClmNST9ZU+U9qQDJKPt/jqDBW6WAd8u4Z+N1PYwcRh94Opkx4ODjIFFEilHlZK8V
# yuesIenO2OieOOFu0aFQBKiN4d7QZXA/4kZ/rTThPumqLrYrH0LpMj9j6G5xMJii
# 7+56Ydbrjoa5V8U+/Rg5WyR85eGKrwf0qVGVI2r+2mc5U3UtwTvOWJGahO+l4UQS
# LwZxdqx683/rpmUjL8jHpxC8kE1T7da2QSLZmes4cgTNASYoQUjVmo6GAwZKlmGb
# GPy2oaFIZjYnmVICamd0yqiitjIq2XegfFM6Uc6jAojCyaMaDPRXFhfMIvQBg9ac
# UrZb/4v3688Pe1LUKhdih/koy83sION3fkcjCNi3nouMo6Gsuwmt0g4iCnh0/WaM
# fs8B1DZHBeSDM23RHtAs98MU7p4hlHDhrDVoh0S7hheS7xIvSQ==
# SIG # End signature block
