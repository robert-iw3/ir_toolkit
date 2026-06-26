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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBt1oG1eaXZkXOq
# FGJ9tW9XHUGsyRPYMLcW6Cqts/Pc/KCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
# lEKgkjdOOOytMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lSIFRvb2xraXQg
# Q29kZSBTaWduaW5nMB4XDTI2MDYyNjAyMjc0OFoXDTI5MDYyNjAyMzc0OFowIjEg
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCVM7HdfviXfsMldvVuCmIVeX2nhTRWSA3FnoNQ7zd2
# lsAZuL+EkM+xZ6OiH6L5B6gZsCree2lTU0n0aNdSbNxKgzfaxFL49pteZwFI3ooS
# E+sqbAHRlG7UYrB90qWqPy6L2nh0ntu7R3IPzCbhTl6wgdT3e4axY+Bt4zZqcGY4
# XNolYl32o1h6/Xn1RDbK2RTsIblxuVYfYLdCotMldxNkE3oXBItZUoiGYNyCbnS0
# pBeBzKuJ7110b3jMhW5euch+jNqPlo7xwpAy57ut6LB/F/apn5BMhVXL0BsSIISW
# bvDg8KnX0ryWSVzEhCRDULbHFHceT8KT0j22yIYBIe19AgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUY4Zdh7We
# EeqWTl4U+JyMI+/Bv44wDQYJKoZIhvcNAQELBQADggEBAGADp8Vqkz5dS0PaRLED
# IuTzMDd6t33jfUATEmnXvHWcir5zyCZhwz+iyGI8atBuTvD9t4skDJNEf+niZneM
# Ql2/lr6nz/cGlWdZjgOAdIsj4I3MSrAwXN7fK5QjyXcCUQpzTfBifVshB7vl3006
# QYE2GwXHWt5/rJKNRHKXBdtuw9XL1iUtmgQOwHhLJ4F//Lf59Fon5KGP7Hmt8tJv
# HrfolpKc7pF7XKyO3grw2sOz7BnmVYBRGTAhVJ+E/+IFAPUsThQFila4LAsvqCPv
# 265GLrtTUiXjZOcQ0LT5ohZWcvU4fpQ3b473zxrl0IpfARI5XSlTC/T6arQoRyXU
# 4QwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEB9AyPDIBaeUQqCSN0447K0w
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgSVjRpIlISDhxo7pLNtjQsl5+3Ov546uCYj3f
# VZST2QkwDQYJKoZIhvcNAQEBBQAEggEACcjXQCjG/ohNRwNBwDSiC8Tv1s0asVm8
# gjzKcCBhAqmc2SjDZUVT/I/ZqLip+6tiDpfi+8VuZdLItDoJXAUbUhGz4ZydJ9zf
# zQTkI6VAv9muugcpGHYWvcpJGdEz3l8C3K+hQTUR6Y0Fu0wk3fvdf/FOVuVdzeje
# CDDQf0T9uOcYGX2fg4A+9RN8n553Jg0mn2ATCpl2UxKOdslFuB2Fb9qgGN675SJ9
# OnFYD9DMF0LODaq3Dy5Bg/YFK2RxfU848hcJZTYDyfP10kD4jG1y9jhzhxSRlVYB
# i834dNBO1UlYmhUSe6lbgLsSzGyfUeFjToV/F76J2iqnHCQUU3fHTqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MjFaMC8GCSqGSIb3DQEJBDEiBCDi
# /tfwHxKhoImFYuSocyvd9J2jx5Xi7zcb+jZnil0r9zANBgkqhkiG9w0BAQEFAASC
# AgA+u2CeponKNo1ISyD3NFqTmEQqR0H14YSgwA0DUW8cx8OVswfvdrqu9HZ3EOBO
# +1i1O8n49CJGOe4rsKjJrDX1XGQvFoMSP7LKO8xNX4yOXgcKe1KVAuwV617aL54H
# vkgPlb9b6foA6AnbqbFv2IR7bKJ/UskLmRZLZGs9pKoidHWvEaAaVEnq/pTuNhuH
# cAb16xVMxHzu2RJgpV316fiKCtPaNmendnhOxNjDQFQLppZO0VqaUidKkekV55nl
# mADUNqghFaVtrfPG+4MO0ThJUyMpm3mZlZu9lTd01M/5wMHYRLMNHAUDbe00tQYh
# okCPIupd1E0dGMhMsTo9Qu219++cgBH7KxcK1Nd6FQRFqPGMlHacOhT+4TNyefxR
# Y9XdQ66z+zFOR9QRRzenXurkenXrQjZQ+JziPPppq63yvdE+Sp26zAOZj1pYOgzV
# cEZVpJmYoYR8uzG6CS38fsT382d9PrpuukL77qp2et3d1aALl3pNI9V6QxDIpVSP
# Li0r9IexEsCAy2cB7ASNR3uzSSB1GegNv0VTgr2McXnbP0CKnGn24QCP8JrfsRud
# 3gEJVM7zmKoL3j7mt8bFBFJ7xqQ+iBKLA/qGAsUny335me2xdrBAG8inLGebdAnc
# rQtjtgp4IcsvsoRV8TIwqnLvHA8rEHXYE4R5m5RYv+0HAA==
# SIG # End signature block
