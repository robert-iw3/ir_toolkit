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
    [Switch]$ScanNetwork,
    [Switch]$ScanYara,
    [String]$YaraRulesDir,
    [Switch]$ScanMWCP,          # DC3-MWCP config extraction on flagged files (needs -IncludeMWCP staging)
    [String[]]$FilePath,        # Specific file(s) or directory to scan with YARA/-ScanMWCP directly,
                                # bypassing the findings-based filter. Useful for follow-on investigation
                                # of a specific artifact. Combine with -Recursive for directory crawl.
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
    NetworkC2        = "T1071 (Application Layer Protocol), T1095 (Non-Standard Port)"
    NamedPipe        = "T1559.001 (Inter-Process Communication: Component Object Model)"
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
        'java.exe','javaw.exe',                                                # Java
        'wsl.exe','wslhost.exe','bash.exe'                                     # WSL -- Linux side evades hooks; Windows child = suspicious
    )

    # Process names that legitimately use encoded commands / hidden windows at scale.
    # Do NOT flag these on -enc or -w hidden alone.
    $lowRiskProcesses = @(
        'svchost.exe','SearchIndexer.exe','SearchHost.exe','WmiPrvSE.exe',
        'msiexec.exe','TiWorker.exe','TrustedInstaller.exe',
        'SgrmBroker.exe','AggregatorHost.exe','SecurityHealthService.exe',
        'OneDrive.exe','OneDriveStandaloneUpdater.exe',
        'MicrosoftEdgeUpdate.exe','GoogleUpdate.exe','OfficeClickToRun.exe'
    )

    foreach ($wmi in $wmiProcesses) {
        $name      = $wmi.Name
        $cmdLine   = [string]$wmi.CommandLine
        $parentName = $parentMap[[int]$wmi.ParentProcessId]

        # --- Hidden process detection ---
        # A name/wildcard match alone does NOT verify identity -- malware naming itself
        # svchost.exe (or matching Mp*/Asus*/Intel* etc) would pass this check too, same
        # masquerade class as Invoke-Eradication.ps1's Test-Protected path-verification fix.
        # So a name match downgrades severity (expected PPL/vendor self-protection is the
        # common case) rather than fully suppressing the finding -- it must stay visible for
        # path/signature corroboration downstream, never silently invisible.
        $nameAllowed = ($name -in $coreAllowed) -or
                       ($coreAllowedWildcards | Where-Object { $name -like $_ })
        if (-not $apiDict.ContainsKey($wmi.ProcessId)) {
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
            if ($stillHidden -and $nameAllowed) {
                Add-Finding -Type "Hidden Process" -Target "PID: $($wmi.ProcessId)" `
                    -Details "Hidden from standard API (re-verified). Name: $name -- matches an expected self-protecting process name (PPL/vendor tooling); a name match is not identity proof, verify on-disk path + signature before treating as a rootkit indicator." `
                    -Severity "Low" -Mitre $Global:MITRE.HiddenProcess
            } elseif ($stillHidden) {
                Add-Finding -Type "Hidden Process" -Target "PID: $($wmi.ProcessId)" `
                    -Details "Hidden from standard API (re-verified). Name: $name" -Severity "High" -Mitre $Global:MITRE.HiddenProcess
            }
        }

        # --- Context-aware LOLBin scoring ---
        if (-not $cmdLine) { continue }

        # SEDR-002: comsvcs.dll MiniDump - LSASS credential dump without external tool.
        # rundll32.exe comsvcs.dll MiniDump <lsass-pid> <output-path> full
        # No benign use - emit Critical directly.
        if ($cmdLine -match '(?i)comsvcs.*minidump') {
            Add-Finding -Type "LSASS Memory Dump" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "comsvcs.dll MiniDump detected - LSASS credential dumping without external tool. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "Critical" -Mitre "T1003.001 (LSASS Memory)"
        }

        # Phase 3A: VSS deletion -- removes backup shadow copies before ransomware/wiper.
        # vssadmin delete + wmic shadowcopy delete are the two canonical mechanisms.
        # No legitimate admin script should delete ALL shadows silently.
        if ($cmdLine -match '(?i)vssadmin.*delete.*shadow' -or
            $cmdLine -match '(?i)wmic.*shadowcopy.*delete') {
            Add-Finding -Type "VSS Deletion" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Shadow copy deletion detected -- pre-ransomware/wiper indicator. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "Critical" -Mitre "T1490 (Inhibit System Recovery)"
        }

        # Phase 3B: Recovery disable via bcdedit -- prevents OS recovery after impact.
        # The specific /set subcommands that disable recovery have no legitimate admin use at scale.
        if ($cmdLine -match '(?i)bcdedit.*(/set|/deletevalue).*recoveryenabled' -or
            $cmdLine -match '(?i)bcdedit.*(/set|/deletevalue).*bootstatuspolicy') {
            Add-Finding -Type "Recovery Disable" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Boot recovery disabled -- pre-ransomware indicator. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1490 (Inhibit System Recovery)"
        }

        # Phase 3D: Archive staging -- compressed archive created in a user-writable staging area.
        # Mechanism: data collection + staging = exfil preparation, regardless of which archiver.
        # 'a' (7z/rar add), 'Compress-Archive' are the canonical creation commands.
        $archiveStagingPath = '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft))'
        if (($cmdLine -match '(?i)\b(7z|7za|7zr|rar|winrar)\b.*\ba\b' -and $cmdLine -match $archiveStagingPath) -or
            ($cmdLine -match '(?i)Compress-Archive'                      -and $cmdLine -match $archiveStagingPath)) {
            Add-Finding -Type "Archive Staging" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Archive created in staging-area path -- exfil preparation indicator. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1560 (Archive Collected Data)"
        }

        # Phase 3E: WSL suspicious execution -- WSL executes Linux binaries outside EDR hooks.
        # Flag when WSL is used to invoke network or code-execution primitives; Linux-side
        # activity (curl, wget, python -c exec, nc) is the signal, not WSL itself.
        if ($name -match '(?i)^wsl(host)?\.exe$' -and
            $cmdLine -match '(?i)(curl|wget|fetch|nc\b|netcat|python.*-c|perl.*-e|ruby.*-e|bash.*-c|sh.*-c)') {
            Add-Finding -Type "WSL Suspicious Execution" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "WSL invoking network/exec primitive -- Linux execution evades Windows hooks. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1202 (Indirect Command Execution)"
        }

        # Phase 6C: FTP / SCP raw transfer -- cleartext or encrypted raw file transfer
        # from Windows-native tools. No legitimate enterprise use runs bare ftp.exe or
        # scp.exe against external hosts; these are exfil or lateral-movement primitives.
        if ($name -match '(?i)^(ftp|scp|sftp|pscp)(\.exe)?$') {
            Add-Finding -Type "Raw File Transfer" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Raw file transfer tool in use -- cleartext/SSH exfil primitive. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1048.002 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol)"
        }

        # Phase 4A: Browser credential store access by non-browser process
        # Mechanism: attacker MUST access the browser's profile data directory to steal
        # credentials -- regardless of what they name the output file. Any non-browser
        # process with a browser profile path in its cmdline is the signal.
        $browserProfilePaths = '(?i)(\\Google\\Chrome\\User.Data\\|\\Microsoft\\Edge\\User.Data\\|\\Mozilla\\Firefox\\Profiles\\|\\Brave-Browser\\User.Data\\|\\BraveSoftware\\Brave-Browser\\User.Data\\)'
        $browserProcesses    = '(?i)^(chrome|msedge|firefox|brave|opera|vivaldi|iexplore)(\.exe)?$'
        if ($cmdLine -match $browserProfilePaths -and $name -notmatch $browserProcesses) {
            Add-Finding -Type "Browser Credential Access" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Non-browser process accessing browser profile data directory -- credential theft mechanism. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1555.003 (Credentials from Web Browsers)"
        }

        # Phase 4C: Credential hive dump via reg.exe -- SAM/SECURITY/SYSTEM hold password hashes
        # and cached credentials. No legitimate admin workflow saves these hives outside a DC
        # backup context. Any instance at the workstation level is an attack indicator.
        if ($cmdLine -match '(?i)\breg(\.exe)?\s+(save|export)\b' -and
            $cmdLine -match '(?i)\bHKLM[\\\/](SAM|SECURITY|SYSTEM)\b') {
            Add-Finding -Type "Credential Hive Dump" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Credential registry hive saved to disk -- offline hash extraction vector. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "Critical" -Mitre "T1003.002 (Security Account Manager), T1003 (OS Credential Dumping)"
        }

        # Phase 4E: Credential vault enumeration (cmdkey / vaultcmd)
        # Mechanism: listing or adding credentials to Windows Credential Manager.
        # /list and /listcreds reveal all stored credentials to the attacker.
        # /add stores attacker-controlled credentials for lateral movement.
        if ($cmdLine -match '(?i)\bcmdkey\b.*/(list|listschemas)') {
            Add-Finding -Type "Credential Vault Access" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Credential Manager enumeration -- stored credentials exposed. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1555.004 (Windows Credential Manager)"
        }
        if ($cmdLine -match '(?i)\bcmdkey\b.*/add') {
            Add-Finding -Type "Credential Vault Access" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Credential Manager store -- credential added programmatically. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "Medium" -Mitre "T1555.004 (Windows Credential Manager)"
        }
        if ($cmdLine -match '(?i)\bvaultcmd\b.*/(list|listcreds)') {
            Add-Finding -Type "Credential Vault Access" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Vault credential enumeration via vaultcmd. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1555.004 (Windows Credential Manager)"
        }

        # GAP-P01: msiexec /i http(s):// - no legitimate enterprise deployment uses raw HTTP.
        # Check before low-risk filter since msiexec is otherwise excluded from scoring.
        if ($cmdLine -match '(?i)msiexec.*(/i\s+https?://)') {
            Add-Finding -Type "LOLBin Execution" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Score=5 Indicators=[msiexec-remoteURL] CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre $Global:MITRE.EncodedCommand
        }

        # MpCmdRun.exe -DownloadFile: documented T1105 proxy download via Windows Defender CLI.
        # No legitimate administrative use -- Defender internal updates use a different code path.
        if ($name -like 'MpCmdRun.exe' -and $cmdLine -match '(?i)-DownloadFile') {
            Add-Finding -Type "LOLBin Execution" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "MpCmdRun.exe -DownloadFile detected -- T1105 proxy download via Windows Defender CLI. CMD=$($cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length)))" `
                -Severity "High" -Mitre "T1105 (Ingress Tool Transfer), T1218 (Signed Binary Proxy Execution)"
        }

        # Low-risk processes legitimately use some LOLBin indicators (encoded PS, WebClient)
        # for their own update mechanisms. Apply a 50% score penalty rather than excluding
        # them -- an attacker injecting into svchost or OneDrive MUST still be detected.
        $isLowRisk = $name -in $lowRiskProcesses
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
        # GAP-P01: additional high-confidence LOLBin patterns
        if ($cmdLine -match '(?i)regsvr32.*(/i:|scrobj)') {
            $score += 2; $reasons.Add('regsvr32-Squiblydoo')
        }
        if ($cmdLine -match '(?i)msiexec.*(/i\s+https?://)') {
            $score += 2; $reasons.Add('msiexec-remoteURL')
        }
        if ($cmdLine -match '(?i)\bwmic\b.*process\s+call\s+create') {
            $score += 2; $reasons.Add('wmic-process-create')
        }
        if ($cmdLine -match '(?i)\binstallutil\b') {
            $score += 2; $reasons.Add('installutil')
        }
        if ($cmdLine -match '(?i)\bcmstp\b') {
            $score += 2; $reasons.Add('cmstp')
        }
        if ($cmdLine -match '(?i)\bodbcconf\b') {
            $score += 2; $reasons.Add('odbcconf')
        }

        # Context multiplier: suspicious parent doubles the score
        if ($parentName -and ($parentName.ToLower() -in $highRiskParents)) {
            $score *= 2
            $reasons.Add("spawned by $parentName")
            $severity = 'Critical'

            # WSL/bash parent: emit a direct finding regardless of child score.
            # The mechanism -- running Windows code spawned from the Linux kernel side --
            # evades all Windows hooks. Any Windows process spawned this way is suspicious.
            if ($parentName -match '(?i)^(wsl|wslhost|bash)\.exe$') {
                $wslPreview = $cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length))
                Add-Finding -Type "WSL Parent Spawn" -Target "PID: $($wmi.ProcessId) ($name)" `
                    -Details "Windows process '$name' launched from WSL parent '$parentName' -- Linux-side execution evades Windows hooks. CMD=$wslPreview" `
                    -Severity "High" -Mitre "T1202 (Indirect Command Execution)"
            }
        } elseif ($score -ge 3) {
            $severity = 'High'
        }

        # SEDR-001: decode -EncodedCommand payload and re-score the decoded content.
        # The initial score already reflects the -enc flag; this pass adds score for
        # what the payload actually DOES. Nested encoding bumps score again.
        $decodedPayload = $null
        if ($cmdLine -match '(?i)(?:-enc(?:odedcommand)?)\s+([A-Za-z0-9+/=]{20,})') {
            try {
                $b64 = $Matches[1]
                # PowerShell always encodes in UTF-16LE; pad to 4-byte boundary
                $pad = switch ($b64.Length % 4) { 2 { '==' } 3 { '=' } default { '' } }
                $bytes = [System.Convert]::FromBase64String($b64 + $pad)
                $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($decoded -match '[\x20-\x7E]{10}') { $decodedPayload = $decoded }
            } catch {}
        }
        if ($decodedPayload) {
            if ($decodedPayload -match '(?i)\bIEX\b|Invoke-Expression')               { $score += 2; $reasons.Add('decoded:IEX') }
            if ($decodedPayload -match '(?i)DownloadString|DownloadFile|Net\.WebClient') { $score += 2; $reasons.Add('decoded:WebClient') }
            if ($decodedPayload -match '(?i)VirtualAlloc|WriteProcessMemory|Marshal\b') { $score += 2; $reasons.Add('decoded:shellcode-API') }
            if ($decodedPayload -match '(?i)Add-Type.*DllImport|\[Runtime\.InteropServices')  { $score += 2; $reasons.Add('decoded:PInvoke') }
            $nestedEnc = $decodedPayload -match '(?i)-enc(?:odedcommand)?|-EncodedCommand'
            if ($nestedEnc) { $score += 2; $reasons.Add('decoded:nested-encoding') }
            if ($decodedPayload -match '(?i)FromBase64String|ToBase64String')            { $score += 1; $reasons.Add('decoded:base64-in-payload') }
            if ($score -ge 3) { $severity = 'High' }
            if ($score -ge 5) { $severity = 'Critical' }
            if ($nestedEnc)   { $severity = 'Critical' }  # nested encoding is always Critical
        }

        # Low-risk process penalty: halve the score and cap severity at Medium.
        # Threshold raised to 5 (vs 3 for normal processes) so single-indicator noise
        # from legitimate update mechanisms doesn't fire, while multi-indicator injection
        # (attacker code in a trusted process host) still produces a finding.
        if ($isLowRisk) {
            $score    = [math]::Floor($score * 0.5)
            $severity = if ($severity -eq 'Critical') { 'High' } else { 'Medium' }
        }

        # Only generate a finding if score meets threshold
        if ($score -ge 3) {
            $cmdPreview = $cmdLine.Substring(0,[math]::Min(300,$cmdLine.Length))
            $payloadPreview = if ($decodedPayload) { " | Decoded=$($decodedPayload.Substring(0,[math]::Min(200,$decodedPayload.Length)))" } else { '' }
            $detail = "Score=$score Indicators=[$($reasons -join ', ')] CMD=$cmdPreview$payloadPreview"
            Add-Finding -Type "LOLBin Execution" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details $detail -Severity $severity -Mitre $Global:MITRE.EncodedCommand
        }
    }
}

function Invoke-InjectionHunt {
    Write-Console "[*] Hunting for Reflective DLL Injection / Foreign Modules..." "Cyan"

    # Process.Modules enumerates actual Win32 module list (via NtQueryProcessInformation).
    # This surfaces ALL loaded DLLs - including injected ones - not just .NET assemblies.
    $procs    = Get-Process -ErrorAction SilentlyContinue
    $sigCache = @{}

    # System-level processes that legitimately carry many unsigned/vendor DLLs.
    $trustedProcesses = @('explorer','svchost','lsass','winlogon','services','smss','csrss','wininit')

    $suspPathPattern = '(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft))'

    # MSIX / Store / SystemApps are PACKAGE-signed: the OS validates the package signature,
    # so individual DLLs (esp. self-contained .NET / NativeAOT runtimes) report 'NotSigned'
    # per-file by design. These dirs are ACL-protected and not user-controllable, so an
    # unsigned DLL here is not a meaningful injection signal - downgrade but still surface.
    $packageSignedPaths = '(?i)(\\Program Files( \(x86\))?\\WindowsApps\\|\\Windows\\SystemApps\\)'

    foreach ($p in $procs) {
        if ($p.ProcessName -in $trustedProcesses) { continue }
        try {
            $modules = $p.Modules
        } catch {
            # 32-bit process accessed from 64-bit PS raises PermissionDenied or Win32Exception
            continue
        }
        foreach ($m in $modules) {
            $dllPath = [string]$m.FileName
            if (-not $dllPath -or $dllPath -notmatch '\.dll$') { continue }

            # 1. Module loaded but file is gone from disk (classic reflective injection artifact)
            if (-not (Test-Path $dllPath -ErrorAction SilentlyContinue)) {
                Add-Finding -Type "Reflective DLL Injection" -Target "$($p.ProcessName) (PID $($p.Id))" `
                    -Details "DLL loaded but absent from disk: $dllPath" `
                    -Severity "High" -Mitre $Global:MITRE.ProcessInjection
                continue
            }

            # 2. Signature check (cached) - only for DLLs outside trusted Windows paths
            $isWindowsDLL = $dllPath -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS|assembly)\\'
            if (-not $isWindowsDLL) {
                if (-not $sigCache.ContainsKey($dllPath)) {
                    $sigCache[$dllPath] = (Get-AuthenticodeSignature -FilePath $dllPath -ErrorAction SilentlyContinue).Status
                }
                $sigStatus = $sigCache[$dllPath]
                if ($sigStatus -ne "Valid") {
                    $note = ''
                    if ($dllPath -match $packageSignedPaths) {
                        $sev  = 'Low'
                        $note = ' (MSIX/Store package-signed path - per-file Authenticode not meaningful)'
                    } elseif ($dllPath -match $suspPathPattern) {
                        $sev = 'Critical'
                    } else {
                        $sev = 'Medium'
                    }
                    Add-Finding -Type "Suspicious Injected DLL" -Target "$($p.ProcessName) (PID $($p.Id))" `
                        -Details "Unsigned DLL outside Windows paths. Sig=$sigStatus Path=$dllPath$note" `
                        -Severity $sev -Mitre $Global:MITRE.ProcessInjection
                }
            }
        }
    }
}

function Invoke-FilelessHunt {
    Write-Console "[*] Hunting for Classic Fileless Persistence..." "Cyan"

    # A WMI subscription requires all three objects to be active together.
    # Checking only __EventConsumer misses orphaned filters and active bindings
    # where the consumer name happens to match an allowlist entry.
    $wmiNS = 'root\subscription'
    $knownGoodConsumers = '(?i)^(BVTConsumer|SCM Event Log Consumer)$'

    $consumers = Get-CimInstance -Namespace $wmiNS -ClassName __EventConsumer -ErrorAction SilentlyContinue
    $filters   = Get-CimInstance -Namespace $wmiNS -ClassName __EventFilter   -ErrorAction SilentlyContinue
    $bindings  = Get-CimInstance -Namespace $wmiNS -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

    # Index by name for fast cross-reference
    $consumerMap = @{}; foreach ($c in $consumers) { $consumerMap[$c.Name] = $c }
    $filterMap   = @{}; foreach ($f in $filters)   { $filterMap[$f.Name]   = $f }

    foreach ($b in $bindings) {
        # Extract consumer and filter names from the binding reference strings.
        # Live hosts produce at least two formats:
        #   WMI-native:  __EventConsumer.Name="SCM Event Log Consumer"
        #   Registry-via: NTEventLogEventConsumer (Name = "SCM Event Log Consumer")
        # Try both; fall back to the full string so we never silently lose context.
        $cName = if     ($b.Consumer -match '__EventConsumer\.Name="([^"]+)"')  { $Matches[1] }
                 elseif ($b.Consumer -match '\(Name\s*=\s*"([^"]+)"\)')         { $Matches[1] }
                 else                                                           { [string]$b.Consumer }
        $fName = if     ($b.Filter   -match '__EventFilter\.Name="([^"]+)"')    { $Matches[1] }
                 elseif ($b.Filter   -match '\(Name\s*=\s*"([^"]+)"\)')         { $Matches[1] }
                 else                                                           { [string]$b.Filter }

        if ($cName -match $knownGoodConsumers) { continue }

        $consumer = $consumerMap[$cName]
        $filter   = $filterMap[$fName]

        $query     = if ($filter)   { $filter.Query }                 else { 'UNKNOWN' }
        $cmdOrPath = if ($consumer) { [string]$consumer.CommandLineTemplate + [string]$consumer.ScriptText } else { 'UNKNOWN' }

        Add-Finding -Type "WMI Persistence" -Target "WMI Subscription: Consumer=$cName / Filter=$fName" `
            -Details "Query=[$query] Action=[$($cmdOrPath.Substring(0,[math]::Min(300,$cmdOrPath.Length)))]" `
            -Severity "High" -Mitre $Global:MITRE.WMIPersistence
    }

    # Also flag unbound consumers that are not in the allowlist (subscription half-installed,
    # or consumer registered for later binding by a dropper).
    foreach ($c in $consumers) {
        if ($c.Name -match $knownGoodConsumers) { continue }
        $isBound = $bindings | Where-Object { $_ -match $c.Name }
        if (-not $isBound) {
            Add-Finding -Type "WMI Persistence" -Target "WMI Orphan Consumer: $($c.Name)" `
                -Details "Consumer exists without active FilterToConsumerBinding - possible partial install" `
                -Severity "Medium" -Mitre $Global:MITRE.WMIPersistence
        }
    }
    $lolbinPattern = '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|installutil|cmstp|odbcconf|msiexec)'

    # Run / RunOnce across HKLM and HKCU, including Wow6432Node (32-bit on 64-bit OS)
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $skipProps = @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")
    # Trusted install paths for Run key entries (Program Files + Windows = admin-protected).
    # Anything outside these is either a LOLBin, a staging area, or a non-standard install
    # that could be replaced. Downgrade not exclude: show all non-standard paths.
    $runKeyTrustedPath = '(?i)^("?[a-z]:\\(windows|program files|program files \(x86\))[\\/])'
    $runKeyStagingPath = '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft))'

    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        foreach ($prop in $entries.PSObject.Properties) {
            if ($prop.Name -in $skipProps) { continue }
            $val = [string]$prop.Value
            if (-not $val) { continue }

            if ($val -match $lolbinPattern) {
                # LOLBin name in Run key -- known execution proxy, regardless of path
                Add-Finding -Type "Suspicious Registry Key" -Target "$key\$($prop.Name)" `
                    -Details "LOLBin in Run Key: $val" -Severity "High" -Mitre $Global:MITRE.RegPersistence
            } elseif ($val -match $runKeyStagingPath) {
                # Custom payload in a user-writable staging area -- attacker binary, not LOLBin
                Add-Finding -Type "Suspicious Registry Key" -Target "$key\$($prop.Name)" `
                    -Details "Run Key entry points to staging-area path (attacker persistence): $val" `
                    -Severity "High" -Mitre $Global:MITRE.RegPersistence
            } elseif ($val -notmatch $runKeyTrustedPath) {
                # Non-standard install location -- downgrade not exclude (could be legitimate vendor)
                Add-Finding -Type "Suspicious Registry Key" -Target "$key\$($prop.Name)" `
                    -Details "Run Key entry outside standard install directories (verify): $val" `
                    -Severity "Medium" -Mitre $Global:MITRE.RegPersistence
            }
        }
    }

    # Winlogon Userinit and Shell - attackers append to or replace these to run at logon
    $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (Test-Path $winlogon) {
        $wl = Get-ItemProperty $winlogon -ErrorAction SilentlyContinue
        foreach ($prop in @('Userinit','Shell')) {
            $val = [string]$wl.$prop
            # Userinit should only be C:\Windows\system32\userinit.exe,
            # Shell should only be explorer.exe. Any addition is suspicious.
            $expected = if ($prop -eq 'Userinit') { '(?i)^\s*[a-z]:\\windows\\system32\\userinit\.exe,?\s*$' } `
                        else                        { '(?i)^explorer\.exe$' }
            if ($val -and $val -notmatch $expected) {
                Add-Finding -Type "Winlogon Hijack" -Target "$winlogon\$prop" `
                    -Details "Value: $val" -Severity "High" -Mitre "T1547.004 (Winlogon Helper DLL)"
            }
        }
    }

    # BootExecute - should only contain 'autocheck autochk *' on a healthy system
    $smKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $be = (Get-ItemProperty $smKey -Name BootExecute -ErrorAction SilentlyContinue).BootExecute
    foreach ($entry in $be) {
        if ($entry -and $entry -notmatch '(?i)^autocheck\s+autochk\s+\*$') {
            Add-Finding -Type "BootExecute Persistence" -Target "$smKey\BootExecute" `
                -Details "Unexpected entry: $entry" -Severity "Critical" -Mitre $Global:MITRE.RegPersistence
        }
    }

    # AppCertDLLs - loaded into every process that calls CreateProcess (T1546.009)
    # Any value here means attacker code runs inside every new process on the system.
    $appcertKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs"
    if (Test-Path $appcertKey) {
        $acProps = Get-ItemProperty -Path $appcertKey -ErrorAction SilentlyContinue
        foreach ($prop in $acProps.PSObject.Properties) {
            if ($prop.Name -in $skipProps) { continue }
            Add-Finding -Type "AppCertDLLs Injection" -Target "$appcertKey\$($prop.Name)" `
                -Details "DLL loaded into every CreateProcess caller: $($prop.Value)" `
                -Severity "Critical" -Mitre "T1546.009 (AppCertDLLs)"
        }
    }

    # Active Setup StubPath - executes per-user at first logon (T1547.014)
    # Legitimate entries are rundll32/regsvr32 with system32 DLLs only.
    $activeSetupKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"
    if (Test-Path $activeSetupKey) {
        # Known-good: bare or full-path rundll32/regsvr32 loading a system32/syswow64 DLL.
        # Live hosts use both forms: "rundll32 ..." and "C:\Windows\System32\Rundll32.exe ..."
        $knownGoodStub = '(?i)^("?[a-z]:\\windows\\(system32|syswow64)\\)?(rundll32|regsvr32)(\.exe)?\s+"?[a-z]:\\windows\\(system32|syswow64)\\[^"]+\.(dll|inf)"?'
        Get-ChildItem $activeSetupKey -ErrorAction SilentlyContinue | ForEach-Object {
            $stubPath = (Get-ItemProperty -Path $_.PSPath -Name StubPath -ErrorAction SilentlyContinue).StubPath
            if (-not $stubPath) { return }
            if ($stubPath -match $knownGoodStub) { return }
            $sev = if ($stubPath -match $lolbinPattern -or
                       $stubPath -match '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft))') {
                'High'
            } else {
                'Medium'
            }
            Add-Finding -Type "Active Setup Persistence" -Target $_.PSPath `
                -Details "StubPath runs at first user logon per-account: $stubPath" `
                -Severity $sev -Mitre "T1547.014 (Active Setup)"
        }
    }

    # LSA Security Packages and Authentication Packages - used for credential interception
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    if (Test-Path $lsaKey) {
        $lsa = Get-ItemProperty $lsaKey -ErrorAction SilentlyContinue
        foreach ($prop in @('Security Packages','Authentication Packages')) {
            $vals = @($lsa.$prop) | Where-Object { $_ -and $_ -notmatch '(?i)^("")?(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|livessp)?("")?$' }
            foreach ($v in $vals) {
                Add-Finding -Type "LSA Package Injection" -Target "$lsaKey\$prop" `
                    -Details "Unexpected package: $v" -Severity "Critical" -Mitre "T1547.005 (Security Support Provider)"
            }
        }
    }

    # Common startup folders (all users and current user)
    $startupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        if (-not (Test-Path $folder)) { continue }
        Get-ChildItem $folder -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                if ($_.Extension -match '\.(exe|dll|ps1|bat|vbs|js|hta|lnk|scr)') {
                    Add-Finding -Type "Startup Folder Entry" -Target $_.FullName `
                        -Details "File in startup folder: $($_.Name) ($(([math]::Round($_.Length/1KB,0))) KB)" `
                        -Severity "Medium" -Mitre $Global:MITRE.RegPersistence
                }
            }
    }

    Invoke-LsassDumpHunt
}

function Invoke-AdvancedRegistryHunt {
    Write-Console "[*] Expanded Registry Persistence (IFEO, AppInit_DLLs, Services)..." "Cyan"

    # Accessibility binaries at the Windows login screen run as SYSTEM.
    # Any IFEO Debugger on these binaries gives an attacker a SYSTEM shell without auth (T1546.008).
    $accessBinaries = @('sethc.exe','utilman.exe','magnify.exe','osk.exe',
                        'narrator.exe','displayswitch.exe','atbroker.exe')

    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        Get-ChildItem $ifeoPath | ForEach-Object {
            $binName = $_.PSChildName
            $binPath = $_.PSPath

            # Accessibility feature hijack -- any debugger value is Critical
            if ($binName -in $accessBinaries) {
                $dbg = Get-ItemProperty -Path $binPath -Name "Debugger" -ErrorAction SilentlyContinue
                if ($dbg.Debugger) {
                    Add-Finding -Type "Accessibility Feature Hijack" -Target $binPath `
                        -Details "Accessibility binary '$binName' has Debugger: $($dbg.Debugger). Activating the accessibility key at the login screen yields a SYSTEM shell." `
                        -Severity "Critical" -Mitre "T1546.008 (Accessibility Features)"
                }
            }

            # IFEO GlobalFlag 0x200 (FLG_APPLICATION_VERIFIER) + SilentProcessExit = silent exec replace
            $gfProp = Get-ItemProperty -Path $binPath -Name "GlobalFlag" -ErrorAction SilentlyContinue
            if ($gfProp.GlobalFlag -and ($gfProp.GlobalFlag -band 0x200)) {
                $monPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$binName"
                $monitored = Test-Path $monPath
                $flagNote = if ($monitored) { 'SilentProcessExit key present -- process replacement vector active.' } `
                            else { 'No SilentProcessExit key detected; monitor for addition.' }
                Add-Finding -Type "IFEO GlobalFlag Hijack" -Target $binPath `
                    -Details "GlobalFlag=0x$($gfProp.GlobalFlag.ToString('X')) on '$binName' (bit 0x200 set). $flagNote" `
                    -Severity "High" -Mitre $Global:MITRE.RegIFEO
            }

            # IFEO Debugger on any process -- the mechanism itself is the threat:
            # every launch of $binName will silently run the Debugger binary first.
            # Severity is driven by WHERE the debugger binary lives, not what it is named.
            # A custom attacker .exe in Temp is just as dangerous as powershell.
            $dbg2 = Get-ItemProperty -Path $binPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($dbg2.Debugger -and $binName -notin $accessBinaries) {
                $dbgVal = $dbg2.Debugger
                $sev = if ($dbgVal -match '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft))') {
                    'High'    # debugger lives in a user-writable staging location
                } elseif ($dbgVal -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|installutil|cmstp|odbcconf|msiexec)') {
                    'High'    # debugger is a known LOLBin
                } else {
                    'Medium'  # any other binary -- may be legitimate (WinDbg) or custom attacker payload
                }
                Add-Finding -Type "IFEO Debugger Hijack" -Target $binName `
                    -Details "Launch of '$binName' silently runs Debugger first: $dbgVal" `
                    -Severity $sev -Mitre $Global:MITRE.RegIFEO
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
    # $lolbinPattern is local to Invoke-FilelessHunt -- define separately here
    # to avoid PowerShell function-scope leakage ($null pattern matches everything).
    $svcLolbinPattern = '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|installutil|cmstp|odbcconf)'
    $svcStagingPath   = '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft\\(Windows|Windows Defender)))'
    # Trusted install locations: Windows system dirs, Program Files, and Defender's versioned update path.
    $svcTrustedPath   = '(?i)^("?[a-z]:\\(windows|program files|program files \(x86\)|ProgramData\\Microsoft\\Windows Defender)[\\/])'

    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        $path = [string]$svc.PathName
        if (-not $path) { continue }

        # Extract the binary path only (before arguments) so that log/config paths
        # in service arguments don't trigger the staging-area check.
        # Handles: "C:\path\binary.exe" args   and   C:\path\binary.exe args
        $binaryPath = if ($path -match '^"([^"]+\.(?:exe|dll|sys))"') {
            $Matches[1]
        } elseif ($path -match '^([^\s]+\.(?:exe|dll|sys))') {
            $Matches[1]
        } else {
            $path
        }

        if ($path -match $svcLolbinPattern -or $binaryPath -match $svcStagingPath) {
            # LOLBin or custom binary in staging location -- high-confidence attack indicator
            Add-Finding -Type "Suspicious Service" -Target "$($svc.Name) ($path)" `
                -Details "Service binary is a LOLBin or in a staging-area path. Path=$path StartMode=$($svc.StartMode)" `
                -Severity "High" -Mitre $Global:MITRE.ServiceTamper
        } elseif ($binaryPath -notmatch $svcTrustedPath) {
            # Service binary outside standard install directories -- downgrade not exclude
            Add-Finding -Type "Suspicious Service" -Target "$($svc.Name) ($path)" `
                -Details "Service binary outside standard install directories (verify). Path=$path StartMode=$($svc.StartMode)" `
                -Severity "Medium" -Mitre $Global:MITRE.ServiceTamper
        }

        # Unquoted service path with spaces -- attacker places executable in a parent directory
        # to intercept before the real binary. System32 paths rarely have exploitable spaces.
        if ($path -and -not $path.StartsWith('"') -and
            $path -match '^[^"]*\s[^"]*\.(exe|dll|sys)' -and
            $path -notmatch '(?i)^[a-z]:\\windows\\') {
            Add-Finding -Type "Unquoted Service Path" -Target $svc.Name `
                -Details "ImagePath has unquoted spaces -- place a binary in a parent directory to hijack: $path" `
                -Severity "High" -Mitre "T1574.009 (Path Interception by Unquoted Path)"
        }
    }

    # Phase 4D: Port monitor / print processor DLL hunt (T1547.010)
    # Mechanism: DLL registered here is loaded by spoolsv.exe in SYSTEM context at boot.
    # All legitimate Windows port monitors install into system32 or syswow64.
    # A DLL outside that path is almost certainly attacker-planted persistence.
    $printMonKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
    if (Test-Path $printMonKey) {
        Get-ChildItem $printMonKey -ErrorAction SilentlyContinue | ForEach-Object {
            $driver = (Get-ItemProperty -Path $_.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver
            if (-not $driver) { return }

            $hasSep = $driver -match '\\'  # bare name (no path) = Windows resolves against system32
            $sev = if ($hasSep -and $driver -match '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft))') {
                'Critical'  # full path into staging area
            } elseif ($hasSep -and $driver -notmatch '(?i)^("?[a-z]:\\windows\\(system32|syswow64)\\)') {
                'High'      # full path outside system32 = suspicious vendor or attacker DLL
            } elseif (-not $hasSep) {
                # Bare name: Windows resolves to system32. Known Windows monitors
                # (localspl, tcpmon, usbmon, wsdmon, pjlmon, fxsmon, appmon, virtualmon)
                # are expected. Unknown bare names are a DLL search-order risk.
                $knownMonitors = '(?i)^(localspl|tcpmon|usbmon|wsdmon|pjlmon|fxsmon|appmon|apmon|virtualmon|cnmlm|rktmon)\.dll$'
                if ($driver -notmatch $knownMonitors) { 'Medium' } else { $null }
            } else {
                $null  # system32 full path = expected
            }
            if ($sev) {
                Add-Finding -Type "Suspicious Print Monitor DLL" -Target "$($_.PSPath)\Driver" `
                    -Details "Port monitor DLL loaded by SYSTEM-context spoolsv.exe at boot: $driver" `
                    -Severity $sev -Mitre "T1547.010 (Port Monitors)"
            }
        }
    }
}

function Invoke-LsassDumpHunt {
    Write-Console "[*] Hunting for LSASS memory dump artifacts..." "Cyan"
    # Minimum size for a real LSASS dump: ~10 MB on a minimally-loaded system.
    # ProcDump and comsvcs MiniDump both produce files in this range.
    $MinDumpBytes = 10MB
    $ScanRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @($env:TEMP, $env:TMP, "$env:SystemDrive\Windows\Temp",
                     "$env:SystemDrive\Users\Public", "$env:SystemDrive\ProgramData")) {
        if ($p -and (Test-Path $p)) { $ScanRoots.Add($p) }
    }
    foreach ($user in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
        foreach ($sub in @('AppData\Local\Temp','Documents','Desktop','Downloads')) {
            $full = Join-Path $user.FullName $sub
            if (Test-Path $full) { $ScanRoots.Add($full) }
        }
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $allOpts = [System.IO.SearchOption]::AllDirectories
    foreach ($root in ($ScanRoots | Select-Object -Unique)) {
        foreach ($ext in @('*.dmp','*.mdmp')) {
            try {
                foreach ($filePath in [System.IO.Directory]::EnumerateFiles($root, $ext, $allOpts)) {
                    if (-not $seen.Add($filePath)) { continue }
                    try {
                        $fi = [System.IO.FileInfo]::new($filePath)
                        if ($fi.Length -ge $MinDumpBytes) {
                            $lsassName = $fi.Name -match '(?i)lsass|lsas\d+|debug|cred'
                            $sev = if ($lsassName) { 'Critical' } else { 'High' }
                            Add-Finding -Type "LSASS Memory Dump" -Target $fi.FullName `
                                -Details "Dump file in user-writable path ($([math]::Round($fi.Length/1MB,1)) MB). Name: $($fi.Name)" `
                                -Severity $sev -Mitre "T1003.001 (LSASS Memory)"
                        }
                    } catch {}
                }
            } catch {}
        }
    }
}

function Invoke-BITSHunt {
    Write-Console "[*] Hunting for Suspicious BITS Jobs..." "Cyan"
    # Behavior-only detection. Display names and CDN hostnames are attacker-controlled
    # (an attacker names their job 'MicrosoftEdgeUpdate' and routes through cloudfront.net).
    # The MECHANISM is: executable/script downloaded to a staging area, OR from a bare IP.
    # Destination path and URL structure are the signals -- not the job name or domain.

    # Staging-area destinations: files here are staged for execution, not installed
    $suspDestPattern = '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft\\Windows\\(?:Start Menu|WindowsUpdate)))'
    # Source URL indicators: executable types or direct IP (domain fronting can't be detected by hostname)
    $suspUrlPattern  = '(?i)\.(exe|dll|ps1|bat|vbs|js|hta|msi|scr)(\?|$)|:\\/\\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    # Protected install destinations: not a staging area, likely a real software update
    $protectedDestPattern = '(?i)^("?[a-z]:\\(windows|program files|program files \(x86\))[\\/])'

    $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    foreach ($job in $jobs) {
        $src  = ''
        $dest = ''
        try {
            $fl   = $job.FileList | Select-Object -First 1
            $src  = [string]$fl.RemoteName
            $dest = [string]$fl.LocalName
        } catch {}

        $suspDest = $dest -and $dest -match $suspDestPattern
        $suspUrl  = $src  -and $src  -match $suspUrlPattern
        $protectedDest = $dest -and $dest -match $protectedDestPattern

        $reason = [System.Collections.Generic.List[string]]::new()
        if ($suspDest) { $reason.Add('StagingDestination') }
        if ($suspUrl)  { $reason.Add('SuspiciousURL') }

        if ($suspDest -or $suspUrl) {
            # Staging destination is the primary signal: attacker moves the payload here
            # before execution. Executable URL without staging = downgrade (could be real update).
            $sev = if ($suspDest) { 'High' } elseif (-not $protectedDest) { 'High' } else { 'Medium' }
            Add-Finding -Type "Suspicious BITS Job" -Target "Job: $($job.DisplayName)" `
                -Details "Flags=[$($reason -join '|')] URL=$src Dest=$dest State=$($job.JobState)" `
                -Severity $sev -Mitre $Global:MITRE.BITSJob
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

    # AMSI provider registry
    $amsiProv = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path $amsiProv) {
        $count = (Get-ChildItem $amsiProv -ErrorAction SilentlyContinue).Count
        if ($count -eq 0) {
            Add-Finding -Type "AMSI Tampering" -Target "AMSI Providers" `
                -Details "0 providers registered. AMSI is completely blinded." -Severity "Critical" -Mitre $Global:MITRE.AMSITampering
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

    # ETW Autologger sessions disabled
    $auto = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
    if (Test-Path $auto) {
        foreach ($s in (Get-ChildItem $auto -ErrorAction SilentlyContinue)) {
            $enabled = Get-ItemProperty -Path $s.PSPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 0) {
                Add-Finding -Type "ETW Tampering" -Target $s.PSChildName `
                    -Details "Autologger session disabled" -Severity "High" -Mitre $Global:MITRE.ETWTampering
            }
        }
    }

    # Critical event log channels - stopped or max-size weaponized
    $criticalChannels = @(
        @{ Name = 'Security';                    Log = 'Security' }
        @{ Name = 'System';                      Log = 'System' }
        @{ Name = 'Microsoft-Windows-Sysmon/Operational'; Log = 'Microsoft-Windows-Sysmon/Operational' }
        @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; Log = 'Microsoft-Windows-Windows Defender/Operational' }
    )
    foreach ($ch in $criticalChannels) {
        try {
            $log = Get-WinEvent -ListLog $ch.Log -ErrorAction Stop
            if (-not $log.IsEnabled) {
                Add-Finding -Type "ETW Tampering" -Target "EventLog: $($ch.Name)" `
                    -Details "Critical event log channel disabled - logging gap created" `
                    -Severity "Critical" -Mitre $Global:MITRE.ETWTampering
            } elseif ($log.MaximumSizeInBytes -gt 0 -and $log.MaximumSizeInBytes -lt 1048576) {
                Add-Finding -Type "ETW Tampering" -Target "EventLog: $($ch.Name)" `
                    -Details "Max log size set to $([math]::Round($log.MaximumSizeInBytes/1KB,0)) KB - tiny size rotates log almost immediately, weaponized to lose events" `
                    -Severity "High" -Mitre $Global:MITRE.ETWTampering
            }
        } catch {}
    }

    # Windows Error Reporting disabled - suppresses crash dump uploads (attacker hides crashes)
    $werKey = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
    if (Test-Path $werKey) {
        $wer = Get-ItemProperty $werKey -ErrorAction SilentlyContinue
        if ($wer.Disabled -eq 1) {
            Add-Finding -Type "ETW Tampering" -Target "Windows Error Reporting" `
                -Details "WER disabled - crash telemetry and dump uploads suppressed" `
                -Severity "Medium" -Mitre $Global:MITRE.ETWTampering
        }
    }
}

function Invoke-PendingRenameHunt {
    Write-Console "[*] Checking PendingFileRenameOperations (MoveEDR)..." "Cyan"
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $val = Get-ItemProperty -Path $key -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    $entries = @($val.PendingFileRenameOperations) | Where-Object { $_ }
    if (-not $entries) { return }

    # Security-relevant targets: EDR/AV agents and their supporting files.
    # Windows itself creates benign entries for installer cleanup (MsiExec, .tmp files).
    $securityToolPattern = '(?i)(MsMpEng|MpCmdRun|MpDefenderCore|MpDlp|NisSrv|SenseCncProxy|SenseIR|MsSense|' +
                           'Sysmon|Sysmon64|WdFilter|WdNisDrv|WdBoot|' +
                           'csagent|csfalcon|CSFalconService|' +   # CrowdStrike
                           'SentinelAgent|SentinelOne|sentinel\.exe|' +
                           'MDE|mdatp|wdavdaemon|' +
                           'cbdefense|CarbonBlack|' +
                           'elastic-endpoint|' +
                           'edrsensor|edrserver)'
    $suspDestPattern = '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|NUL$|^$)'

    $hitEntries   = [System.Collections.Generic.List[string]]::new()
    $criticalHits = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        if (-not $entry) { continue }
        if ($entry -match $securityToolPattern) { $criticalHits.Add($entry) }
        # Destination is the NEXT entry (rename pairs: source, dest, source, dest...)
        elseif ($i -gt 0 -and $entries[$i-1] -match $securityToolPattern -and $entry -match $suspDestPattern) {
            $criticalHits.Add("$($entries[$i-1]) -> $entry")
        } elseif ($entry -match $securityToolPattern -or ($i % 2 -eq 1 -and $entry -match $suspDestPattern)) {
            $hitEntries.Add($entry)
        }
    }

    if ($criticalHits.Count -gt 0) {
        Add-Finding -Type "PendingFileRenameOperations" -Target "Session Manager" `
            -Details "Security tool targeted for boot-time rename/deletion: $($criticalHits -join '; ')" `
            -Severity "Critical" -Mitre $Global:MITRE.PendingRename
    } elseif ($hitEntries.Count -gt 0) {
        Add-Finding -Type "PendingFileRenameOperations" -Target "Session Manager" `
            -Details "Pending renames present including suspicious destinations: $($hitEntries -join '; ')" `
            -Severity "High" -Mitre $Global:MITRE.PendingRename
    } else {
        # Generic - entries exist but don't match security tools (likely legitimate installer cleanup)
        Add-Finding -Type "PendingFileRenameOperations" -Target "Session Manager" `
            -Details "Entries present ($($entries.Count)) - review manually. Common source: Windows Installer cleanup." `
            -Severity "Low" -Mitre $Global:MITRE.PendingRename
    }
}

function Invoke-DriverHunt {
    Write-Host "[*] Hunting Loaded Drivers & Known Vulnerable (BYOVD)..." -ForegroundColor Cyan

    # Static name list - fast pre-filter only. A renamed driver bypasses this;
    # hash-based detection below is the rename-resistant primary signal.
    $knownVulnNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(
        "capcom.sys","iqvw64.sys","RTCore64.sys","DBUtil_2_3.sys","TfSysMon.sys",
        "gdrv.sys","AsrDrv.sys","AsrDrv101.sys","AsrDrv102.sys","AsrDrv103.sys",
        "AsrDrv104.sys","AsrDrv105.sys","amifldrv64.sys","AMIFLDRV.sys",
        "aswArPot.sys","aswSP.sys","BdApiUtil64.sys","ksapi64.sys","ksapi64_del.sys",
        "NSecKrnl.sys","TrueSight.sys","ThrottleStop.sys","probmon.sys","IoBitUnlocker.sys",
        "Zemana.sys","kavservice.sys","agent64.sys","AODDriver.sys","ASUS.sys",
        "ASMMAP.sys","ASRDRV.sys","DBUtil.sys","DBUtil_2_3_0_4.sys",
        "MsIo64.sys","MsIo64_2.sys","WinRing0x64.sys","WinRing0.sys",
        "Truesight.sys","wsftprm.sys","BdApiUtil.sys","K7RKScan.sys",
        "CcProtect.sys","ProcessMonitorDriver.sys","Safetica.sys"
    ) | ForEach-Object { $null = $knownVulnNames.Add($_) }

    # SHA256 hash set populated from loldrivers.io API or offline cache.
    # Catches renamed BYOVD drivers that still contain identical bytes.
    $knownVulnHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $lolCache = Join-Path $PSScriptRoot '..\..\..\..\..\tools\loldrivers.json'

    $apiDrivers = $null
    if ($AutoUpdateDrivers) {
        $loaded = $false
        try {
            Write-Host "[*] Fetching latest vulnerable drivers from loldrivers.io..." -ForegroundColor Cyan
            $apiDrivers = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json" -Method Get -ErrorAction Stop
            Write-Host "[+] Loaded $($apiDrivers.Count) records from loldrivers.io" -ForegroundColor Green
            $loaded = $true
        } catch {
            Write-Host "[-] Could not reach loldrivers.io. Checking offline cache..." -ForegroundColor Yellow
        }
        if (-not $loaded -and (Test-Path $lolCache)) {
            try {
                $apiDrivers = Get-Content $lolCache -Raw | ConvertFrom-Json
                Write-Host "[+] Loaded $($apiDrivers.Count) records from offline cache" -ForegroundColor Green
            } catch {
                Write-Host "[-] Offline cache unreadable. Using built-in list only." -ForegroundColor Yellow
            }
        } elseif (-not $loaded) {
            Write-Host "[-] No offline cache found. Using built-in names only." -ForegroundColor Yellow
        }
    } elseif (Test-Path $lolCache) {
        # Always load offline cache for hashes even without -AutoUpdateDrivers
        try {
            $apiDrivers = Get-Content $lolCache -Raw | ConvertFrom-Json
            Write-Host "[+] Loaded hash index from offline cache ($($apiDrivers.Count) records)" -ForegroundColor Gray
        } catch {}
    }

    if ($apiDrivers) {
        foreach ($d in ($apiDrivers | Where-Object { $_.KnownVulnerable })) {
            # Add names from API to the name set
            $fnames = if ($d.Filename -is [array]) { $d.Filename } else { @($d.Filename) }
            foreach ($fn in $fnames) { if ($fn) { $null = $knownVulnNames.Add($fn) } }

            # Add all SHA256 hashes (file hash + PE authentihash) for rename-resistant matching.
            # loldrivers stores both $.SHA256[] (file hash) and $.Authentihash.SHA256[] (PE hash).
            foreach ($h in @($d.SHA256)) { if ($h) { $null = $knownVulnHashes.Add($h.ToUpper()) } }
            if ($d.Authentihash -and $d.Authentihash.SHA256) {
                foreach ($h in @($d.Authentihash.SHA256)) { if ($h) { $null = $knownVulnHashes.Add($h.ToUpper()) } }
            }
        }
        Write-Host "[*] BYOVD index: $($knownVulnNames.Count) names | $($knownVulnHashes.Count) hashes" -ForegroundColor Cyan
    }

    # Paths where legitimate vendor drivers normally reside. An unsigned driver
    # OUTSIDE these paths is far more suspicious than one inside System32\drivers.
    $trustedDriverPaths = '(?i)(\\System32\\drivers\\|\\SysWOW64\\drivers\\|\\SystemRoot\\|Windows\\inf\\)'

    $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue
    foreach ($drv in $drivers) {
        if ([string]::IsNullOrWhiteSpace($drv.Name)) { continue }

        $nameHit    = $knownVulnNames.Contains($drv.Name)
        $hashHit    = $false
        $fileHash   = ''
        $sigStatus  = 'N/A'
        $isUnsigned = $false

        $hasFile = -not [string]::IsNullOrWhiteSpace($drv.PathName) -and
                   (Test-Path -Path $drv.PathName -ErrorAction SilentlyContinue)

        if ($hasFile) {
            $sig = Get-AuthenticodeSignature -FilePath $drv.PathName -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus  = $sig.Status
                $isUnsigned = ($sig.Status -ne 'Valid')
            }
            if ($knownVulnHashes.Count -gt 0) {
                try {
                    $fileHash = (Get-FileHash -Path $drv.PathName -Algorithm SHA256 -ErrorAction Stop).Hash
                    $hashHit  = $knownVulnHashes.Contains($fileHash)
                } catch {}
            }
        }

        # Unsigned driver only matters if it is outside the trusted driver path -
        # many legitimate vendor drivers have broken/expired certs in System32\drivers.
        $suspiciousUnsigned = $isUnsigned -and $drv.PathName -and
                              ($drv.PathName -notmatch $trustedDriverPaths)

        if (-not ($hashHit -or $nameHit -or $suspiciousUnsigned)) { continue }

        $basis = [System.Collections.Generic.List[string]]::new()
        if ($hashHit)           { $basis.Add("HASH-MATCH:$($fileHash.Substring(0,16))...") }
        if ($nameHit)           { $basis.Add("NAME-MATCH:$($drv.Name)") }
        if ($suspiciousUnsigned){ $basis.Add("UNSIGNED-SUSPICIOUS-PATH") }

        # Hash match is highest confidence (rename-resistant); name match is medium;
        # unsigned-in-bad-path is informational without other evidence.
        $sev = if ($hashHit) { 'Critical' } elseif ($nameHit) { 'High' } else { 'Medium' }

        Add-Finding -Type "Suspicious Kernel Driver" `
            -Target "$($drv.DisplayName) ($($drv.PathName))" `
            -Details "Detection=[$($basis -join '|')] Signed=$sigStatus$(if($fileHash){" SHA256=$fileHash"})" `
            -Severity $sev -Mitre $Global:MITRE.BYOVD
    }
}

function Invoke-ScheduledTaskHunt {
    Write-Console "[*] Hunting Scheduled Tasks for suspicious persistence..." "Cyan"
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }

    $userWritablePaths = '(?i)(\\Users\\(?!Public\\Windows\\)|\\AppData\\|\\Temp\\|\\ProgramData\\(?!Microsoft\\Windows\\))'

    # Path patterns that make a missing binary genuinely suspicious (fileless loaders
    # drop here and self-delete). A missing binary under Program Files / Windows is
    # almost always a stale task left after an uninstall - not a threat.
    $suspiciousDropPaths = '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft\\Windows\\)|\\Downloads\\)'

    foreach ($task in $tasks) {
        $cmdLine = ""
        $exePath = ""
        if ($task.Actions) {
            # Only MSFT_TaskExecAction has an Execute property. COM-handler actions
            # (MSFT_TaskComHandlerAction) expose ClassId instead - guard against both
            # so -ExpandProperty / property access never throws on a COM task.
            $execActions = @($task.Actions | Where-Object { $_.PSObject.Properties['Execute'] -and $_.Execute })
            if ($execActions.Count -gt 0) {
                $cmdLine = ($execActions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join " "
                $exePath = [string]$execActions[0].Execute
            }
        }

        # --- GAP-D02: structural checks ---

        # Binary-not-on-disk: fileless loaders often clean up the binary post-execution.
        if ($exePath -and $exePath -notmatch '(?i)^cmd|^powershell|^pwsh|^wscript|^cscript|^mshta') {
            # Strip surrounding quotes and expand environment variables (%windir% etc.)
            # before resolving, or every env-var-pathed vendor task is a false positive.
            $resolvedExe = $exePath -replace '^"([^"]+)".*$','$1'
            $resolvedExe = [System.Environment]::ExpandEnvironmentVariables($resolvedExe)
            $onDisk = $true
            if ($resolvedExe -match '^[A-Za-z]:\\') {
                $onDisk = Test-Path -LiteralPath $resolvedExe -ErrorAction SilentlyContinue
            }
            if (-not $onDisk) {
                # Only Critical when the missing binary lived in a suspicious drop path;
                # a missing Program Files/Windows binary is a stale uninstall remnant.
                if ($resolvedExe -match $suspiciousDropPaths) {
                    Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                        -Details "BinaryNotOnDisk: Enabled task, binary missing from suspicious path. Exe=$exePath" `
                        -Severity "Critical" -Mitre $Global:MITRE.ScheduledTask
                } else {
                    Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                        -Details "BinaryNotOnDisk: Enabled task, binary missing (likely stale/uninstalled). Exe=$exePath" `
                        -Severity "Low" -Mitre $Global:MITRE.ScheduledTask
                }
            }
        }

        # SYSTEM task with binary in user-writable path (privilege escalation vector)
        $runAsSystem = $false
        try {
            $p = $task.Principal
            if ($p.UserId -match '(?i)SYSTEM|S-1-5-18' -or $p.RunLevel -eq 'HighestAvailable') { $runAsSystem = $true }
        } catch {}
        if ($runAsSystem -and $exePath -match $userWritablePaths) {
            # The privesc premise is "a standard user can overwrite this SYSTEM-run binary."
            # A validly-signed binary is NOT attacker-controllable, so verify the signature
            # before calling it Critical. This keeps the detection generic (no vendor names)
            # while downgrading legit signed binaries that live under ProgramData - e.g.
            # Defender's "C:\ProgramData\Microsoft\Windows Defender\Platform\<ver>\MpCmdRun.exe".
            $resolvedSys = $exePath -replace '^"([^"]+)".*$','$1'
            $resolvedSys = [System.Environment]::ExpandEnvironmentVariables($resolvedSys)
            $sysSig = $null
            if (Test-Path -LiteralPath $resolvedSys -ErrorAction SilentlyContinue) {
                $sysSig = (Get-AuthenticodeSignature -LiteralPath $resolvedSys -ErrorAction SilentlyContinue).Status
            }
            if ($sysSig -eq 'Valid') {
                Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                    -Details "SYSTEM-SignedBinaryNonStdPath: SYSTEM task runs a SIGNED binary from a non-standard (ProgramData/user) path - low risk, file not user-controllable. Exe=$exePath" `
                    -Severity "Low" -Mitre $Global:MITRE.ScheduledTask
            } else {
                Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                    -Details "SYSTEM-UserWritableBinary: SYSTEM task binary UNSIGNED in user-writable path (privilege-escalation vector). Sig=$sysSig Exe=$exePath" `
                    -Severity "Critical" -Mitre $Global:MITRE.ScheduledTask
            }
        }

        # UNC path execution (lateral movement / network-backed persistence)
        if ($exePath -match '^\\\\' -or $cmdLine -match '(?i)\\\\[a-z0-9._-]+\\[a-z$]') {
            Add-Finding -Type "Suspicious Scheduled Task" -Target "Task: $($task.TaskName)" `
                -Details "UNCPathExecution: Task executes from network path. Exe=$exePath" `
                -Severity "High" -Mitre $Global:MITRE.ScheduledTask
        }

        # --- Score-based LOLBin / obfuscation detection ---
        $score   = 0
        $taskSev = 'High'

        if ($cmdLine -match '(?i)-enc\b|-encodedcommand')                          { $score += 3 }
        if ($cmdLine -match '(?i)\bIEX\b|Invoke-Expression')                       { $score += 3 }
        if ($cmdLine -match '(?i)DownloadString|DownloadFile|WebClient')           { $score += 3 }
        if ($cmdLine -match '(?i)mshta\b')                                         { $score += 3 }
        if ($cmdLine -match '(?i)certutil.*-decode|certutil.*-urlcache')           { $score += 3 }
        if ($cmdLine -match '(?i)bitsadmin.*/transfer')                            { $score += 3 }
        if ($cmdLine -match '(?i)regsvr32.*(/i:|scrobj)')                            { $score += 3 }
        if ($cmdLine -match '(?i)msiexec.*(/i\s+https?://)')                      { $score += 3 }
        if ($cmdLine -match '(?i)\bwmic\b.*process\s+call\s+create')              { $score += 3 }
        if ($cmdLine -match '(?i)installutil|cmstp|odbcconf')                     { $score += 3 }
        if ($cmdLine -match '(?i)-w\s+hid|-windowstyle\s+hid')                    { $score += 1 }
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

# Single source of truth for the magic-byte masquerade severity decision. A PE with a
# non-PE extension is a real dropper signal only in user-writable locations; under
# ACL-protected install/staging trees (Windows Installer cache, vendor package dirs) a
# PE-in-.tmp/.bin is expected, so it is surfaced at Low rather than High.
$script:MagicHighRiskPaths = '(?i)(\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\\$Recycle\.Bin\\)'

function Get-MagicByteSeverity {
    param([string]$Path)
    if ($Path -match $script:MagicHighRiskPaths) { 'High' } else { 'Low' }
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

        # Bitdefender quarantine -- encrypted containers, no file-hunt value
        "*Bitdefender*", "*Symantec*", "*Trend Micro*", "*Sophos*", "*ESET*",

        # Vendor uninstaller temp directories - signed vendor files, high-entropy
        # legitimately (compressed payload bundles, NativeAOT, packed JS).
        "*\AppData\Local\Temp\TiUninst*",   # Trend Micro Maximum Security uninstaller
        "*\AppData\Local\Temp\Ti*",          # Trend Micro temp prefix (TmJs*, PrivacyScanner)
        "*\.vscode\extensions\*",            # VS Code extension bundles (Roslyn NativeAOT etc.)
        "*\AppData\Local\Programs\Microsoft VS Code\*"
    )

    $ActiveExclusions = $BaseExcludedDirs + $ExcludePaths

    Write-Console "[*] High-Speed File Hunt in: $Path $(if($QuickMode){'(QuickMode)'}) $(if($LowMemoryMode){'(LowMemory)'})" "Cyan"

    $filesToScan     = [System.Collections.Generic.List[string]]::new()
    $magicCheckFiles = [System.Collections.Generic.List[string]]::new()
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
                    # GAP-FL01: expanded script/link/dropper extensions
                    if ($file.Extension -match "\.(exe|dll|sys|ps1|bat|vbs|js|hta|lnk|scr|vbe|jse)$") {
                        $fileAttr = $file.Attributes.ToString()
                        if ($fileAttr -match "Offline|RecallOnData|RecallOnOpen|ReparsePoint") { continue }
                        if ($QuickMode -and $file.LastWriteTime -lt $QuickModeCutoff -and
                            $file.CreationTime -lt $QuickModeCutoff) { continue }
                        if ($file.Length -le $MaxSizeBytes) {
                            $filesToScan.Add($file.FullName)
                        }
                    }
                    # GAP-FL02: common disguise extensions - checked only for MZ magic-byte
                    elseif ($file.Extension -match "\.(jpg|jpeg|png|gif|bmp|pdf|dat|tmp|bin|log|docx?|xlsx?)$" -and
                            $file.Length -ge 2 -and $file.Length -le $MaxSizeBytes) {
                        $magicCheckFiles.Add($file.FullName)
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

    # GAP-FL02: non-PE extensions that should never carry an MZ (PE) header
    $nonPeExtList = [string[]]@('.ps1','.bat','.cmd','.vbs','.js','.hta','.lnk','.vbe','.jse')

    # Magic-byte masquerade severity is path-tiered (see Get-MagicByteSeverity). The runspace
    # block cannot see script-scope functions, so it receives the pattern by value and applies
    # the same match inline - $script:MagicHighRiskPaths is the single source of truth.
    $magicHighRiskPaths = $script:MagicHighRiskPaths

    # -- Lightweight magic-byte-only scriptblock for camouflage extensions --
    $magicOnlyBlock = {
        param([string[]]$fileList, [string]$HighRiskPaths)
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($filePath in $fileList) {
            try {
                $fs  = [System.IO.File]::OpenRead($filePath)
                $hdr = New-Object byte[] 4
                $n   = $fs.Read($hdr, 0, 4)
                $fs.Close()
                if ($n -ge 2 -and $hdr[0] -eq 0x4D -and $hdr[1] -eq 0x5A) {
                    $ext = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()
                    if ($HighRiskPaths -and $filePath -match $HighRiskPaths) {
                        $sev = 'High'; $msg = "PE (MZ) header in $ext file in a user-writable path - executable disguised as non-executable"
                    } else {
                        $sev = 'Low';  $msg = "PE (MZ) header in $ext file under an install/staging tree (likely installer cache or packaged resource)"
                    }
                    $results.Add([PSCustomObject]@{
                        Type="MagicByte Mismatch"; Target=$filePath
                        Details=$msg
                        Severity=$sev; Mitre="T1036.008"
                    })
                }
            } catch {}
        }
        return $results
    }

    # -- Worker scriptblock -------------------------------------------------
    $huntingBlock = {
        param([string[]]$fileList, [int]$SampleBytes, [bool]$IsQuickMode, [string]$TsSkipPattern, [string[]]$HighEntropyAllowExts, [string[]]$NonPeExts)
        $threadResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($filePath in $fileList) {
            try {
                $file = [System.IO.FileInfo]::new($filePath)

                # High Entropy check - skip extensions that are legitimately high-entropy
                # by design (minified JS/CSS, source maps, WASM, compiled .NET assets).
                $ext = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()
                $skipEntropy = $HighEntropyAllowExts -and $HighEntropyAllowExts.Contains($ext)
                $bytes = $null
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

                # GAP-FL02: magic-byte mismatch - non-PE extension with PE (MZ) header
                if ($NonPeExts -and $NonPeExts.Contains($ext)) {
                    $hdr = if ($bytes -and $bytes.Count -ge 2) {
                        $bytes
                    } else {
                        try {
                            $fs = [System.IO.File]::OpenRead($filePath)
                            $b4  = New-Object byte[] 4
                            $fs.Read($b4, 0, 4) | Out-Null
                            $fs.Close()
                            $b4
                        } catch { $null }
                    }
                    if ($hdr -and $hdr.Count -ge 2 -and $hdr[0] -eq 0x4D -and $hdr[1] -eq 0x5A) {
                        $threadResults.Add([PSCustomObject]@{
                            Type="MagicByte Mismatch"; Target=$filePath
                            Details="PE (MZ) header in $ext file - executable masquerading as script/link"
                            Severity="High"; Mitre="T1036.008"
                        })
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
            $ps = [powershell]::Create().AddScript($huntingBlock).AddArgument($chunk).AddArgument($EntropySampleBytes).AddArgument([bool]$QuickMode).AddArgument($tsSkipPattern).AddArgument($highEntropyAllowExts).AddArgument($nonPeExtList)
            $ps.RunspacePool = $runspacePool
            $jobs += [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
        }

        # GAP-FL02: add magic-byte-only jobs for camouflage extension files
        if ($magicCheckFiles.Count -gt 0) {
            $mChunks = [System.Collections.Generic.List[System.Object[]]]::new()
            for ($i = 0; $i -lt $magicCheckFiles.Count; $i += $FilesPerChunk) {
                $end = [math]::Min($i + $FilesPerChunk, $magicCheckFiles.Count)
                $mChunks.Add($magicCheckFiles.GetRange($i, $end - $i).ToArray())
            }
            foreach ($mc in $mChunks) {
                $ps = [powershell]::Create().AddScript($magicOnlyBlock).AddArgument($mc).AddArgument($magicHighRiskPaths)
                $ps.RunspacePool = $runspacePool
                $jobs += [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
            }
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

function Find-MWCP {
    <#
    .SYNOPSIS
        Locate the DC3-MWCP library and the toolkit's bundled Python interpreter.
        Returns @{Python=<exe>; Lib=<absolute_path>} or $null if not staged.
        Stage with: Build-OfflineToolkit.ps1 -IncludeMWCP

        Walks up the directory tree from $PSScriptRoot looking for tools\mwcp\lib\mwcp
        (same pattern as Invoke-YaraFileScan uses for yara64.exe) -- works from any
        call site regardless of whether EDR_Toolkit.ps1 or EDR_Toolkit_Deploy.ps1 is running.
        Uses the bundled MemProcFS Python (tools\memprocfs\python\python.exe) so mwcp
        runs the same interpreter as memory analysis -- no system Python dependency.
        PS 5.1 compatible: no null-conditional ?. operator.
    #>

    # Walk up from PSScriptRoot to find the toolkit root that contains tools\mwcp\lib
    $libAbs  = $null
    $pyAbs   = $null
    $walkDir = $PSScriptRoot
    for ($i = 0; $i -lt 7; $i++) {
        $candidate = Join-Path $walkDir 'tools\mwcp\lib'
        if (Test-Path (Join-Path $candidate 'mwcp')) {
            $libAbs = $candidate
            # Bundled Python is at tools\memprocfs\python\python.exe in the same root
            $pyCandidate = Join-Path $walkDir 'tools\memprocfs\python\python.exe'
            if (Test-Path $pyCandidate) { $pyAbs = $pyCandidate }
            break
        }
        $parent = Split-Path $walkDir -Parent
        if (-not $parent -or $parent -eq $walkDir) { break }
        $walkDir = $parent
    }

    if (-not $libAbs) { return $null }

    if ($pyAbs) {
        return @{ Python = $pyAbs; Lib = $libAbs }
    }

    # Fallback: system Python if bundled Python is not staged
    $sysPy = $null
    $cmd = Get-Command 'python' -ErrorAction SilentlyContinue
    if ($cmd) { $sysPy = $cmd.Source }
    if (-not $sysPy) {
        $cmd = Get-Command 'python3' -ErrorAction SilentlyContinue
        if ($cmd) { $sysPy = $cmd.Source }
    }
    if (-not $sysPy) {
        $cmd = Get-Command 'py' -ErrorAction SilentlyContinue
        if ($cmd) { $sysPy = $cmd.Source }
    }
    if (-not $sysPy) { return $null }
    return @{ Python = $sysPy; Lib = $libAbs }
}


function Invoke-MWCPFileScan {
    <#
    .SYNOPSIS
        Optional DC3-MWCP pass over flagged files: extracts malware configuration
        (mutex names, C2 addresses, dropped filenames, passwords/keys) from any
        High/Critical file flagged by Invoke-FileHunt or Invoke-YaraFileScan.

        Requires -IncludeMWCP to have been run via Build-OfflineToolkit.ps1.
        Gracefully skips with a warning if mwcp is not staged.

        mwcp's GenericMutex + GenericC2 parsers cover ALL malware families.
        Family-specific parsers (when present) extract full beacon configuration.
        Results roll up into the EDR report as 'mwcp Config Extraction' findings.
    #>
    [CmdletBinding()]
    param(
        [string[]]$FilePath,    # Specific file(s) or directory to scan directly -- bypasses the
                                # findings filter. Useful for follow-on investigation of a specific
                                # artifact that wasn't caught by the automated hunt. Accepts files
                                # or directories (files enumerated from directory).
        [switch]$Recursive,     # When -FilePath points to a directory, recurse into subdirectories
        [switch]$Quiet
    )

    $mwcp = Find-MWCP
    if (-not $mwcp) {
        Write-Console "[~] mwcp: not staged -- run Build-OfflineToolkit.ps1 -IncludeMWCP to enable file-scan config extraction." "Yellow"
        return
    }

    $filePathTargets = $null

    # Fix 1: large-file size limit -- multi-GB files can't have embedded malware config
    # and would just slow the batch down. Warn the analyst and suggest a one-off scan.
    $mwcpMaxBytes = 50MB  # files above this are skipped in directory-mode batch scans

    if ($FilePath -and $FilePath.Count -gt 0) {
        # Direct mode: resolve each -FilePath entry to a list of real files
        $filePathTargets = [System.Collections.Generic.List[string]]::new()
        $skippedLarge   = [System.Collections.Generic.List[string]]::new()
        foreach ($fp in $FilePath) {
            if (-not $fp -or -not (Test-Path $fp -ErrorAction SilentlyContinue)) { continue }
            $isDir = Test-Path $fp -PathType Container
            if ($isDir) {
                # Enumerate files, applying size filter. Assign Get-ChildItem result to
                # variable first -- PS does not allow piping from an if/else block directly.
                $enumResult = if ($Recursive) {
                    Get-ChildItem -Path $fp -File -Recurse -ErrorAction SilentlyContinue
                } else {
                    Get-ChildItem -Path $fp -File -ErrorAction SilentlyContinue
                }
                foreach ($fi2 in $enumResult) {
                    if ($fi2.Length -le $mwcpMaxBytes) {
                        $filePathTargets.Add($fi2.FullName)
                    } else {
                        $skippedLarge.Add($fi2.FullName)
                    }
                }
            } else {
                # Single file: check size but don't block -- analyst explicitly targeted it
                $fi = Get-Item $fp -ErrorAction SilentlyContinue
                if ($fi -and $fi.Length -gt $mwcpMaxBytes) {
                    Write-Console "[~] mwcp: '$($fi.Name)' is $([math]::Round($fi.Length/1MB,0)) MB -- scanning anyway (explicit -FilePath target)" "Yellow"
                }
                $filePathTargets.Add($fp)
            }
        }
        if ($skippedLarge.Count -gt 0) {
            Write-Console "[~] mwcp: skipped $($skippedLarge.Count) file(s) over $([math]::Round($mwcpMaxBytes/1MB,0)) MB in directory scan (too large for embedded config)." "Yellow"
            Write-Console "    To scan a specific large file: -FilePath `"$($skippedLarge[0])`" -ScanMWCP" "Yellow"
        }
    }

    # Determine target list: -FilePath takes priority over findings-based list
    if ($filePathTargets -and $filePathTargets.Count -gt 0) {
        $targets = @($filePathTargets)
        Write-Console "[*] mwcp: scanning $($targets.Count) file(s) via -FilePath (batch mode -- single Python process)..." "Cyan"
    } else {
        # Target: High/Critical file-class findings that have a real file path on disk
        $fileTypes = @('Suspicious File','MagicByte Mismatch','High Entropy File',
                       'YARA Match (File)','Timestomped File','mwcp Config Extraction')
        $targets = @($script:Findings |
            Where-Object { $_.Type -in $fileTypes -and $_.Severity -in @('High','Critical') } |
            Select-Object -ExpandProperty Target -Unique |
            Where-Object { $_ -and (Test-Path $_ -PathType Leaf -ErrorAction SilentlyContinue) })

        if ($targets.Count -eq 0) {
            if (-not $Quiet) { Write-Console "[~] mwcp file scan: no High/Critical file targets -- use -FilePath to scan specific artifacts directly." "Gray" }
            return
        }
        Write-Console "[*] mwcp: analyzing $($targets.Count) flagged file(s) for embedded malware config (batch mode)..." "Cyan"
    }

    # Fix 2: batch mode -- locate mwcp_scan.py once, then pass ALL targets in a single
    # Python invocation. Eliminates per-file subprocess overhead (was N * Python startups).
    $foundScanner = $null
    $walkDir2 = $PSScriptRoot
    for ($si = 0; $si -lt 7; $si++) {
        $c2 = Join-Path $walkDir2 'playbooks\windows\threat_hunting\mwcp_scan.py'
        if (Test-Path $c2) { $foundScanner = $c2; break }
        $p2 = Split-Path $walkDir2 -Parent
        if (-not $p2 -or $p2 -eq $walkDir2) { break }
        $walkDir2 = $p2
    }
    if (-not $foundScanner) {
        Write-Console "[~] mwcp: mwcp_scan.py not found -- cannot scan" "Yellow"
        return
    }

    Write-Console "[*] mwcp: invoking batch scan ($($targets.Count) file(s) in one Python process)..." "Gray"
    # Write target list to a temp file to avoid Windows command-line length limit (32KB).
    # With 1000+ files the argument list easily exceeds the OS limit.
    $listFile = [System.IO.Path]::GetTempFileName()
    try {
        # One file path per line, UTF-8, no BOM (PS 5.1 compatible)
        $noBom2 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllLines($listFile, $targets, $noBom2)
    } catch {
        Write-Console "[~] mwcp: could not write file list: $($_.Exception.Message)" "Yellow"
        Remove-Item $listFile -Force -ErrorAction SilentlyContinue
        return
    }
    try {
        # Fix 2: single Python call with --filelist -- mwcp_scan.py returns a JSON array
        # (one entry per file). Eliminates N subprocess startups for N files.
        $outDir2 = if ($ReportPath) { $ReportPath } else { '-' }
        $raw = & $mwcp.Python $foundScanner $mwcp.Lib $outDir2 '--filelist' $listFile 2>$null

        if ($raw) {
            $results = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (-not $results) {
                Write-Console "[~] mwcp: could not parse batch output" "Yellow"
            } else {
                $idx = 0
                foreach ($entry in @($results)) {
                    $idx++
                    $entryFile = $entry.file
                    $fname2    = if ($entryFile) { [System.IO.Path]::GetFileName($entryFile) } else { "?" }
                    Write-Console "[*] mwcp [$idx/$($results.Count)] $fname2" "Gray"

                    if ($entry.error) {
                        Write-Console "    [~] RESULT: $($entry.error)" "Yellow"
                        continue
                    }
                    $parts = [System.Collections.Generic.List[string]]::new()
                    if ($entry.mutex    -and $entry.mutex.Count    -gt 0) { $parts.Add("Mutexes: $($entry.mutex -join ', ')") }
                    if ($entry.address  -and $entry.address.Count  -gt 0) { $parts.Add("C2: $($entry.address -join ', ')") }
                    if ($entry.filename -and $entry.filename.Count -gt 0) { $parts.Add("Drops: $($entry.filename -join ', ')") }
                    if ($entry.password -and $entry.password.Count -gt 0) { $parts.Add("Keys: $($entry.password -join ', ')") }

                    if ($parts.Count -gt 0) {
                        Add-Finding -Type "mwcp Config Extraction" -Target $entryFile `
                            -Details "DC3-MWCP extracted config from '$fname2': $($parts -join ' | ')" `
                            -Severity "High" -Mitre "T1027 (Obfuscated Files or Information), T1140 (Deobfuscate/Decode Files)"
                        Write-Console "    [!] RESULT: config extracted -- $($parts -join ' | ')" "Red"
                    } else {
                        Write-Console "    [+] RESULT: clean -- no config extracted" "Green"
                    }
                }
            }
        } else {
            Write-Console "[~] mwcp: no output from mwcp_scan.py" "Yellow"
        }
    } catch {
        Write-Console "[~] mwcp batch error: $($_.Exception.Message)" "Yellow"
    } finally {
        Remove-Item $listFile -Force -ErrorAction SilentlyContinue
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
        [string[]]$FilePath,    # Direct file(s) or directory to scan -- bypasses the findings filter.
                                # Accepts specific files OR a directory path (combine with -Recursive
                                # in the caller). Useful for follow-on investigation of a specific artifact.
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

    # -- 2. Build scan target list -------------------------------------------------
    # Priority: (1) -FilePath explicit targets -- direct investigation of specific artifact(s)
    #           (2) prior High/Critical findings from file hunt
    #           (3) fallback to full TargetPath directory
    $scanTargets = $null

    if ($FilePath -and $FilePath.Count -gt 0) {
        # Direct mode: scan the specified file(s) / directory regardless of prior findings.
        # Each entry can be a specific file path or a directory (yara64 -r handles recursion).
        $validPaths = @($FilePath | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) })
        if ($validPaths.Count -gt 0) {
            Write-Console "[*] YARA: direct scan - $($validPaths.Count) path(s) provided via -FilePath." "Cyan"
            $scanTargets = $validPaths
        } else {
            Write-Console "[~] YARA: -FilePath provided but no valid paths found." "Yellow"
        }
    }

    if (-not $scanTargets) {
        # Findings-based: scan files flagged by prior file hunt phases
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

    # -- 4. Write a temporary rule index (no BOM -- yara64.exe treats BOM as non-ASCII) ------
    # PS 5.1 Out-File -Encoding UTF8 adds a BOM which yara64.exe rejects at line 1.
    # Also filter out rule files that contain non-ASCII bytes -- same guard the memory
    # scan applies to prevent a bad rule file from aborting the entire compile pass.
    $tmpRuleIndex = [System.IO.Path]::GetTempFileName() -replace '\.tmp$','.yar'
    $asciiOnlyFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($rf in $ruleFiles) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($rf)
            $ok = $true
            for ($bi = 0; $bi -lt [math]::Min($bytes.Length, 2048); $bi++) {
                if ($bytes[$bi] -gt 127) { $ok = $false; break }
            }
            if ($ok) { $asciiOnlyFiles.Add($rf) }
        } catch {}
    }
    $includeLines = $asciiOnlyFiles | ForEach-Object { "include `"$_`"" }
    $noBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllLines($tmpRuleIndex, $includeLines, $noBom)

    $yaraBaseArgs = @('-w','-d','filename=','-d','filepath=','-d','extension=','-d','filetype=','-d','owner=')

    # -- 4a. Self-test: prove the engine + rules actually load and match -------
    # yara64 returns 0 matches if the ruleset fails to compile; a canary marker
    # file that MUST match confirms a clean result is real, not a silent dud.
    $canaryRule = [System.IO.Path]::GetTempFileName() -replace '\.tmp$','.yar'
    $canaryFile = [System.IO.Path]::GetTempFileName()
    # Write without BOM -- yara64.exe rejects BOM bytes as non-ASCII at line 1
    [System.IO.File]::WriteAllText($canaryRule,
        'rule IRToolkit_File_Canary { strings: $m = "IRTOOLKIT_FILE_CANARY_MARKER" condition: $m }',
        (New-Object System.Text.UTF8Encoding $false))
    [System.IO.File]::WriteAllText($canaryFile,
        'IRTOOLKIT_FILE_CANARY_MARKER',
        (New-Object System.Text.UTF8Encoding $false))
    $canaryHit = & $yaraExe @yaraBaseArgs $canaryRule $canaryFile 2>$null
    if ($canaryHit -match 'IRToolkit_File_Canary') {
        Write-Console "    [+] YARA self-test OK (engine matching)." "Green"
    } else {
        Write-Console "    [!] YARA self-test FAILED - engine not matching; file YARA results unreliable." "Red"
    }
    Remove-Item $canaryRule, $canaryFile -Force -ErrorAction SilentlyContinue

    # -- 5. Scan each target with per-file log stamps -------------------------
    $totalMatches = 0
    $targetIdx    = 0
    foreach ($target in $scanTargets) {
        $targetIdx++
        $isDir    = Test-Path $target -PathType Container
        $tLabel   = if ($isDir) { "[dir]  $target" } else { "[file] $([System.IO.Path]::GetFileName($target))" }
        Write-Console "[*] YARA [$targetIdx/$($scanTargets.Count)] scanning: $tLabel" "Gray"

        $yaraArgs = $yaraBaseArgs + $tmpRuleIndex
        if ($isDir) { $yaraArgs += '-r' }
        $yaraArgs += $target

        $errFile     = [System.IO.Path]::GetTempFileName()
        $fileMatches = 0
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
                    Write-Console "    [!] MATCH: $rule on $([System.IO.Path]::GetFileName($file))" "Red"
                    $fileMatches++
                    $totalMatches++
                }
            }
            if ($fileMatches -eq 0) {
                Write-Console "    [+] RESULT: clean -- no YARA matches" "Green"
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

function Get-NamedPipeName {
    # List named-pipe NAMES only. [System.IO.Directory]::GetFiles on the pipe namespace
    # uses FindFirstFile/FindNextFile - it lists names WITHOUT opening or connecting to
    # any pipe. This is deliberately NOT Get-ChildItem (whose provider can stat/open each
    # pipe and on a live host wedged core networking-service RPC pipes - 2026-06-26).
    try { return [System.IO.Directory]::GetFiles('\\.\pipe\') } catch { return @() }
}

function Invoke-NetworkHunt {
    Write-Console "[*] Auditing Network Connections, Listeners & Named Pipes..." "Cyan"

    # High-noise beacon ports that are expected on managed Windows endpoints.
    # Only flag ESTABLISHED connections to non-RFC1918 IPs on unusual ports.
    $trustedPorts = [System.Collections.Generic.HashSet[int]]@(
        80, 443, 8080, 8443,
        53,
        135, 445, 139, 389, 636,
        3268, 3269,
        5985, 5986,
        1688
    )

    # RFC1918 and loopback CIDR blocks - outbound to these is never flagged.
    $privateRanges = @(
        @{ Start = [Net.IPAddress]::Parse('10.0.0.0');      Mask = 8  }
        @{ Start = [Net.IPAddress]::Parse('172.16.0.0');    Mask = 12 }
        @{ Start = [Net.IPAddress]::Parse('192.168.0.0');   Mask = 16 }
        @{ Start = [Net.IPAddress]::Parse('127.0.0.0');     Mask = 8  }
        @{ Start = [Net.IPAddress]::Parse('169.254.0.0');   Mask = 16 }
    )

    function Test-PrivateAddress {
        param([string]$IpStr)
        try {
            $addr = [Net.IPAddress]::Parse($IpStr)
            if ($addr.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $true }
            $addrBytes = $addr.GetAddressBytes()
            foreach ($r in $privateRanges) {
                $maskBits  = $r.Mask
                $baseBytes = $r.Start.GetAddressBytes()
                $match     = $true
                $fullBytes = [math]::Floor($maskBits / 8)
                for ($i = 0; $i -lt $fullBytes; $i++) {
                    if ($addrBytes[$i] -ne $baseBytes[$i]) { $match = $false; break }
                }
                if ($match -and ($maskBits % 8) -ne 0) {
                    $remBits = $maskBits % 8
                    $maskByte = 0xFF -shl (8 - $remBits) -band 0xFF
                    if (($addrBytes[$fullBytes] -band $maskByte) -ne ($baseBytes[$fullBytes] -band $maskByte)) {
                        $match = $false
                    }
                }
                if ($match) { return $true }
            }
            return $false
        } catch { return $true }
    }

    # Processes that legitimately hold many outbound connections.
    $trustedOutboundProcs = @(
        'svchost','lsass','SearchIndexer','MsMpEng','MsSense','WaaSMedicAgent',
        'OneDrive','Teams','slack','discord','chrome','msedge','firefox',
        'Defender','SecurityHealthService','MpCmdRun','SgrmBroker',
        'TiWorker','TrustedInstaller','wuauclt'
    )

    # Known DoH resolver IPs (DNS-over-HTTPS providers). Direct HTTPS (443) from a
    # non-browser process to these IPs bypasses DNS cache logging -- C2 beacon indicator.
    $dohResolverIPs = [System.Collections.Generic.HashSet[string]]@(
        '1.1.1.1','1.0.0.1',               # Cloudflare
        '8.8.8.8','8.8.4.4',               # Google
        '9.9.9.9','149.112.112.112',       # Quad9
        '208.67.222.222','208.67.220.220', # OpenDNS
        '185.228.168.9','185.228.169.9'    # CleanBrowsing
    )
    # Processes that legitimately use DoH as part of their normal network stack.
    $dohBrowserProcs = '(?i)^(chrome|msedge|firefox|brave|opera|vivaldi|iexplore)(\.exe)?$'

    # SMTP/submission ports -- only legitimate from known mail clients.
    $smtpPorts = [System.Collections.Generic.HashSet[int]]@(25, 587, 465)
    $mailClientProcs = '(?i)^(outlook|thunderbird|em_client|mailbird|sparrow|postbox)(\.exe)?$'

    # -- 1. Outbound ESTABLISHED connections to public IPs on non-standard ports --
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
             Where-Object { $_.RemotePort -ne 0 }

    $pidProcMap = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        ForEach-Object { $pidProcMap[$_.ProcessId] = [PSCustomObject]@{ Name = $_.Name; Path = $_.ExecutablePath } }

    foreach ($c in $conns) {
        $remoteIp   = $c.RemoteAddress
        $remotePort = $c.RemotePort
        $ownerPid   = $c.OwningProcess
        $info       = $pidProcMap[$ownerPid]
        $procName   = if ($info) { $info.Name } else { $null }

        if (-not $remoteIp -or (Test-PrivateAddress $remoteIp)) { continue }

        # Phase 6A: DoH beacon -- non-browser HTTPS to a known DoH resolver IP.
        # DNS-over-HTTPS bypasses DNS cache logging; beacons over this channel are invisible.
        if ($remotePort -eq 443 -and $dohResolverIPs.Contains($remoteIp)) {
            if (-not $procName -or $procName -notmatch $dohBrowserProcs) {
                Add-Finding -Type "DoH Beacon" `
                    -Target "PID: $ownerPid ($procName)" `
                    -Details "Non-browser HTTPS to DoH resolver $remoteIp -- DNS-over-HTTPS evades DNS cache logging. C2 beacon pattern." `
                    -Severity "High" -Mitre "T1071.004 (DNS), T1071 (Application Layer Protocol)"
                continue
            }
        }

        # Phase 6D: SMTP exfil -- TCP 25/587/465 from a non-mail process.
        # Mail clients (Outlook, Thunderbird) are legitimate; everything else is data exfil or relay.
        # Always continue after the SMTP check so mail clients don't fall through to the generic
        # suspicious-connection report (port 587 from Outlook is fully expected behavior).
        if ($smtpPorts.Contains([int]$remotePort)) {
            if (-not $procName -or $procName -notmatch $mailClientProcs) {
                Add-Finding -Type "SMTP Exfiltration" `
                    -Target "PID: $ownerPid ($procName)" `
                    -Details "Non-mail process on SMTP port $remotePort to $remoteIp -- credential relay or data exfiltration." `
                    -Severity "High" -Mitre "T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)"
            }
            continue  # SMTP ports fully handled above; skip generic connection check
        }

        if ($trustedPorts.Contains([int]$remotePort)) { continue }

        # Trusted outbound processes are prime injection targets for C2 tunnelling.
        # Downgrade severity by one tier rather than excluding: if an attacker injects
        # into OneDrive.exe or Teams.exe and beacons on a non-standard port, we must see it.
        $isTrustedProc = $procName -and (($procName -replace '(?i)\.exe$','') -in $trustedOutboundProcs)

        $sev = if ($remotePort -in @(4444,1234,8888,9999,31337,6666,7777)) { 'High' } else { 'Medium' }
        if ($isTrustedProc) {
            $sev = if ($sev -eq 'High') { 'Medium' } else { 'Low' }
        }
        Add-Finding -Type "Suspicious Outbound Connection" `
            -Target "PID: $ownerPid ($procName)" `
            -Details "ESTABLISHED to $remoteIp`:$remotePort (non-standard port, public IP$(if($isTrustedProc){'; trusted process -- verify not injected'}))" `
            -Severity $sev -Mitre "T1071 (Application Layer Protocol), T1095 (Non-Standard Port)"
    }

    # -- 2. Unexpected listeners (LISTEN state on non-system ports) --
    # Ephemeral ports 49152+ are dynamic RPC and always expected.
    $ephemeralStart = 49152
    $expectedListeners = [System.Collections.Generic.HashSet[int]]@(
        80, 443, 445, 139, 135, 3389,
        5985, 5986, 1688
    )

    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    $sigCache  = @{}
    foreach ($l in $listeners) {
        $port    = $l.LocalPort
        $ownerP  = $l.OwningProcess
        $info    = $pidProcMap[$ownerP]
        $proc    = if ($info) { $info.Name } else { $null }
        $exe     = if ($info) { $info.Path } else { $null }
        if ($port -ge $ephemeralStart) { continue }
        if ($expectedListeners.Contains([int]$port)) { continue }

        # A validly-signed owning process listening is far more likely a legit service /
        # vendor agent (Hyper-V vmms, CDPSvc, ASUS/Adobe helpers) than a backdoor. Verify
        # the binary signature and downgrade signed listeners - still surfaced, not screamed.
        $signed = $false
        if ($exe) {
            if (-not $sigCache.ContainsKey($exe)) {
                $sigCache[$exe] = if (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue) {
                    (Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction SilentlyContinue).Status
                } else { 'NoPath' }
            }
            $signed = ($sigCache[$exe] -eq 'Valid')
        }
        if ($signed) {
            $sev = 'Low'
        } else {
            $sev = if ($port -lt 1024) { 'High' } else { 'Medium' }
        }
        Add-Finding -Type "Unexpected Network Listener" `
            -Target "PID: $ownerP ($proc)" `
            -Details "Listening on port $port (not in expected service list; owner signed=$signed)" `
            -Severity $sev -Mitre "T1071 (Application Layer Protocol)"
    }

    # -- 3. Named pipe enumeration for suspicious C2 pipes --
    # Common C2 framework default pipe names: Cobalt Strike, Metasploit, impacket, etc.
    # NOTE: 'mojo.' is deliberately EXCLUDED - it is legitimate Chromium/Edge IPC and
    # appears in the hundreds, producing a false-positive storm with zero IR value.
    # Anchor framework tokens to whole-word-ish boundaries to avoid matching substrings
    # inside benign service pipe names.
    # Well-known C2 framework default pipe names (supplementary signal -- sophisticated
    # attackers change these, so this catches only out-of-the-box frameworks).
    $suspPipePattern = '(?i)(msagent_[0-9a-f]+|postex_[0-9a-f]+|status_[0-9a-f]+|metsvc|' +
                       'RemCom_communication|MSSE-[0-9a-f]+-server|' +
                       '\bcobalt|\bbeacon\b|\bhavoc\b|\bsliver\b|\bmythic\b|' +
                       'PSEXESVC|paexec|csexecsvc)'

    # Structural pattern: GUID-format pipe names. C2 frameworks randomize their pipe
    # names to avoid static signature detection, and GUID format is the most common choice.
    # Legitimate GUID pipes do exist (COM activation, DTC) but are typically short-lived;
    # a persisted GUID pipe from a non-system process is a behavioral indicator.
    $guidPipePattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

    # Common system pipe names that are always expected -- never flag these.
    $systemPipes = '(?i)^(lsass|svcctl|srvsvc|winreg|ntsvcs|wkssvc|browser|epmapper|' +
                   'spoolss|netlogon|samr|lsarpc|netdfs|InitShutdown|eventlog|atsvc|trkwks|' +
                   'protected_storage|mojo\.|chrome\.|crashpad_|ipc_)(.+)?$'

    # Enumerate pipe NAMES ONLY via Get-NamedPipeName (never opens a pipe).
    $pipes = @(Get-NamedPipeName)

    foreach ($pipe in $pipes) {
        $pipeName = [System.IO.Path]::GetFileName($pipe)
        if ($pipeName -match $systemPipes) { continue }

        if ($pipeName -match $suspPipePattern) {
            Add-Finding -Type "Suspicious Named Pipe" `
                -Target "Pipe: $pipeName" `
                -Details "Named pipe matches known C2 framework default pattern: $pipe" `
                -Severity "High" -Mitre "T1071 (Application Layer Protocol), T1559.001 (Inter-Process Communication)"
        } elseif ($pipeName -match $guidPipePattern) {
            # GUID pipe name = structural C2 indicator. Frameworks randomize to evade
            # static names. Report as Medium (needs corroboration -- check owning process).
            Add-Finding -Type "Suspicious Named Pipe" `
                -Target "Pipe: $pipeName" `
                -Details "GUID-format pipe name -- C2 frameworks use this to evade static name detection. Verify owning process. Full path: $pipe" `
                -Severity "Medium" -Mitre "T1071 (Application Layer Protocol), T1559.001 (Inter-Process Communication)"
        }
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

if (-not ($ScanProcesses -or $ScanFileless -or $TargetDirectory -or $ScanTasks -or $ScanDrivers -or
          $ScanInjection -or $ScanADS -or $ScanRegistry -or $ScanETWAMSI -or $ScanPendingRename -or
          $ScanBITS -or $ScanCOM -or $ScanNetwork -or $ScanYara -or $ScanMWCP -or
          ($FilePath -and $FilePath.Count -gt 0))) {
    Write-Host "Usage examples:" -ForegroundColor Yellow
    Write-Host " .\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM -ScanNetwork"
    Write-Host " .\EDR_Toolkit.ps1 -TargetDirectory 'C:\' -Recursive -ScanADS -QuickMode -SeverityFilter Critical,High -OutputFormat JSON -Quiet"
    Write-Host " .\EDR_Toolkit.ps1 -FilePath 'C:\suspect.exe' -ScanYara -ScanMWCP   # direct file investigation"
    Write-Host " .\EDR_Toolkit.ps1 -FilePath 'C:\Downloads' -Recursive -ScanMWCP   # directory mwcp scan"
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
if ($ScanNetwork)    { Invoke-NetworkHunt }

if ($TargetDirectory) {
    Invoke-FileHunt -Path $TargetDirectory -Recurse:$Recursive `
        -QuickMode:$QuickMode -QuickModeDaysBack $QuickModeDaysBack -Quiet:$Quiet
    if ($ScanADS)  { Invoke-ADSHunt -Path $TargetDirectory -Recurse:$Recursive }
    if ($ScanYara) {
        $yaraFpArgs = @{ TargetPath=$TargetDirectory; RulesDir=$YaraRulesDir; Quiet=$Quiet }
        if ($FilePath) { $yaraFpArgs.FilePath = $FilePath }
        Invoke-YaraFileScan @yaraFpArgs
    }
    if ($ScanMWCP) {
        $mwcpFpArgs = @{ Quiet=$Quiet }
        if ($FilePath) { $mwcpFpArgs.FilePath = $FilePath; $mwcpFpArgs.Recursive = $Recursive }
        Invoke-MWCPFileScan @mwcpFpArgs
    }
} elseif ($FilePath -and ($ScanYara -or $ScanMWCP)) {
    # -FilePath without -TargetDirectory: scan the specified paths directly
    $fallbackTarget = if ($FilePath.Count -gt 0) { Split-Path $FilePath[0] -Parent } else { $PWD.Path }
    if ($ScanYara) { Invoke-YaraFileScan -TargetPath $fallbackTarget -RulesDir:$YaraRulesDir -FilePath $FilePath -Quiet:$Quiet }
    if ($ScanMWCP) { Invoke-MWCPFileScan -FilePath $FilePath -Recursive:$Recursive -Quiet:$Quiet }
} elseif ($ScanYara) {
    Write-Console "[-] -ScanYara requires -TargetDirectory or -FilePath to be set." "Yellow"
}

Export-Reports -OutDir $ReportPath

