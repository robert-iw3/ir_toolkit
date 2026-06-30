<#
.SYNOPSIS
    Phase 4 gap-fill tests -- credential access detections.

    All are behavior-based: detect the MECHANISM of credential access.

    P4-4A  Browser cred staging  (T1555.003) -- Login Data / logins.json outside profile dir -> High
    P4-4C  Registry hive dump    (T1003.002) -- reg.exe save SAM/SECURITY/SYSTEM -> Critical
    P4-4D  Port monitor DLL      (T1547.010) -- non-system32 DLL in Print\Monitors -> High/Critical
    P4-4E  Credential vault      (T1555.004) -- cmdkey/vaultcmd enumeration cmdlines -> High/Medium
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "01_Process_And_Injection.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")

    function script:Set-P4BaselineMocks {
        Mock Get-Process      { @() }
        Mock Get-CimInstance  { @() }
        Mock Get-WmiObject    { @() }
        Mock Test-Path        { $false }
        Mock Get-ItemProperty { [PSCustomObject]@{} }
        Mock Get-ChildItem    { @() }
        Mock Invoke-LsassDumpHunt {}
        Mock Get-BitsTransfer { @() }
    }

    function script:Make-WmiProc {
        param([int]$ProcId=9001, [string]$Name='cmd.exe', [string]$Cmd, [int]$PPid=4)
        [PSCustomObject]@{ ProcessId=$ProcId; Name=$Name; CommandLine=$Cmd; ParentProcessId=$PPid }
    }
}

# ---------------------------------------------------------------------------
# P4-4C: Registry hive dump (reg.exe save SAM/SECURITY/SYSTEM)
# Mechanism: dumping the credential hive lets an attacker extract password hashes offline.
# ---------------------------------------------------------------------------
Describe "P4-4C Registry Credential Hive Dump" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P4BaselineMocks
    }

    It "Should flag 'reg.exe save HKLM\SAM' as Critical" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9001; Name='reg.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9001 -Name 'reg.exe' -Cmd 'reg.exe save HKLM\SAM C:\Temp\sam.hiv')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Credential Hive Dump' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].MITRE    | Should -Match 'T1003'
    }

    It "Should flag 'reg.exe save HKLM\SECURITY' as Critical" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9002; Name='reg.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9002 -Name 'reg.exe' -Cmd 'reg save HKLM\SECURITY C:\Users\Public\sec.hiv /y')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Credential Hive Dump' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
    }

    It "Should flag 'reg.exe save HKLM\SYSTEM' as Critical" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9003; Name='reg.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9003 -Name 'reg.exe' -Cmd 'reg.exe save HKLM\SYSTEM .\system.hiv')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Credential Hive Dump' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
    }

    It "Should NOT flag 'reg.exe save HKLM\SOFTWARE' (not a credential hive)" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9004; Name='reg.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9004 -Name 'reg.exe' -Cmd 'reg.exe save HKLM\SOFTWARE C:\backup\sw.hiv')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Credential Hive Dump' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P4-4E: Credential vault access (cmdkey / vaultcmd)
# Mechanism: enumerating or modifying stored credentials reveals saved passwords.
# ---------------------------------------------------------------------------
Describe "P4-4E Credential Vault Enumeration" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P4BaselineMocks
    }

    It "Should flag 'cmdkey /list' as High" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9010; Name='cmdkey.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9010 -Name 'cmdkey.exe' -Cmd 'cmdkey.exe /list')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Credential Vault Access' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1555'
    }

    It "Should flag 'vaultcmd /listcreds' as High" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9011; Name='vaultcmd.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9011 -Name 'vaultcmd.exe' -Cmd 'vaultcmd /listcreds:"Windows Credentials"')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Credential Vault Access' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should flag 'cmdkey /add' as Medium (credential store manipulation)" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9012; Name='cmdkey.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9012 -Name 'cmdkey.exe' -Cmd 'cmdkey /add:targetserver /user:attacker /pass:p@ssw0rd')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Credential Vault Access' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Medium'
    }
}

# ---------------------------------------------------------------------------
# P4-4D: Port monitor / print processor DLL
# Mechanism: DLL loaded by spoolsv.exe in SYSTEM context at boot -- durable persistence.
# Legitimate monitors are always in system32. Non-system32 = attacker-planted.
# ---------------------------------------------------------------------------
Describe "P4-4D Suspicious Print Monitor DLL" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P4BaselineMocks
    }

    It "Should flag a port monitor DLL in a staging path as Critical" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\Print\Monitors\EvilMon'; PSChildName = 'EvilMon' })
        } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Driver = 'C:\Users\Public\evil.dll' }
        } -ParameterFilter { $Path -match 'EvilMon' -and $Name -eq 'Driver' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Print Monitor DLL' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].MITRE    | Should -Match 'T1547.010'
    }

    It "Should flag a port monitor DLL outside system32 as High" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\Print\Monitors\SuspMon'; PSChildName = 'SuspMon' })
        } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Driver = 'C:\Program Files\WeirdApp\printmon.dll' }
        } -ParameterFilter { $Path -match 'SuspMon' -and $Name -eq 'Driver' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Print Monitor DLL' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should NOT flag a system32 port monitor DLL (expected legitimate)" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\Print\Monitors\LocalMon'; PSChildName = 'LocalMon' })
        } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Driver = 'C:\Windows\System32\localspl.dll' }
        } -ParameterFilter { $Path -match 'LocalMon' -and $Name -eq 'Driver' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Print Monitor DLL' }) |
            Should -HaveCount 0
    }

    It "Should NOT fire when Print\Monitors key is absent" {
        Invoke-AdvancedRegistryHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Print Monitor DLL' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P4-4A: Browser credential store access by non-browser process
# Mechanism: the attacker MUST access the browser's profile data directory to
# steal credentials -- regardless of what they name the output file.
# A non-browser process with a browser profile path in its cmdline is the signal.
# ---------------------------------------------------------------------------
Describe "P4-4A Browser Credential Access (non-browser process targeting profile dir)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P4BaselineMocks
    }

    It "Should flag non-browser process referencing Chrome User Data path as High" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9040; Name='cmd.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9040 -Name 'cmd.exe' `
                -Cmd 'cmd.exe /c copy "C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\Temp\out')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Browser Credential Access' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1555.003'
    }

    It "Should flag non-browser process referencing Firefox Profiles path as High" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9041; Name='powershell.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9041 -Name 'powershell.exe' `
                -Cmd 'powershell.exe -c Copy-Item "$env:APPDATA\Mozilla\Firefox\Profiles\abc.default\key4.db" C:\Temp\')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Browser Credential Access' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should NOT flag Chrome.exe itself accessing its own profile" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9042; Name='chrome.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9042 -Name 'chrome.exe' `
                -Cmd '"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory="Default"')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Browser Credential Access' }) |
            Should -HaveCount 0 -Because "the browser accessing its own profile is legitimate"
    }

    It "Should NOT flag a process with no browser profile path in cmdline" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9043; Name='cmd.exe' }) }
        Mock Get-CimInstance {
            @(Make-WmiProc -ProcId 9043 -Name 'cmd.exe' -Cmd 'cmd.exe /c dir C:\Users\Public')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Browser Credential Access' }) |
            Should -HaveCount 0
    }
}
