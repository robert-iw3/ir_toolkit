<#
.SYNOPSIS
    Behavior-refactor regression tests -- validates that the toolkit detects
    MECHANISMS not tool names, and downgrades benign activity rather than
    excluding it. Each test pair proves: TP fires AND FP is downgraded.

    Covers fixes to:
      01_  lowRiskProcesses: score penalty not skip (T1059/T1218)
      02_  Run key: staging-path + non-trusted-dir detection (T1547.001)
      02_  Service path: same expansion (T1543.003)
      03_  BITS: behavior-only, no name/CDN allowlists (T1197)
      06_  Network outbound: trusted-proc downgrade not skip (T1071)
      06_  Named pipe: GUID structural detection alongside name patterns (T1559.001)
      01_  Hidden process: coreAllowed/coreAllowedWildcards downgrade not skip (T1055/T1014)
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "01_Process_And_Injection.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")
    . (Join-Path $SrcPath "03_BITS_COM_ETW_AMSI.ps1")
    . (Join-Path $SrcPath "06_Network.ps1")

    function script:Set-RefactorBaseline {
        Mock Get-Process      { @() }
        Mock Get-CimInstance  { @() }
        Mock Get-WmiObject    { @() }
        Mock Test-Path        { $false }
        Mock Get-ItemProperty { [PSCustomObject]@{} }
        Mock Get-ChildItem    { @() }
        Mock Invoke-LsassDumpHunt {}
        Mock Get-BitsTransfer { @() }
        Mock Get-NetTCPConnection { @() }
        Mock Get-NamedPipeName   { @() }
        Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status = 'NotSigned' } }
    }

    function script:Make-RefProc {
        param([int]$ProcId=9001, [string]$Name='cmd.exe', [string]$Cmd='', [int]$PPid=4)
        [PSCustomObject]@{ ProcessId=$ProcId; Name=$Name; CommandLine=$Cmd; ParentProcessId=$PPid }
    }

    function script:New-FakeBitsJob {
        param([string]$Name='TestJob', [string]$Url='', [string]$Dest='', [string]$State='Transferring')
        $fl = [PSCustomObject]@{ RemoteName=$Url; LocalName=$Dest }
        [PSCustomObject]@{ DisplayName=$Name; JobState=$State; FileList=@($fl) }
    }
}

# ===========================================================================
# Fix 1: lowRiskProcesses score penalty (not skip)
# ===========================================================================
Describe "Fix-1 lowRiskProcesses: downgrade not exclude" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-RefactorBaseline
    }

    It "Should fire at MEDIUM (not High) for svchost.exe with very high score indicators" {
        # svchost.exe IS in lowRiskProcesses -- but multiple high-confidence LOLBin
        # indicators together must still produce a finding (at downgraded severity).
        Mock Get-Process    { @([PSCustomObject]@{ Id=9001; Name='svchost.exe' }) }
        Mock Get-CimInstance {
            @(Make-RefProc -ProcId 9001 -Name 'svchost.exe' `
                -Cmd 'svchost.exe -enc AAABBBCCC IEX DownloadString WebClient')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' }
        $f | Should -Not -BeNullOrEmpty -Because "svchost.exe never uses -enc+IEX+WebClient; downgrade not exclude"
        $f[0].Severity | Should -Be 'Medium' -Because "lowRiskProcesses gets a score penalty but is not excluded"
    }

    It "Should NOT fire for svchost.exe with only one weak indicator (score too low after penalty)" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9002; Name='svchost.exe' }) }
        Mock Get-CimInstance {
            @(Make-RefProc -ProcId 9002 -Name 'svchost.exe' `
                -Cmd 'svchost.exe -NoProfile -k netsvcs')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' }) |
            Should -HaveCount 0 -Because "single -NoProfile is low score; penalty keeps it below threshold"
    }

    It "Should fire for OneDrive.exe with high score (injection target, still detectable)" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9003; Name='OneDrive.exe' }) }
        Mock Get-CimInstance {
            @(Make-RefProc -ProcId 9003 -Name 'OneDrive.exe' `
                -Cmd 'OneDrive.exe -enc AAABBB -w hidden IEX DownloadString')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' }
        $f | Should -Not -BeNullOrEmpty -Because "malware injected into OneDrive must still be detected"
        $f[0].Severity | Should -Be 'Medium' -Because "lowRiskProcesses downgraded, not excluded"
    }
}

# ===========================================================================
# Fix 2: Run key — staging path + non-trusted-dir detection
# ===========================================================================
Describe "Fix-2 Run key: behavior-based detection (staging path + non-trusted dir)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-RefactorBaseline
    }

    It "Should flag a custom payload in %APPDATA% as High even without a LOLBin name" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'HKLM.*Run$' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ EvilApp = 'C:\Users\victim\AppData\Roaming\evil.exe' }
        } -ParameterFilter { $Path -match 'HKLM.*Run$' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Registry Key' -and $_.Target -match 'Run' }
        $f | Should -Not -BeNullOrEmpty -Because "custom payload in AppData Run key is the attack mechanism"
        $f[0].Severity | Should -Be 'High'
    }

    It "Should flag a non-standard path (not Program Files / Windows) as Medium (downgrade not exclude)" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'HKLM.*Run$' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ VendorTool = 'C:\CustomApps\vendortool.exe' }
        } -ParameterFilter { $Path -match 'HKLM.*Run$' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Registry Key' -and $_.Target -match 'Run' }
        $f | Should -Not -BeNullOrEmpty -Because "non-standard path in Run key should be visible at Medium"
        $f[0].Severity | Should -Be 'Medium'
    }

    It "Should NOT flag a standard Program Files path (normal software install)" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'HKLM.*Run$' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Outlook = '"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"' }
        } -ParameterFilter { $Path -match 'HKLM.*Run$' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Registry Key' -and $_.Target -match 'Run' }) |
            Should -HaveCount 0 -Because "Program Files path is a trusted install location"
    }
}

# ===========================================================================
# Fix 3: BITS — behavior-only, no name/CDN allowlists
# ===========================================================================
Describe "Fix-3 BITS: behavior-only detection (no name or CDN suppression)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-RefactorBaseline
    }

    It "Should flag exe download to staging path as High regardless of display name or CDN source" {
        # Attacker names job 'MicrosoftEdgeUpdate' and downloads from a CDN --
        # the DESTINATION (staging) is the mechanism signal.
        Mock Get-BitsTransfer {
            @(New-FakeBitsJob -Name 'MicrosoftEdgeUpdate' `
                -Url 'https://azureedge.net/packages/edge.exe' `
                -Dest 'C:\Users\Public\edge.exe')
        }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High' -Because "exe to staging path is the attack mechanism, name is irrelevant"
    }

    It "Should flag a CDN-sourced job to a protected path as Medium (exe signal, not staging)" {
        # Edge update from azureedge.net to Program Files -- not staging, but exe download
        # with unknown context. Downgrade to Medium, not suppress.
        Mock Get-BitsTransfer {
            @(New-FakeBitsJob -Name 'MicrosoftEdgeUpdate' `
                -Url 'https://msedge.azureedge.net/packages/edge.exe' `
                -Dest 'C:\Program Files\Edge\edge.exe')
        }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Medium' -Because "exe download but not to staging -- downgrade not suppress"
    }

    It "Should flag staging-area destination as High even for non-executable file types" {
        # Domain-fronted payload without .exe extension still goes to staging
        Mock Get-BitsTransfer {
            @(New-FakeBitsJob -Name 'BackupSync' `
                -Url 'https://cloudfront.net/update.dat' `
                -Dest 'C:\Users\victim\AppData\Local\Temp\update.dat')
        }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High' -Because "staging destination is the behavior signal regardless of extension"
    }

    It "Should flag a bare-IP source URL as High even with a trusted-sounding job name" {
        Mock Get-BitsTransfer {
            @(New-FakeBitsJob -Name 'WindowsUpdate' `
                -Url 'http://203.0.113.9/payload.dat' `
                -Dest 'C:\Windows\Temp\payload.dat')
        }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }
}

# ===========================================================================
# Fix 4a: Network outbound — trusted proc downgrade not skip
# ===========================================================================
Describe "Fix-4a Network: trusted outbound process downgraded not excluded" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-RefactorBaseline
    }

    It "Should still flag OneDrive.exe beaconing on non-standard port but at Medium (downgraded)" {
        # Attacker injects C2 into OneDrive.exe -- currently skipped entirely.
        # After fix: flagged at Medium (trusted proc + unusual port).
        $conn = [PSCustomObject]@{
            RemoteAddress = '1.2.3.4'; RemotePort = 8888
            LocalPort = 54321; OwningProcess = 9050; State = 'Established'
        }
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId = 9050; Name = 'OneDrive.exe'; ExecutablePath = 'C:\Windows\OneDrive.exe' })
        }

        Invoke-NetworkHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Outbound Connection' }
        $f | Should -Not -BeNullOrEmpty -Because "C2 injected into OneDrive must not be silently skipped"
        $f[0].Severity | Should -Be 'Medium' -Because "trusted process gets one severity tier downgraded"
    }

    It "Should flag Teams.exe on a non-standard port as Medium (injection detection)" {
        $conn = [PSCustomObject]@{
            RemoteAddress = '5.6.7.8'; RemotePort = 4444
            LocalPort = 54321; OwningProcess = 9051; State = 'Established'
        }
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId = 9051; Name = 'teams.exe'; ExecutablePath = 'C:\Users\victim\AppData\Local\Microsoft\Teams\teams.exe' })
        }

        Invoke-NetworkHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Outbound Connection' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'Medium'
    }
}

# ===========================================================================
# Fix 4b: Named pipe GUID structural detection
# ===========================================================================
Describe "Fix-4b Named pipe: GUID-format pipe detection (structural, not name-based)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-RefactorBaseline
    }

    It "Should flag a GUID-format pipe name as Medium (structural C2 pattern)" {
        # Cobalt Strike and other frameworks randomize pipe names to GUID format.
        # Detecting the STRUCTURE catches renamed frameworks.
        Mock Get-NamedPipeName {
            @('\\.\pipe\a1b2c3d4-e5f6-7890-abcd-ef1234567890')
        }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Named Pipe' }
        $f | Should -Not -BeNullOrEmpty -Because "GUID-format pipe name is a structural C2 indicator"
    }

    It "Should still flag known C2 framework default pipe names" {
        Mock Get-NamedPipeName { @('\\.\pipe\msagent_1a2b3c') }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Named Pipe' }
        $f | Should -Not -BeNullOrEmpty
    }

    It "Should NOT flag standard system named pipes" {
        Mock Get-NamedPipeName {
            @('\\.\pipe\lsass', '\\.\pipe\svcctl', '\\.\pipe\srvsvc', '\\.\pipe\winreg')
        }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Named Pipe' }) |
            Should -HaveCount 0
    }
}

# ===========================================================================
# Fix 5: Hidden process — coreAllowed/coreAllowedWildcards downgrade not skip
# ===========================================================================
Describe "Fix-5 Hidden process: coreAllowed name match downgrades, does not exclude" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-RefactorBaseline
    }

    It "Should fire Hidden Process at Low severity when name matches coreAllowed exactly" {
        # svchost.exe is in $coreAllowed -- a genuinely hidden process (confirmed via
        # re-verify, so this is NOT an enumeration-race false positive) using this name
        # must still be visible, just downgraded. A name match is not identity proof --
        # malware naming itself svchost.exe would pass this check too.
        Mock Get-CimInstance {
            @(Make-RefProc -ProcId 9010 -Name 'svchost.exe')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' -and -not $Filter }
        Mock Get-Process { throw 'not found' } -ParameterFilter { $Id -eq 9010 }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId = 9010 })
        } -ParameterFilter { $Filter -match 'ProcessId=9010' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Hidden Process' -and $_.Target -match '9010' }
        $f | Should -Not -BeNullOrEmpty -Because "a genuinely hidden process must never be silently invisible, even if the name matches an expected list"
        $f[0].Severity | Should -Be 'Low' -Because "name match alone is not identity proof -- downgrade, don't exclude"
    }

    It "Should fire Hidden Process at Low severity when name matches a coreAllowedWildcards prefix" {
        Mock Get-CimInstance {
            @(Make-RefProc -ProcId 9011 -Name 'IntelAudioService.exe')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' -and -not $Filter }
        Mock Get-Process { throw 'not found' } -ParameterFilter { $Id -eq 9011 }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId = 9011 })
        } -ParameterFilter { $Filter -match 'ProcessId=9011' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Hidden Process' -and $_.Target -match '9011' }
        $f | Should -Not -BeNullOrEmpty -Because "Intel* wildcard match must still surface a genuinely hidden process"
        $f[0].Severity | Should -Be 'Low'
    }

    It "Should fire Hidden Process at High severity when name does NOT match any allowlist entry" {
        Mock Get-CimInstance {
            @(Make-RefProc -ProcId 9012 -Name 'totallyrandom.exe')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' -and -not $Filter }
        Mock Get-Process { throw 'not found' } -ParameterFilter { $Id -eq 9012 }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId = 9012 })
        } -ParameterFilter { $Filter -match 'ProcessId=9012' }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Hidden Process' -and $_.Target -match '9012' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'High' -Because "an unnamed/unexpected hidden process is still full severity"
    }

    It "Should NOT fire when the process is a timing-race artifact (visible in Get-Process re-verify)" {
        Mock Get-CimInstance {
            @(Make-RefProc -ProcId 9013 -Name 'svchost.exe')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' -and -not $Filter }
        # Re-verify succeeds this time -> not actually hidden, just a snapshot-timing race.
        Mock Get-Process { [PSCustomObject]@{ Id = 9013 } } -ParameterFilter { $Id -eq 9013 }

        Invoke-ProcessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Hidden Process' -and $_.Target -match '9013' }) |
            Should -HaveCount 0 -Because "re-verify confirmed this was an enumeration race, not a real hidden process"
    }
}
