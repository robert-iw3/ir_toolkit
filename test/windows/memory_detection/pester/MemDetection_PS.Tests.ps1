<#
.SYNOPSIS
    Pester 5 tests for PowerShell-side memory detection logic.

    Covers:
      - TTP-017 (PEB cmdline spoofing): Get-FindingContext.ps1 cross-reference block
        that compares in-memory cmdline against collected processes.csv cmdline.
      - TTP-011 (CLR execute-assembly): live-host CLR-in-non-managed-host detection
        that would be added to dev/src/01_Process_And_Injection.ps1.

    These tests validate the LOGIC before it is rolled into production PS1 files.
    All tests use in-memory data fixtures -- no live WMI, no remote connections.
#>

BeforeAll {
    # ---------------------------------------------------------------------------
    # Inline the TTP-017 PS logic under test so we can unit-test it directly.
    # When rolled to production this block lives in Get-FindingContext.ps1.
    # ---------------------------------------------------------------------------
    function Test-CmdlineMismatch {
        param(
            [string]$MemCmdline,
            [string]$EventCmdline,
            [string]$ProcessName,
            [int]$ProcessId
        )
        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $memLow   = $MemCmdline.Trim().ToLower()
        $evtLow   = $EventCmdline.Trim().ToLower()
        if (-not $memLow -or -not $evtLow) { return $findings }
        if ($memLow -eq $evtLow)            { return $findings }
        $findings.Add([pscustomobject]@{
            Severity = 'High'
            Type     = 'PEB CommandLine Spoofing (Argue)'
            Target   = "PID $ProcessId ($ProcessName)"
            Details  = "Mismatch: creation-time=[$evtLow] vs in-memory PEB=[$memLow]. " +
                       "Consistent with Cobalt Strike Argue post-launch cmdline patch."
            MITRE    = 'T1055.012, T1036'
        })
        return $findings
    }

    # ---------------------------------------------------------------------------
    # Inline the TTP-011 PS logic under test.
    # When rolled to production this block lives in Invoke-InjectionHunt (EDR_Toolkit).
    # ---------------------------------------------------------------------------
    $Script:ManagedHosts = @(
        'powershell','pwsh','dotnet','msbuild','devenv','code','rider',
        'csc','vbc','java','mono','ngen','regasm','regsvcs','installutil'
    )
    $Script:ClrModules = @('clr.dll','coreclr.dll','clrjit.dll','mscorlib.dll')

    function Test-ClrInNonManagedHost {
        param(
            [string]$ProcessName,
            [int]$ProcessId,
            [string[]]$LoadedModules
        )
        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $nameLow  = $ProcessName.ToLower() -replace '\.exe$',''
        if ($Script:ManagedHosts -contains $nameLow) { return $findings }
        $clrHits = $LoadedModules | Where-Object { $Script:ClrModules -contains $_.ToLower() }
        if (-not $clrHits) { return $findings }
        # Suppress if mscoree.dll present (legitimate managed host).
        if ($LoadedModules -icontains 'mscoree.dll') { return $findings }
        $findings.Add([pscustomobject]@{
            Severity = 'High'
            Type     = 'CLR in Non-Managed Process'
            Target   = "PID $ProcessId ($ProcessName)"
            Details  = "CLR module(s) [$($clrHits -join ', ')] in non-.NET host. " +
                       "execute-assembly/Donut indicator."
            MITRE    = 'T1620, T1055'
        })
        return $findings
    }
}


# ==============================================================================
# TTP-017: PEB CommandLine Spoofing (Argue)
# ==============================================================================
Describe "TTP-017 PEB Cmdline Spoofing -- mismatch logic" {

    It "fires High when in-memory cmdline differs from creation-time cmdline" {
        $r = Test-CmdlineMismatch -MemCmdline 'powershell -enc AABB' `
                                   -EventCmdline 'notepad.exe' `
                                   -ProcessName 'powershell.exe' -ProcessId 1234
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'High'
        $r[0].Type     | Should -Match 'Argue'
    }

    It "does not fire when cmdlines match (case-insensitive)" {
        $r = Test-CmdlineMismatch -MemCmdline 'NOTEPAD.EXE' `
                                   -EventCmdline 'notepad.exe' `
                                   -ProcessName 'notepad.exe' -ProcessId 1235
        $r.Count | Should -Be 0
    }

    It "does not fire when either cmdline is empty" {
        $r1 = Test-CmdlineMismatch -MemCmdline '' -EventCmdline 'notepad.exe' `
                                    -ProcessName 'notepad.exe' -ProcessId 1236
        $r2 = Test-CmdlineMismatch -MemCmdline 'notepad.exe' -EventCmdline '' `
                                    -ProcessName 'notepad.exe' -ProcessId 1237
        $r1.Count | Should -Be 0
        $r2.Count | Should -Be 0
    }

    It "Target contains ProcessId and process name" {
        $r = Test-CmdlineMismatch -MemCmdline 'evil -cmd' -EventCmdline 'benign' `
                                   -ProcessName 'svchost.exe' -ProcessId 9999
        $r[0].Target | Should -Match '9999'
        $r[0].Target | Should -Match 'svchost'
    }

    It "Details contains both cmdlines" {
        $r = Test-CmdlineMismatch -MemCmdline 'malicious args' `
                                   -EventCmdline 'original benign' `
                                   -ProcessName 'notepad.exe' -ProcessId 1238
        $r[0].Details | Should -Match 'malicious args'
        $r[0].Details | Should -Match 'original benign'
    }

    It "MITRE includes T1055.012" {
        $r = Test-CmdlineMismatch -MemCmdline 'x' -EventCmdline 'y' `
                                   -ProcessName 'test.exe' -ProcessId 1239
        $r[0].MITRE | Should -Match 'T1055.012'
    }

    It "whitespace-only cmdline treated as empty -- no finding" {
        $r = Test-CmdlineMismatch -MemCmdline '   ' -EventCmdline 'notepad.exe' `
                                   -ProcessName 'notepad.exe' -ProcessId 1240
        $r.Count | Should -Be 0
    }

    It "cleared in-memory cmdline -- no finding at this layer (handled by log-comparison layer)" {
        $r = Test-CmdlineMismatch -MemCmdline '' -EventCmdline 'mimikatz.exe /dumpcreds' `
                                   -ProcessName 'svchost.exe' -ProcessId 1241
        $r.Count | Should -Be 0
    }
}


# ==============================================================================
# TTP-011: CLR in non-managed host
# ==============================================================================
Describe "TTP-011 CLR in Non-Managed Host -- detection logic" {

    It "fires High for notepad.exe with clr.dll" {
        $r = Test-ClrInNonManagedHost -ProcessName 'notepad.exe' -ProcessId 2000 `
                                       -LoadedModules @('ntdll.dll','kernel32.dll','clr.dll','clrjit.dll')
        $r.Count       | Should -Be 1
        $r[0].Severity | Should -Be 'High'
        $r[0].Type     | Should -Match 'CLR'
    }

    It "does not fire for powershell.exe (managed host)" {
        $r = Test-ClrInNonManagedHost -ProcessName 'powershell.exe' -ProcessId 2001 `
                                       -LoadedModules @('clr.dll','clrjit.dll')
        $r.Count | Should -Be 0
    }

    It "does not fire when mscoree.dll is also loaded (legitimate)" {
        $r = Test-ClrInNonManagedHost -ProcessName 'myapp.exe' -ProcessId 2002 `
                                       -LoadedModules @('mscoree.dll','clr.dll')
        $r.Count | Should -Be 0
    }

    It "does not fire when no CLR modules are loaded" {
        $r = Test-ClrInNonManagedHost -ProcessName 'calc.exe' -ProcessId 2003 `
                                       -LoadedModules @('ntdll.dll','kernel32.dll')
        $r.Count | Should -Be 0
    }

    It "lists CLR modules found in Details" {
        $r = Test-ClrInNonManagedHost -ProcessName 'explorer.exe' -ProcessId 2004 `
                                       -LoadedModules @('clr.dll','coreclr.dll')
        $r[0].Details | Should -Match 'clr.dll'
    }

    It "Target contains ProcessId and process name" {
        $r = Test-ClrInNonManagedHost -ProcessName 'svchost.exe' -ProcessId 9876 `
                                       -LoadedModules @('clr.dll')
        $r[0].Target | Should -Match '9876'
        $r[0].Target | Should -Match 'svchost'
    }

    It "suppresses .exe suffix when matching managed host list" {
        $r = Test-ClrInNonManagedHost -ProcessName 'msbuild.exe' -ProcessId 2005 `
                                       -LoadedModules @('clr.dll')
        $r.Count | Should -Be 0
    }

    It "MITRE includes T1620" {
        $r = Test-ClrInNonManagedHost -ProcessName 'notepad.exe' -ProcessId 2006 `
                                       -LoadedModules @('clr.dll')
        $r[0].MITRE | Should -Match 'T1620'
    }
}
