<#
.SYNOPSIS
    Phase 2 gap-fill tests -- new persistence registry detections in
    Invoke-FilelessHunt and Invoke-AdvancedRegistryHunt.

    Items under test:
      P2-2B  AppCertDLLs     (T1546.009) -- any value -> Critical
      P2-2C  IFEO Debugger   (T1546.012) -- any binary with Debugger value -> High
      P2-2C  IFEO GlobalFlag (T1546.012) -- bit 0x200 set -> High
      P2-2E  Active Setup    (T1547.014) -- suspicious StubPath -> High/Medium
      P2-2G  Accessibility   (T1546.008) -- sethc/utilman/magnify/osk Debugger -> Critical
      P2-3C  Unquoted Svc    (T1574.009) -- space-bearing unquoted ImagePath -> High
      Regression: existing AppInit_DLLs / BootExecute / Winlogon via AdvancedRegistryHunt
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")

    function script:Set-P2BaselineMocks {
        Mock Get-CimInstance      { @() }
        Mock Get-WmiObject        { @() }
        Mock Get-BitsTransfer     { @() }
        Mock Invoke-LsassDumpHunt {}
        Mock Test-Path            { $false }
        Mock Get-ItemProperty     { [PSCustomObject]@{} }
        Mock Get-ChildItem        { @() }
    }
}

# ---------------------------------------------------------------------------
# P2-2B: AppCertDLLs
# ---------------------------------------------------------------------------
Describe "P2-2B AppCertDLLs Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should flag any value in AppCertDLLs as Critical" {
        Mock Test-Path { $true } -ParameterFilter {
            $Path -match 'AppCertDLLs'
        }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ EvilHook = 'C:\evil\hook.dll' }
        } -ParameterFilter { $Path -match 'AppCertDLLs' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'AppCertDLLs Injection' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].Details  | Should -Match 'hook\.dll'
        $f[0].Details  | Should -Match 'CreateProcess'
    }

    It "Should report ATT&CK T1546.009 in MITRE field" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'AppCertDLLs' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Dropper = 'C:\Temp\payload.dll' }
        } -ParameterFilter { $Path -match 'AppCertDLLs' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'AppCertDLLs Injection' }
        $f[0].MITRE | Should -Match 'T1546.009'
    }

    It "Should NOT fire when AppCertDLLs key is absent" {
        Invoke-FilelessHunt
        ($script:Findings | Where-Object { $_.Type -eq 'AppCertDLLs Injection' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P2-2G: Accessibility Feature IFEO Hijack (sethc, utilman, magnify, osk, narrator)
# ---------------------------------------------------------------------------
Describe "P2-2G Accessibility Feature IFEO Hijack" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    # Single test covering all accessibility binaries together -- avoids Pester mock closure issues.
    # The mechanism is the same for all of them: ANY debugger -> Critical.
    It "Should flag all accessibility binaries (sethc/utilman/magnify/osk/narrator) with Debugger as Critical" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Image File Execution Options' }
        Mock Get-ChildItem {
            @(
                [PSCustomObject]@{ PSPath = 'HKLM:\...\IFEO\sethc.exe';    PSChildName = 'sethc.exe'    },
                [PSCustomObject]@{ PSPath = 'HKLM:\...\IFEO\utilman.exe';   PSChildName = 'utilman.exe'  },
                [PSCustomObject]@{ PSPath = 'HKLM:\...\IFEO\magnify.exe';   PSChildName = 'magnify.exe'  },
                [PSCustomObject]@{ PSPath = 'HKLM:\...\IFEO\osk.exe';       PSChildName = 'osk.exe'      },
                [PSCustomObject]@{ PSPath = 'HKLM:\...\IFEO\narrator.exe';  PSChildName = 'narrator.exe' }
            )
        } -ParameterFilter { $Path -match 'Image File Execution Options' }
        # Return a Debugger for ALL Get-ItemProperty calls against these paths
        Mock Get-ItemProperty { [PSCustomObject]@{ Debugger = 'C:\evil\payload.exe' } } `
            -ParameterFilter { $Path -match 'IFEO' -and $Name -eq 'Debugger' }
        # GlobalFlag returns nothing for these
        Mock Get-ItemProperty { [PSCustomObject]@{} } `
            -ParameterFilter { $Path -match 'IFEO' -and $Name -eq 'GlobalFlag' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Accessibility Feature Hijack' }
        $f | Should -HaveCount 5   # one per binary
        $f | ForEach-Object {
            $_.Severity | Should -Be 'Critical'
            $_.MITRE    | Should -Match 'T1546.008'
            $_.Details  | Should -Match 'SYSTEM shell'
        }
    }

    It "Should NOT fire Accessibility Finding for a non-accessibility binary (but IFEO Debugger Hijack fires instead)" {
        # notepad.exe is NOT an accessibility binary -- its debugger gets flagged as
        # IFEO Debugger Hijack (the behavior-based check), NOT Accessibility Feature Hijack.
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Image File Execution Options' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\notepad.exe'; PSChildName = 'notepad.exe' })
        } -ParameterFilter { $Path -match 'Image File Execution Options' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Debugger = 'cmd.exe' }
        } -ParameterFilter { $Path -match 'notepad\.exe' }

        Invoke-AdvancedRegistryHunt

        # Accessibility-specific finding must NOT fire
        ($script:Findings | Where-Object { $_.Type -eq 'Accessibility Feature Hijack' }) |
            Should -HaveCount 0
        # But the behavior-based IFEO Debugger Hijack MUST fire (any debugger = redirect)
        ($script:Findings | Where-Object { $_.Type -eq 'IFEO Debugger Hijack' }) |
            Should -HaveCount 1
    }
}

# ---------------------------------------------------------------------------
# P2-2C: IFEO GlobalFlag (0x200 = FLG_APPLICATION_VERIFIER -- silent exec replace)
# ---------------------------------------------------------------------------
Describe "P2-2C IFEO GlobalFlag Hijack" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should flag GlobalFlag with bit 0x200 set as High" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Image File Execution Options' }
        Mock Test-Path { $false } -ParameterFilter { $Path -match 'SilentProcessExit' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\victim.exe'; PSChildName = 'victim.exe' })
        } -ParameterFilter { $Path -match 'Image File Execution Options' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ GlobalFlag = 0x200 }
        } -ParameterFilter { $Path -match 'victim\.exe' -and $Name -eq 'GlobalFlag' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'IFEO GlobalFlag Hijack' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1546.012'
        $f[0].Details  | Should -Match '200'
    }

    It "Should NOT fire when GlobalFlag is 0 or absent" {
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\victim.exe'; PSChildName = 'victim.exe' })
        } -ParameterFilter { $Path -match 'Image File Execution Options' }
        Mock Get-ItemProperty { [PSCustomObject]@{} } -ParameterFilter {
            $Path -match 'victim\.exe' -and $Name -eq 'GlobalFlag'
        }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'IFEO GlobalFlag Hijack' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P2-2E: Active Setup StubPath persistence
# ---------------------------------------------------------------------------
Describe "P2-2E Active Setup Persistence Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should flag a LOLBin StubPath as High" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\Active Setup\{EVIL-GUID}'; PSChildName = '{EVIL-GUID}' })
        } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ StubPath = 'powershell -enc AAABBBCCC' }
        } -ParameterFilter { $Path -match 'EVIL-GUID' -and $Name -eq 'StubPath' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1547.014'
        $f[0].Details  | Should -Match 'logon'
    }

    It "Should flag a Temp-path StubPath as High (staging area)" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\{TEMP-GUID}'; PSChildName = '{TEMP-GUID}' })
        } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ StubPath = 'C:\Users\Public\payload.exe' }
        } -ParameterFilter { $Path -match 'TEMP-GUID' -and $Name -eq 'StubPath' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should flag an unusual StubPath (not system32 rundll32/regsvr32) as Medium" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\{WEIRD-GUID}'; PSChildName = '{WEIRD-GUID}' })
        } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ StubPath = 'C:\ProgramFiles\VendorApp\setup.exe /silent' }
        } -ParameterFilter { $Path -match 'WEIRD-GUID' -and $Name -eq 'StubPath' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Medium'
    }

    It "Should NOT flag a standard rundll32 system32 StubPath" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\{OK-GUID}'; PSChildName = '{OK-GUID}' })
        } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ StubPath = 'rundll32 "C:\Windows\system32\iesetup.dll",IEHardenLMSettings' }
        } -ParameterFilter { $Path -match 'OK-GUID' -and $Name -eq 'StubPath' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }) |
            Should -HaveCount 0
    }

    It "Should NOT fire when Active Setup key is absent" {
        Invoke-FilelessHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# P2-3C: Unquoted Service Path
# ---------------------------------------------------------------------------
Describe "P2-3C Unquoted Service Path Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should flag a service with unquoted space-bearing ImagePath as High" {
        $svc = [PSCustomObject]@{
            Name     = 'EvilSvc'
            PathName = 'C:\Program Files\Evil App\evil.exe -svc'
            StartMode = 'Auto'
        }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Unquoted Service Path' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].MITRE    | Should -Match 'T1574.009'
        $f[0].Details  | Should -Match 'Evil App'
    }

    It "Should NOT flag a correctly quoted ImagePath with spaces" {
        $svc = [PSCustomObject]@{
            Name     = 'SafeSvc'
            PathName = '"C:\Program Files\Safe App\safe.exe" -svc'
            StartMode = 'Auto'
        }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Unquoted Service Path' }) |
            Should -HaveCount 0
    }

    It "Should NOT flag a path with no spaces" {
        $svc = [PSCustomObject]@{
            Name     = 'CompactSvc'
            PathName = 'C:\Windows\system32\svchost.exe -k netsvcs'
            StartMode = 'Auto'
        }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Unquoted Service Path' }) |
            Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# Regression: AppInit_DLLs (already implemented -- ensure not broken)
# ---------------------------------------------------------------------------
Describe "Regression AppInit_DLLs Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should flag any non-empty AppInit_DLLs as High" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'AppInit_DLLs|CurrentVersion\\Windows' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ AppInit_DLLs = 'C:\evil\inject.dll' }
        } -ParameterFilter { $Path -match 'CurrentVersion\\Windows' }
        Mock Get-CimInstance { @() } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'AppInit_DLLs Hijack' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'High'
    }
}

# ---------------------------------------------------------------------------
# Live-test regression fixes (discovered 2026-06-28 live scan)
# ---------------------------------------------------------------------------
Describe "Live-fix: Service check $lolbinPattern scope bug (all services fired High)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should NOT flag C:\Windows\system32\svchost.exe as Suspicious Service" {
        # BUG: $lolbinPattern was undefined in Invoke-AdvancedRegistryHunt scope ->
        # '$path -match $null' = always True -> every service fired High.
        # Fix: define $svcLolbinPattern locally in Invoke-AdvancedRegistryHunt.
        $svc = [PSCustomObject]@{ Name='TestSvc'; PathName='C:\Windows\system32\svchost.exe -k netsvcs'; StartMode='Auto' }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' -or $Path -match 'Print\\Monitors' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Service' -and $_.Target -match 'TestSvc' }) |
            Should -HaveCount 0 -Because "system32 svchost.exe is a trusted Windows service path"
    }

    It "Should NOT flag C:\Program Files\Common Files\vendor\service.exe as Suspicious Service" {
        $svc = [PSCustomObject]@{ Name='VendorSvc'; PathName='"C:\Program Files\Common Files\VendorApp\vendorsvc.exe"'; StartMode='Auto' }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' -or $Path -match 'Print\\Monitors' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Service' -and $_.Target -match 'VendorSvc' }) |
            Should -HaveCount 0 -Because "Program Files path is a trusted install location"
    }

    It "Should NOT flag NVIDIA service whose binary is in Program Files but args contain ProgramData log path" {
        # Bug: staging-area check fired on '-f C:\ProgramData\NVIDIA\...' in args.
        # Fix: extract binary path before checking, not the full PathName with args.
        $nvPath = '"C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe" -s NvContainerLocalSystem -a -f "C:\ProgramData\NVIDIA\log.txt"'
        $svc = [PSCustomObject]@{ Name='NvContainerSvc'; PathName=$nvPath; StartMode='Auto' }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' -or $Path -match 'Print\\Monitors' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Service' -and $_.Target -match 'NvContainerSvc' }) |
            Should -HaveCount 0 -Because "binary is in Program Files; ProgramData in args is a log file path not the binary"
    }

    It "Should NOT flag Windows Defender services in ProgramData\Microsoft\Windows Defender" {
        # Defender installs to versioned paths under ProgramData\Microsoft\Windows Defender
        # by design (platform updates). These are trusted Microsoft binaries.
        $defPath = '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26050.15-0\MsMpEng.exe"'
        $svc = [PSCustomObject]@{ Name='WinDefend'; PathName=$defPath; StartMode='Auto' }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' -or $Path -match 'Print\\Monitors' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Service' -and $_.Target -match 'WinDefend' }) |
            Should -HaveCount 0 -Because "Windows Defender ProgramData path is Microsoft-signed trusted binary"
    }

    It "Should still flag a service path in AppData as High" {
        $svc = [PSCustomObject]@{ Name='EvilSvc'; PathName='C:\Users\victim\AppData\Roaming\evil.exe'; StartMode='Auto' }
        Mock Get-CimInstance { @($svc) } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' -or $Path -match 'Print\\Monitors' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Service' -and $_.Target -match 'EvilSvc' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High' -Because "staging-area service path is High severity"
    }
}

Describe "Live-fix: Print Monitor bare DLL names (system32-resolved) wrongly flagged" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should NOT flag a bare DLL name (no path) as port monitor is system32-resolved" {
        # localspl.dll, tcpmon.dll etc are stored WITHOUT a path -- Windows resolves
        # them to system32. The path-prefix check fails on bare names -> all fire High.
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\Print\Monitors\LocalMon'; PSChildName = 'LocalMon' })
        } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Driver = 'localspl.dll' }
        } -ParameterFilter { $Path -match 'LocalMon' -and $Name -eq 'Driver' }
        Mock Get-CimInstance { @() } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' }

        Invoke-AdvancedRegistryHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Print Monitor DLL' }) |
            Should -HaveCount 0 -Because "bare DLL name = system32-resolved = trusted Windows monitor"
    }

    It "Should still flag a bare DLL name that is not a known Windows monitor name as Medium" {
        # Unknown bare name without path = could be DLL hijack via search-order
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\Print\Monitors\EvMon'; PSChildName = 'EvMon' })
        } -ParameterFilter { $Path -match 'Print\\Monitors' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Driver = 'unknownmon.dll' }
        } -ParameterFilter { $Path -match 'EvMon' -and $Name -eq 'Driver' }
        Mock Get-CimInstance { @() } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        Mock Get-ChildItem { @() } -ParameterFilter { $Path -match 'Image File' }

        Invoke-AdvancedRegistryHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Print Monitor DLL' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Medium' -Because "unknown bare name = DLL search-order risk, downgrade"
    }
}

# ---------------------------------------------------------------------------
# Live-test regression fixes (discovered 2026-06-28 against this machine)
# ---------------------------------------------------------------------------
Describe "Live-fix: WMI consumer name extraction (SCM Event Log Consumer FP)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should suppress SCM Event Log Consumer when name is in alternate format 'NTEventLogEventConsumer (Name = ...)'" {
        # Real-world format from live host differs from __EventConsumer.Name="..." pattern.
        # Fallback to full string caused the allowlist check to miss it -> spurious High.
        $fakeConsumer = [PSCustomObject]@{
            Name                 = 'SCM Event Log Consumer'
            CommandLineTemplate  = ''
            ScriptText           = ''
        }
        $fakeFilter = [PSCustomObject]@{ Name = 'SCM Event Log Filter'; Query = 'SELECT * FROM __InstanceModificationEvent' }
        $fakeBinding = [PSCustomObject]@{
            Consumer = 'NTEventLogEventConsumer (Name = "SCM Event Log Consumer")'
            Filter   = '__EventFilter (Name = "SCM Event Log Filter")'
        }
        Mock Get-CimInstance { @($fakeConsumer) } -ParameterFilter { $ClassName -eq '__EventConsumer' }
        Mock Get-CimInstance { @($fakeFilter)   } -ParameterFilter { $ClassName -eq '__EventFilter' }
        Mock Get-CimInstance { @($fakeBinding)  } -ParameterFilter { $ClassName -eq '__FilterToConsumerBinding' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'WMI Persistence' }) |
            Should -HaveCount 0 -Because "SCM Event Log Consumer is a known-good Windows built-in"
    }

    It "Should still flag a genuinely unknown consumer with the alternate name format" {
        $fakeConsumer = [PSCustomObject]@{ Name = 'EvilConsumer'; CommandLineTemplate = 'cmd /c evil.bat'; ScriptText = '' }
        $fakeFilter   = [PSCustomObject]@{ Name = 'EvilFilter';   Query = 'SELECT * FROM __InstanceModificationEvent' }
        $fakeBinding  = [PSCustomObject]@{
            Consumer = 'NTEventLogEventConsumer (Name = "EvilConsumer")'
            Filter   = '__EventFilter (Name = "EvilFilter")'
        }
        Mock Get-CimInstance { @($fakeConsumer) } -ParameterFilter { $ClassName -eq '__EventConsumer' }
        Mock Get-CimInstance { @($fakeFilter)   } -ParameterFilter { $ClassName -eq '__EventFilter' }
        Mock Get-CimInstance { @($fakeBinding)  } -ParameterFilter { $ClassName -eq '__FilterToConsumerBinding' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'WMI Persistence' -and $_.Severity -eq 'High' }) |
            Should -HaveCount 1
    }
}

Describe "Live-fix: Active Setup known-good pattern (full-path Rundll32 FP)" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-P2BaselineMocks
    }

    It "Should NOT flag full-path Rundll32.exe with system32 DLL (mscories.dll pattern)" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\{89B4C1CD}'; PSChildName = '{89B4C1CD}' })
        } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ StubPath = 'C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install' }
        } -ParameterFilter { $Path -match '89B4C1CD' -and $Name -eq 'StubPath' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }) |
            Should -HaveCount 0 -Because "Full-path Rundll32.exe with a system32 DLL is a known-good Windows pattern"
    }

    It "Should NOT flag bare rundll32 with system32 DLL (existing pattern, regression)" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\{OK}'; PSChildName = '{OK}' })
        } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ StubPath = 'rundll32 "C:\Windows\system32\iesetup.dll",IEHardenLMSettings' }
        } -ParameterFilter { $Path -match 'OK' -and $Name -eq 'StubPath' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }) |
            Should -HaveCount 0
    }

    It "Should STILL flag an attacker using Rundll32 with a non-system32 DLL as High" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ChildItem {
            @([PSCustomObject]@{ PSPath = 'HKLM:\...\{EVIL}'; PSChildName = '{EVIL}' })
        } -ParameterFilter { $Path -match 'Active Setup' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ StubPath = 'C:\Windows\System32\Rundll32.exe C:\Users\Public\evil.dll,Run' }
        } -ParameterFilter { $Path -match 'EVIL' -and $Name -eq 'StubPath' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Active Setup Persistence' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High' -Because "Rundll32 with a user-writable DLL path is a staging-area indicator"
    }
}
