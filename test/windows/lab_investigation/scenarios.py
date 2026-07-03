"""Synthetic finding scenarios for the investigation engine lab.

Scenarios cover the full detection spectrum:
  - Normal background noise (taskhostw, svchost, wmiprvse) -- must close without investigation
  - LotL blending: system binary names, legitimate paths, but anomalous behavior
  - Advanced techniques: Ekko sleep, CLR execute-assembly, COM VTable hijacking
  - Clear TP chains: CobaltStrike, Sliver, shellcode threads with YARA
  - Intermediate / mixed signals: UNDETERMINED cases needing more collection

Each scenario is a dict with:
  pid, process (for labeling), expected_verdict (VerdictLabel string), and
  findings (list of memory_forensic.py-format dicts).
"""
from __future__ import annotations
from typing import Any, Dict, List


def _f(severity: str, ftype: str, pid: int, process: str,
       details: str, addr: str = '', mitre: str = 'T1055') -> Dict[str, Any]:
    target = f'PID {pid} ({process})' + (f' @ {addr}' if addr else '')
    return {
        'Timestamp': '2026-07-03 10:00:00',
        'Severity':  severity,
        'Type':      ftype,
        'Target':    target,
        'Details':   details,
        'MITRE':     mitre,
    }


# ============================================================================
# CATEGORY 1: NORMAL BACKGROUND NOISE -- engine must NOISE_CLOSE these
# ============================================================================

NOISE_TASKHOSTW = {
    'pid': 7076,
    'process': 'taskhostw.exe',
    'expected': 'NOISE_CLOSED',
    'description': 'taskhostw.exe task-scheduler work items -- canonical benign M13 example from investigation guide',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 7076, 'taskhostw.exe',
           'Private RW region entropy=7.06 size=32768 bytes. No execute flag at snapshot time -- '
           'consistent with sleep-mask or Gargoyle W^X beacon resting between execution windows. '
           'Prot=PAGE_READWRITE. '
           'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=7a 00 00 00 f8 7f 10 1d 3a 01 00 00 00 00 00 00. '
           'Corroborate: APC/timer targeting this address.',
           '0x13a1c8c0000'),
        _f('High', 'Dormant Beacon Candidate (Memory)', 7076, 'taskhostw.exe',
           'Private RW region entropy=7.17 size=32768 bytes. '
           'ByteDistrib: CV=198% [non-uniform(data-likely)] ASCII=46% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=7a 00 00 00 db 01 00 00 00 00 00 00 00 00 00 00. '
           'Corroborate: APC/timer targeting this address.',
           '0x13a1c930000'),
        _f('Medium', 'Thread-Pool / Ekko Pattern (Memory)', 7076, 'taskhostw.exe',
           '8 ntdll-backed running thread(s) in a process that also has a High-severity '
           'dormant beacon region. Matches Ekko/Foliage sleep-obfuscation pattern.'),
        _f('Medium', 'YARA Hit (Memory)', 7076, 'taskhostw.exe',
           '| LOLBin_BITS_Drop | 2 match(es) | file-backed -wx taskhostw.exe'),
    ],
}

NOISE_SVCHOST_COM = {
    'pid': 1024,
    'process': 'svchost.exe',
    'expected': 'NOISE_CLOSED',
    'description': 'svchost.exe COM infrastructure -- high CV, no AdjAnonExec, known parent',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 1024, 'svchost.exe',
           'Private RW region entropy=7.22 size=65536 bytes. '
           'ByteDistrib: CV=180% [non-uniform(data-likely)] ASCII=38% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=00 00 00 00 01 00 00 00 00 10 00 00 00 00 00 00. '
           'Corroborate: APC/timer targeting this address.',
           '0x1a000000'),
    ],
}

NOISE_WMIPRVSE = {
    'pid': 3344,
    'process': 'wmiprvse.exe',
    'expected': 'NOISE_CLOSED',
    'description': 'wmiprvse.exe WMI provider in normal COM host state',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 3344, 'wmiprvse.exe',
           'Private RW region entropy=7.05 size=32768 bytes. '
           'ByteDistrib: CV=165% [non-uniform(data-likely)] ASCII=35% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00.',
           '0x2b000000'),
    ],
}

NOISE_AUDIODG = {
    'pid': 2200,
    'process': 'audiodg.exe',
    'expected': 'NOISE_CLOSED',
    # PCM audio has HIGH CV (non-uniform) -- 16-bit samples cluster near zero (silence).
    # This is NOT uniform like AES. CV ~180-300% is realistic for audio buffers.
    'description': 'audiodg.exe PCM audio buffer -- high CV non-uniform distribution, low ASCII',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 2200, 'audiodg.exe',
           'Private RW region entropy=7.06 size=131072 bytes. '
           'ByteDistrib: CV=220% [non-uniform(data-likely)] ASCII=2% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=00 00 f3 f3 00 00 f2 f2 00 00 00 00 f1 f1 f1 f1.',
           '0x3c000000'),
    ],
}

NOISE_LSASS_KEY = {
    'pid': 676,
    'process': 'lsass.exe',
    'expected': 'NOISE_CLOSED',
    'description': 'lsass.exe AES key material -- UNIFORM but known process at legitimate path',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 676, 'lsass.exe',
           'Private RW region entropy=7.90 size=32 bytes. '
           'ByteDistrib: CV=6% [UNIFORM(crypto-likely)] ASCII=1% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=a3 f2 11 bc 4d 9e 72 a1 c8 55 3d e7 09 6a b4 28. '
           'SECURITY-PROC: security process (AV/EDR/VTL1 component).',
           '0x700000000'),
    ],
}


# ============================================================================
# CATEGORY 2: LOTL BLENDING -- system binary name, normal path, but something is off
# ============================================================================

LOTL_SVCHOST_WRONG_PATH = {
    'pid': 5512,
    'process': 'svchost.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'svchost.exe spawned from C:\\Users\\Public -- path masquerading (LotL)',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 5512, 'svchost.exe',
           'Private RW region entropy=7.87 size=65536 bytes. '
           'Path=C:\\Users\\Public\\svchost.exe. '
           'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=1% '
           'MZ-remnant=False AdjAnonExec=True '
           'Head=fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51. '
           'Corroborate: APC/timer targeting this address.',
           '0x4a000000'),
        _f('High', 'Shellcode Thread (Memory)', 5512, 'svchost.exe',
           'Thread start address 0x4a010000 falls outside all loaded modules. '
           'Executable private VAD (anonymous exec). Not JIT-consistent.'),
        _f('High', 'External Network Connection', 5512, 'svchost.exe',
           'ESTABLISHED 192.168.1.100:49152 -> 185.220.101.45:443 (suspicious external IP)'),
    ],
}

LOTL_DLLHOST_BEACON = {
    'pid': 6688,
    'process': 'dllhost.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'dllhost.exe COM surrogate hosting CobaltStrike -- UNIFORM M13 + M5 + YARA',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 6688, 'dllhost.exe',
           'Private RW region entropy=7.91 size=65536 bytes. '
           'ByteDistrib: CV=7% [UNIFORM(crypto-likely)] ASCII=0% '
           'MZ-remnant=False AdjAnonExec=True '
           'Head=fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51. '
           'Corroborate: APC/timer targeting this address.',
           '0x5b000000'),
        _f('High', 'Shellcode Thread (Memory)', 6688, 'dllhost.exe',
           'Thread start address 0x5b040000 falls outside all loaded modules. '
           'Executable private anonymous VAD. Not JIT-consistent.'),
        _f('High', 'YARA Hit (Memory)', 6688, 'dllhost.exe',
           '| CobaltStrike_BeaconSleep | 3 match(es) | anon 0x5b040000'),
    ],
}

LOTL_EXPLORER_HOLLOW = {
    'pid': 2580,
    'process': 'explorer.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'explorer.exe hollowed -- injected region + shellcode thread + network activity',
    'findings': [
        _f('High', 'Injected Memory Region', 2580, 'explorer.exe',
           'Executable private VAD (no backing file). Protection=PAGE_EXECUTE_READWRITE.',
           '0x10000000'),
        _f('High', 'Shellcode Thread (Memory)', 2580, 'explorer.exe',
           'Thread start address 0x10001000 falls outside all loaded modules. '
           'Thread start inside Module 3 flagged VAD @ 0x10000000. '
           'Cross-process: CreateRemoteThread from PID 4444 (malicious.exe).'),
        _f('High', 'External Network Connection', 2580, 'explorer.exe',
           'ESTABLISHED 10.0.0.5:54321 -> 203.0.113.100:4444'),
    ],
}

LOTL_TASKHOSTW_WITH_SHELLCODE = {
    'pid': 8848,
    'process': 'taskhostw.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'taskhostw.exe -- superficially looks like noise but has shellcode thread + network (noise filter should NOT close)',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 8848, 'taskhostw.exe',
           'Private RW region entropy=7.88 size=65536 bytes. '
           'ByteDistrib: CV=9% [UNIFORM(crypto-likely)] ASCII=0% '
           'MZ-remnant=False AdjAnonExec=True '
           'Head=fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51.',
           '0x6c000000'),
        _f('High', 'Shellcode Thread (Memory)', 8848, 'taskhostw.exe',
           'Thread start 0x6c040000 outside all modules. Anonymous exec. Not JIT-consistent.'),
        _f('High', 'External Network Connection', 8848, 'taskhostw.exe',
           'ESTABLISHED 10.0.0.10:50100 -> 198.51.100.50:443'),
    ],
}


# ============================================================================
# CATEGORY 3: ADVANCED TECHNIQUES
# ============================================================================

ADVANCED_EKKO_SLEEP = {
    'pid': 4420,
    'process': 'notepad.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'Ekko/Foliage sleep: UNIFORM M13 + ntdll thread-pool + Module 14 corroborated',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 4420, 'notepad.exe',
           'Private RW region entropy=7.93 size=65536 bytes. '
           'ByteDistrib: CV=6% [UNIFORM(crypto-likely)] ASCII=0% '
           'MZ-remnant=False AdjAnonExec=True '
           'Head=fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51.',
           '0x7d000000'),
        _f('High', 'Thread-Pool / Ekko Pattern (Memory)', 4420, 'notepad.exe',
           '4 ntdll-backed running thread(s) in a process that also has a '
           'High-severity dormant beacon region. Matches Ekko/Foliage sleep-obfuscation.'),
        _f('High', 'ntdll Syscall Stub Patched (Memory)', 4420, 'notepad.exe',
           'Syscall stub SSN=0x0018 (NtAllocateVirtualMemory) has hook opcode 0xe9 '
           'instead of expected mov r10,rcx (4C 8B D1). '
           'Hook redirects to anonymous exec region 0x7d010000.'),
    ],
}

ADVANCED_CLR_EXECUTE_ASSEMBLY = {
    'pid': 9120,
    'process': 'rundll32.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'CLR execute-assembly via Donut into native process (BSJB in anon exec)',
    'findings': [
        _f('High', 'CLR Execute-Assembly (Memory)', 9120, 'rundll32.exe',
           'BSJB (ECMA-335 .NET assembly magic) found in anonymous executable VAD. '
           'rundll32.exe is a native process -- no CLR hosting expected. '
           'Consistent with Donut/execute-assembly in-memory .NET injection.',
           '0x8e000000'),
        _f('High', 'Injected Memory Region', 9120, 'rundll32.exe',
           'Executable private VAD (no backing file). Protection=PAGE_EXECUTE_READ.',
           '0x8e000000'),
        _f('High', 'Shellcode Thread (Memory)', 9120, 'rundll32.exe',
           'Thread start 0x8e020000 outside all loaded modules. '
           'Thread start inside Module 3 flagged VAD @ 0x8e000000. '
           'Not JIT-consistent. Donut bootstrap stub detected.'),
        _f('High', 'External Network Connection', 9120, 'rundll32.exe',
           'ESTABLISHED 10.10.10.10:53200 -> 104.21.56.78:443'),
    ],
}

ADVANCED_COM_VTABLE = {
    'pid': 3388,
    'process': 'msiexec.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'COM VTable hijacking: pointer redirected into Module 13 dormant beacon region',
    'findings': [
        _f('High', 'COM VTable Hijacking (Memory)', 3388, 'msiexec.exe',
           'COM VTable pointer anomaly: src_address=0x7ff800a1234 dst_address=0xaf000000. '
           'dst falls inside anonymous executable region flagged by Module 13 dormant beacon. '
           'Legitimate VTables point back into their own module image.',
           '0x7ff800a1234'),
        _f('High', 'Dormant Beacon Candidate (Memory)', 3388, 'msiexec.exe',
           'Private RW region entropy=7.89 size=65536 bytes. '
           'ByteDistrib: CV=7% [UNIFORM(crypto-likely)] ASCII=0% '
           'MZ-remnant=False AdjAnonExec=True '
           'Head=4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00.',
           '0xaf000000'),
    ],
}

ADVANCED_PPID_SPOOF = {
    'pid': 7700,
    'process': 'powershell.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'PPID spoofing: powershell.exe with parent PID reuse/mismatch',
    'findings': [
        _f('High', 'PPID Orphan (Memory)', 7700, 'powershell.exe',
           'PID reused: PPID=4 (System) claimed by powershell.exe, but event log 4688 '
           'shows parent was svchost.exe (PID 1234 at spawn time). '
           'PID 4 was recycled after svchost.exe exited. Possible PPID spoofing.'),
        _f('High', 'Shellcode Thread (Memory)', 7700, 'powershell.exe',
           'Thread start 0xba000000 outside all loaded modules. '
           'Anonymous exec. JIT-consistent (CLR host). '
           'Module 12 ntdll hook present in same PID.'),
        _f('High', 'ntdll Syscall Stub Patched (Memory)', 7700, 'powershell.exe',
           'NtWriteVirtualMemory stub patched: SSN=0x003a e9 redirect to anonymous exec 0xba010000.'),
    ],
}

ADVANCED_PEB_DECOY = {
    'pid': 5544,
    'process': 'cmd.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'CobaltStrike Argue technique: PEB CommandLine tampered post-launch',
    'findings': [
        _f('High', 'PEB CommandLine Pointer (Memory)', 5544, 'cmd.exe',
           'PEB.ProcessParameters.CommandLine = "cmd.exe /c whoami" (live memory). '
           'Event log 4688 at spawn time: "cmd.exe /c powershell -enc SGVsbG8...". '
           'Mismatch confirmed: cmdline tampered after process creation (Argue technique). '
           'Buffer pointer falls in anonymous exec region 0xca000000.'),
        _f('High', 'Shellcode Thread (Memory)', 5544, 'cmd.exe',
           'Thread start 0xca010000 outside all loaded modules. Anonymous exec.'),
        _f('High', 'YARA Hit (Memory)', 5544, 'cmd.exe',
           '| CobaltStrike_Argue | 1 match(es) | anon 0xca010000'),
    ],
}

ADVANCED_SLIVER_REFLECTIVE = {
    'pid': 4488,
    'process': 'msdtc.exe',
    'expected': 'TRUE_POSITIVE',
    'description': 'Sliver reflective DLL injected into msdtc.exe -- M3 MZ header + M5 thread + YARA',
    'findings': [
        _f('High', 'Injected Memory Region', 4488, 'msdtc.exe',
           'Executable private VAD (no backing file). MZ header at offset 0 of region. '
           'Protection=PAGE_EXECUTE_READ. Possible manually-mapped PE (reflective DLL/Donut).',
           '0xda000000'),
        _f('High', 'Shellcode Thread (Memory)', 4488, 'msdtc.exe',
           'Thread start 0xda001000 inside Module 3 flagged VAD @ 0xda000000. '
           'Cross-process: CreateRemoteThread from PID 9999.'),
        _f('High', 'YARA Hit (Memory)', 4488, 'msdtc.exe',
           '| Sliver_Implant_ReflectiveLoader | 2 match(es) | anon 0xda000000'),
        _f('High', 'External Network Connection', 4488, 'msdtc.exe',
           'ESTABLISHED 10.0.0.1:60000 -> 10.0.0.2:8888 (internal lateral movement C2)'),
    ],
}


# ============================================================================
# CATEGORY 4: UNDETERMINED -- mixed signals needing more collection
# ============================================================================

UNDETERMINED_JIT_ONLY = {
    'pid': 1188,
    'process': 'chrome.exe',
    'expected': 'UNDETERMINED',
    'description': 'JIT-consistent shellcode thread with NO corroborating signals -- should be UNDETERMINED',
    'findings': [
        _f('Medium', 'Shellcode Thread (Memory)', 1188, 'chrome.exe',
           'Thread start 0x20000000 outside loaded modules. '
           'JIT-consistent (known JIT host: V8 engine). '
           'Corroboration: YARA=None, ntdll-hooks=None, remote-thread=None, MZ=None.'),
    ],
}

UNDETERMINED_SINGLE_GENERIC_YARA = {
    'pid': 2288,
    'process': 'notepad.exe',
    # Engine closes file-backed YARA as FP (with mandatory hash verification note).
    # The file-backed region means bytes are in the loaded image, not anon exec.
    # FP with hash-verify action is the correct verdict; no anonymous exec = no TP path.
    'expected': 'FALSE_POSITIVE',
    'description': 'Single generic YARA rule on file-backed region -- FP with hash-verify note',
    'findings': [
        _f('Medium', 'YARA Hit (Memory)', 2288, 'notepad.exe',
           '| LOLBin_BITS_Drop | 1 match(es) | file-backed -wx notepad.exe'),
    ],
}

UNDETERMINED_M13_MODERATE_CV = {
    'pid': 3300,
    'process': 'spoolsv.exe',
    # Moderate CV + no adj exec + no MZ = 0 positive dims -> FP closure (hash-verify required).
    'expected': 'FALSE_POSITIVE',
    'description': 'Moderate CV M13 (30%) with no AdjAnonExec/MZ -- FP closure with hash-verify note',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 3300, 'spoolsv.exe',
           'Private RW region entropy=7.10 size=65536 bytes. '
           'ByteDistrib: CV=30% [moderate] ASCII=10% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=00 10 00 00 40 00 00 00 00 00 00 00 00 00 00 00.',
           '0xee000000'),
    ],
}

UNDETERMINED_EDR_HOOK_ONLY = {
    'pid': 4400,
    'process': 'lsass.exe',
    # EDR hook to known vendor DLL = documented benign -> FP closure is correct
    'expected': 'FALSE_POSITIVE',
    'description': 'ntdll hook to CrowdStrike DLL -- EDR hook (negative), correctly FP-closed',
    'findings': [
        _f('High', 'ntdll Syscall Stub Patched (Memory)', 4400, 'lsass.exe',
           'Syscall stub SSN=0x0020 patched. Hook target falls inside CrowdStrike sensor DLL '
           '(C:\\Windows\\System32\\drivers\\CrowdStrike\\csagent.sys region). '
           'Broad hook set consistent across all non-elevated processes.'),
    ],
}


# ============================================================================
# CATEGORY 5: FALSE POSITIVE -- all signals benign, must close out
# ============================================================================

FP_TASKHOSTW_FIVE_SIGNALS = {
    'pid': 7076,
    'process': 'taskhostw.exe',
    'expected': 'NOISE_CLOSED',
    'description': 'Exact taskhostw.exe worked example from investigation guide -- all 5 M13 signals benign',
    'findings': [
        _f('High', 'Dormant Beacon Candidate (Memory)', 7076, 'taskhostw.exe',
           'Private RW region entropy=7.06 size=32768 bytes. '
           'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=7a 00 00 00 f8 7f 10 1d 3a 01 00 00 00 00 00 00.',
           '0x13a1c8c0000'),
        _f('High', 'Dormant Beacon Candidate (Memory)', 7076, 'taskhostw.exe',
           'Private RW region entropy=7.17 size=32768 bytes. '
           'ByteDistrib: CV=198% [non-uniform(data-likely)] ASCII=46% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=7a 00 00 00 db 01 00 00 00 00 00 00 00 00 00 00.',
           '0x13a1c930000'),
        _f('High', 'Dormant Beacon Candidate (Memory)', 7076, 'taskhostw.exe',
           'Private RW region entropy=7.26 size=32768 bytes. '
           'ByteDistrib: CV=190% [non-uniform(data-likely)] ASCII=42% '
           'MZ-remnant=False AdjAnonExec=False '
           'Head=7a 00 00 00 a1 02 00 00 00 00 00 00 00 00 00 00.',
           '0x13a1d190000'),
        _f('Medium', 'Thread-Pool / Ekko Pattern (Memory)', 7076, 'taskhostw.exe',
           '8 ntdll-backed running thread(s) in a process that also has a '
           'High-severity dormant beacon region. Matches Ekko/Foliage sleep-obfuscation.'),
        _f('Medium', 'YARA Hit (Memory)', 7076, 'taskhostw.exe',
           '| LOLBin_BITS_Drop | 2 match(es) | file-backed -wx taskhostw.exe'),
    ],
}

FP_LSASS_EDR_HOOK = {
    'pid': 676,
    'process': 'lsass.exe',
    'expected': 'FALSE_POSITIVE',
    'description': 'lsass.exe EDR hook (CrowdStrike) -- broad hook set, no anon exec redirect',
    'findings': [
        _f('High', 'ntdll Syscall Stub Patched (Memory)', 676, 'lsass.exe',
           'Multiple syscall stubs patched. Hook targets fall inside CrowdStrike sensor DLL. '
           'Broad hook set consistent across all non-elevated processes. '
           'EDR API monitoring pattern, not selective attacker patching.'),
    ],
}

FP_CHROME_JIT = {
    'pid': 8800,
    'process': 'chrome.exe',
    'expected': 'FALSE_POSITIVE',
    'description': 'Chrome V8 JIT with no corroboration -- benign JIT thread',
    'findings': [
        _f('Medium', 'Shellcode Thread (Memory)', 8800, 'chrome.exe',
           'Thread start 0x30000000 outside loaded modules. '
           'JIT-consistent (known JIT host: V8 engine). '
           'Adjacent evidence: absent. Single JIT thread in known V8 host. '
           'Corroboration count: 0. Verdict: unconfirmed JIT.'),
    ],
}

FP_POWERSHELL_MANAGED_HOST = {
    'pid': 7744,
    'process': 'powershell.exe',
    'expected': 'FALSE_POSITIVE',
    'description': 'PowerShell CLR host -- BSJB in anon exec is expected managed behavior',
    'findings': [
        _f('Medium', 'CLR Execute-Assembly (Memory)', 7744, 'powershell.exe',
           'BSJB (ECMA-335 .NET assembly magic) found in anonymous executable VAD. '
           'Process is powershell.exe -- a fully managed .NET host. '
           'CLR JIT compilation produces anonymous exec regions as expected behavior.'),
    ],
}

FP_SHARED_SECTION = {
    'pid': 1500,
    'process': 'dllhost.exe',
    'expected': 'FALSE_POSITIVE',
    'description': 'High-user-space address shared section -- same 0x7FFF... address across multiple PIDs',
    'findings': [
        _f('Medium', 'Injected Memory Region', 1500, 'dllhost.exe',
           'Executable private VAD (no backing file). Protection=PAGE_EXECUTE_READ.',
           '0x7fff00100000'),
        # Same address in another PID -- should make the injected_memory module classify as shared
        _f('Medium', 'Injected Memory Region', 2600, 'svchost.exe',
           'Executable private VAD (no backing file). Protection=PAGE_EXECUTE_READ.',
           '0x7fff00100000'),
    ],
}

FP_FILE_BACKED_THREAD_NO_CORROBORATION = {
    'pid': 6120,
    'process': 'msedgewebview2.exe',
    'expected': 'FALSE_POSITIVE',
    'description': (
        'Threads outside PEB module list but in file-backed image VAD -- no corroboration '
        '(DLL loaded without PEB linkage or snapshot race). Must NOT be TP without corroboration.'
    ),
    'findings': [
        # Multiple threads all in the same file-backed image VAD outside PEB.
        # Scenario: WebView2 component DLL loaded via non-standard mechanism or
        # memory scan captured before PEB InLoadOrderModuleList was updated.
        _f('High', 'Shellcode Thread (Memory)', 6120, 'msedgewebview2.exe',
           'Thread start 0x7ffe08621b20 falls outside all loaded modules but resides in a '
           'file-backed (image) VAD -- DLL is loaded but absent from the PEB '
           'InLoadOrderModuleList (possible DLL injection without PEB linkage, or snapshot race). '
           'Corroborate: check Module 3 for anonymous exec regions in same PID.',
           '0x7ffe08600000'),
        _f('High', 'Shellcode Thread (Memory)', 6120, 'msedgewebview2.exe',
           'Thread start 0x7ffe08643a10 falls outside all loaded modules but resides in a '
           'file-backed (image) VAD -- DLL is loaded but absent from the PEB '
           'InLoadOrderModuleList (possible DLL injection without PEB linkage, or snapshot race). '
           'Corroborate: check Module 3 for anonymous exec regions in same PID.',
           '0x7ffe08600000'),
        _f('High', 'Shellcode Thread (Memory)', 6120, 'msedgewebview2.exe',
           'Thread start 0x7ffe0867c2f0 falls outside all loaded modules but resides in a '
           'file-backed (image) VAD -- DLL is loaded but absent from the PEB '
           'InLoadOrderModuleList (possible DLL injection without PEB linkage, or snapshot race). '
           'Corroborate: check Module 3 for anonymous exec regions in same PID.',
           '0x7ffe08600000'),
    ],
}


# ============================================================================
# AGGREGATE SCENARIO SETS
# ============================================================================

# All scenarios as a flat list for parametrized tests
ALL_SCENARIOS = [
    NOISE_TASKHOSTW,
    NOISE_SVCHOST_COM,
    NOISE_WMIPRVSE,
    NOISE_AUDIODG,
    NOISE_LSASS_KEY,
    LOTL_SVCHOST_WRONG_PATH,
    LOTL_DLLHOST_BEACON,
    LOTL_EXPLORER_HOLLOW,
    LOTL_TASKHOSTW_WITH_SHELLCODE,
    ADVANCED_EKKO_SLEEP,
    ADVANCED_CLR_EXECUTE_ASSEMBLY,
    ADVANCED_COM_VTABLE,
    ADVANCED_PPID_SPOOF,
    ADVANCED_PEB_DECOY,
    ADVANCED_SLIVER_REFLECTIVE,
    UNDETERMINED_JIT_ONLY,
    UNDETERMINED_SINGLE_GENERIC_YARA,
    UNDETERMINED_M13_MODERATE_CV,
    UNDETERMINED_EDR_HOOK_ONLY,
    FP_TASKHOSTW_FIVE_SIGNALS,
    FP_LSASS_EDR_HOOK,
    FP_CHROME_JIT,
    FP_POWERSHELL_MANAGED_HOST,
    FP_SHARED_SECTION,
    FP_FILE_BACKED_THREAD_NO_CORROBORATION,
]

NOISE_SCENARIOS = [s for s in ALL_SCENARIOS if s['expected'] == 'NOISE_CLOSED']
TP_SCENARIOS    = [s for s in ALL_SCENARIOS if s['expected'] == 'TRUE_POSITIVE']
FP_SCENARIOS    = [s for s in ALL_SCENARIOS if s['expected'] == 'FALSE_POSITIVE']
UNDETERMINED_SCENARIOS = [s for s in ALL_SCENARIOS if s['expected'] == 'UNDETERMINED']
