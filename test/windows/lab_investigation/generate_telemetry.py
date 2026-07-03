"""Synthetic telemetry generator for the investigation ML engine lab.

Produces rich multi-source data sets that exercise the full analysis pipeline:
  - Memory findings (memory_forensic.py format)
  - EDR behavioral events (deep_sensor_ml format)
  - Windows event log entries (4688, 4624, 7045)
  - mwcp C2 config extractions

Purpose: feed the ML noise filter with enough behavioral variation that
IsolationForest can build a stable benign baseline and detect outliers.
The generator produces 3 tiers:

  BASELINE: Normal Windows background activity (500+ vectors).
            Should all close as NOISE or FALSE_POSITIVE.

  ADMIN:    Legitimate administrative operations (WMI, scheduled tasks,
            PowerShell, WinRM remoting) that look "suspicious" in isolation.
            Must NOT be promoted to TRUE_POSITIVE.

  ADVERSARY: Attack techniques blending into normal operations.
             Must be detected despite mimicking admin activity.
"""
from __future__ import annotations
import json
import random
import math
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

random.seed(42)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_secs: int = 0) -> str:
    base = datetime(2026, 7, 3, 10, 0, 0)
    return (base + timedelta(seconds=offset_secs)).strftime('%Y-%m-%d %H:%M:%S')


def _mf(severity: str, ftype: str, pid: int, proc: str, details: str,
        addr: str = '', mitre: str = 'T1055', offset: int = 0) -> dict:
    target = f'PID {pid} ({proc})' + (f' @ {addr}' if addr else '')
    return {
        'Timestamp': _ts(offset),
        'Severity': severity,
        'Type': ftype,
        'Target': target,
        'Details': details,
        'MITRE': mitre,
    }


def _edr(pid: int, proc: str, z: float = 0.5, score: float = 0.2,
         vel: float = 0.5, ent: float = 2.0, confidence: float = 0.0,
         reason: str = '', event_type: str = 'ProcessActivity') -> dict:
    return {
        'pid': pid, 'process': proc,
        'z_score': z, 'isolation_score': score,
        'velocity': vel, 'entropy': ent,
        'confidence': confidence, 'alert_reason': reason,
        'event_type': event_type,
    }


def _log(event_id: int, pid: int, cmd: str = '', parent: str = '', user: str = 'SYSTEM',
         logon_type: int = 0, svc_name: str = '', svc_path: str = '',
         new_proc_id: int = 0) -> dict:
    return {
        'EventID': event_id, 'pid': pid,
        'CommandLine': cmd, 'ParentProcessName': parent,
        'SubjectUserName': user, 'LogonType': logon_type,
        'ServiceName': svc_name, 'ServiceFileName': svc_path,
        'NewProcessId': new_proc_id,
    }


def _mwcp(pid: int, addresses: List[str] = None, mutex: str = '',
          password: str = '') -> dict:
    fname = f'C:\\Windows\\Temp\\carved_pid-{pid}_region.bin'
    return {
        'file': fname,
        'address': addresses or [],
        'mutex': [mutex] if mutex else [],
        'password': [password] if password else [],
        'filename': [],
        'decoded': [],
    }


# ---------------------------------------------------------------------------
# BASELINE: Normal Windows background noise (500+ scenarios)
# ---------------------------------------------------------------------------

def _benign_m13(cv: float = None, ascii_p: float = None,
                mz: bool = False, adj: bool = False,
                head: str = '7a 00 00 00') -> str:
    if cv is None:
        cv = random.uniform(120, 350)
    if ascii_p is None:
        ascii_p = random.uniform(25, 55)
    label = 'non-uniform(data-likely)' if cv > 40 else 'moderate'
    entropy = round(random.uniform(6.5, 7.5), 2)
    return (
        f'ByteDistrib: CV={cv:.0f}% [{label}] ASCII={ascii_p:.0f}% '
        f'MZ-remnant={mz} AdjAnonExec={adj} entropy={entropy} Head={head}'
    )


def _tp_m13(cv: float = None, ascii_p: float = None, adj: bool = True,
            head: str = 'fc 48 83 e4 f0 e8') -> str:
    if cv is None:
        cv = random.uniform(2, 14)
    if ascii_p is None:
        ascii_p = random.uniform(0, 4)
    entropy = round(random.uniform(7.5, 7.99), 2)
    return (
        f'ByteDistrib: CV={cv:.1f}% [UNIFORM(crypto-likely)] ASCII={ascii_p:.1f}% '
        f'MZ-remnant=False AdjAnonExec={adj} entropy={entropy} Head={head}'
    )


# System processes that appear repeatedly in normal operation
_SYSTEM_PROCS = [
    ('taskhostw.exe', 'C:\\Windows\\System32\\taskhostw.exe', 'svchost.exe', 7076),
    ('svchost.exe',   'C:\\Windows\\System32\\svchost.exe',   'services.exe', 1288),
    ('wmiprvse.exe',  'C:\\Windows\\System32\\wbem\\wmiprvse.exe', 'svchost.exe', 4444),
    ('audiodg.exe',   'C:\\Windows\\System32\\audiodg.exe',   'svchost.exe', 3320),
    ('lsass.exe',     'C:\\Windows\\System32\\lsass.exe',     'wininit.exe', 844),
    ('dwm.exe',       'C:\\Windows\\System32\\dwm.exe',        'winlogon.exe', 2232),
    ('searchindexer.exe', 'C:\\Windows\\System32\\SearchIndexer.exe', 'services.exe', 5616),
    ('msmpeng.exe',   'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24010.12-0\\MsMpEng.exe',
     'services.exe', 3980),
    ('explorer.exe',  'C:\\Windows\\explorer.exe',             'userinit.exe', 9212),
    ('spoolsv.exe',   'C:\\Windows\\System32\\spoolsv.exe',    'services.exe', 2180),
]

def generate_baseline() -> Dict[str, List[dict]]:
    """500+ normal Windows background findings across all system processes."""
    findings, edr_events = [], []

    for i, (proc, path, parent, pid_base) in enumerate(_SYSTEM_PROCS):
        # Each system process generates multiple M13 findings (normal background)
        for rep in range(50):
            pid = pid_base + rep * 7
            cv  = random.uniform(100, 400)
            a   = random.uniform(20, 60)
            addr = f'0x{random.randint(0x10000000, 0x7fff0000):08x}'
            findings.append(_mf(
                'High', 'Dormant Beacon Candidate (Memory)', pid, proc,
                _benign_m13(cv=cv, ascii_p=a), addr=addr, offset=i * 50 + rep
            ))
            edr_events.append(_edr(pid, proc,
                z=random.uniform(0.1, 1.5), score=random.uniform(0.05, 0.25),
                vel=random.uniform(0.1, 2.0), ent=random.uniform(1.0, 2.5),
            ))

    return {'findings': findings, 'edr_events': edr_events, 'mwcp_hits': [], 'event_logs': []}


# ---------------------------------------------------------------------------
# ADMIN: Legitimate administration (must NOT TP)
# ---------------------------------------------------------------------------

def generate_admin_activity() -> Dict[str, List[dict]]:
    """Legitimate IT admin operations that look like attacks in isolation."""
    findings, edr_events, event_logs = [], [], []

    # 1. Scheduled task deployment via wmic (admin, normal)
    findings.append(_mf('Medium', 'Dormant Beacon Candidate (Memory)', 6600, 'wmiprvse.exe',
        _benign_m13(cv=190, ascii_p=31), addr='0xaa000000', mitre='T1047', offset=100))
    edr_events.append(_edr(6600, 'wmiprvse.exe', z=1.8, score=0.3, vel=1.2, ent=2.8))
    event_logs.append(_log(4688, 6600,
        cmd='wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE',
        parent='wmiprvse.exe', user='DOMAIN\\sysadmin'))

    # 2. PowerShell admin remoting -- encoded command but from admin context
    findings.append(_mf('Medium', 'Dormant Beacon Candidate (Memory)', 7744, 'powershell.exe',
        _benign_m13(cv=145, ascii_p=38), addr='0xbb000000', mitre='T1059.001', offset=200))
    findings.append(_mf('Low', 'CLR Execute-Assembly (Memory)', 7744, 'powershell.exe',
        'BSJB signature in anonymous exec VAD of powershell.exe.', offset=201))
    edr_events.append(_edr(7744, 'powershell.exe', z=2.1, score=0.35, vel=3.0, ent=3.5))
    event_logs.append(_log(4688, 7744,
        cmd='powershell.exe -EncodedCommand JABzAGUAcwBzAGkAbwBuAA==',
        parent='wmiprvse.exe', user='DOMAIN\\sysadmin'))

    # 3. Scheduled task runner - normal work items
    findings.append(_mf('High', 'Dormant Beacon Candidate (Memory)', 7076, 'taskhostw.exe',
        _benign_m13(cv=234, ascii_p=42, head='7a 00 00 00 f8 7f'),
        addr='0x13a1c8c0000', mitre='T1053', offset=300))
    edr_events.append(_edr(7076, 'taskhostw.exe', z=0.4, score=0.1, vel=0.5, ent=1.2))

    # 4. svchost service control - RPC traffic
    findings.append(_mf('High', 'Dormant Beacon Candidate (Memory)', 1288, 'svchost.exe',
        _benign_m13(cv=175, ascii_p=33), addr='0x20000000', offset=400))
    findings.append(_mf('Low', 'External Network Connection', 1288, 'svchost.exe',
        'ESTABLISHED 127.0.0.1:49155 -> 127.0.0.1:135 (RPC)', mitre='T1071', offset=401))
    edr_events.append(_edr(1288, 'svchost.exe', z=0.8, score=0.15))

    # 5. WinRM / PS Remoting server (normal on managed endpoints)
    findings.append(_mf('Medium', 'Dormant Beacon Candidate (Memory)', 8888, 'wsmprovhost.exe',
        _benign_m13(cv=160, ascii_p=30), addr='0xcc000000', offset=500))
    event_logs.append(_log(4624, 8888, user='DOMAIN\\sysadmin', logon_type=3))
    edr_events.append(_edr(8888, 'wsmprovhost.exe', z=1.5, score=0.28))

    # 6. Windows Defender scanning - high entropy regions (packed binaries under scan)
    findings.append(_mf('High', 'Dormant Beacon Candidate (Memory)', 3980, 'msmpeng.exe',
        _benign_m13(cv=8, ascii_p=1, adj=False, head='4d 5a 90 00'),
        addr='0xdd000000', offset=600))
    edr_events.append(_edr(3980, 'msmpeng.exe', z=0.3, score=0.08))

    return {'findings': findings, 'edr_events': edr_events, 'mwcp_hits': [], 'event_logs': event_logs}


# ---------------------------------------------------------------------------
# ADVERSARY: Attack techniques blending into normal operations
# ---------------------------------------------------------------------------

def generate_adversary_blending() -> Dict[str, List[dict]]:
    """
    Adversary TTPs designed to look like normal admin activity.
    Engine must detect these despite their camouflage.

    Key principle: no named family detection. These are STRUCTURAL/BEHAVIORAL
    indicators -- the same signals an unknown adversary would produce.
    """
    findings, edr_events, event_logs, mwcp_hits = [], [], [], []

    # --- Scenario A: Hollow svchost (wrong path, UNIFORM M13) ---
    # Adversary spawns svchost.exe from non-System32 path, hollows it
    pid_a = 19800
    findings.extend([
        _mf('High', 'Dormant Beacon Candidate (Memory)', pid_a, 'svchost.exe',
            _tp_m13(cv=7, ascii_p=0.8, head='fc 48 83 e4 f0 e8 c8 00'),
            addr='0x7d000000', offset=1000),
        _mf('High', 'Shellcode Thread (Memory)', pid_a, 'svchost.exe',
            'Thread start 0x7d040000 outside all modules. Anonymous exec. '
            'Not JIT-consistent. Cross-process: CreateRemoteThread from PID 6688.',
            offset=1001),
        _mf('High', 'Injected Memory Region', pid_a, 'svchost.exe',
            'Executable private VAD at 0x7d000000. MZ header at offset 0 of region.',
            offset=1002),
        _mf('Low', 'External Network Connection', pid_a, 'svchost.exe',
            'ESTABLISHED 10.0.0.15:54322 -> 185.220.101.45:443 (external)',
            mitre='T1071', offset=1003),
    ])
    edr_events.append(_edr(pid_a, 'svchost.exe', z=5.8, score=0.78,
        confidence=91.0, reason='Hollow svchost: path outside System32'))

    # --- Scenario B: WMI persistence loader (LotL, blends with admin WMI) ---
    pid_b = 23456
    findings.extend([
        _mf('High', 'Dormant Beacon Candidate (Memory)', pid_b, 'wmiprvse.exe',
            _tp_m13(cv=9, ascii_p=1.1, adj=True, head='fc 48 83 e4 f0 e8'),
            addr='0x33000000', offset=2000),
        _mf('High', 'Shellcode Thread (Memory)', pid_b, 'wmiprvse.exe',
            'Thread start 0x33040000 anonymous exec. Not JIT-consistent.',
            offset=2001),
        _mf('High', 'ntdll Syscall Stub Patched (Memory)', pid_b, 'wmiprvse.exe',
            'NtAllocateVirtualMemory hook -> 0x33080000 (anonymous). Selective: '
            'only allocation/injection syscalls patched.',
            offset=2002),
    ])
    edr_events.append(_edr(pid_b, 'wmiprvse.exe', z=4.9, score=0.71,
        confidence=87.0, reason='LotL temporal: WMI spawned decode+exec at 02:14'))
    event_logs.extend([
        _log(7045, pid_b, svc_name='WmiHelper', svc_path='C:\\Windows\\Temp\\wmihlp.exe'),
        _log(4688, pid_b, cmd='wmic process call create "powershell -enc SGVsbG8K"',
             parent='wmiprvse.exe', user='SYSTEM'),
    ])
    mwcp_hits.append(_mwcp(pid_b, addresses=['185.220.101.45:443'], mutex='Global\\WmiSync_7d3f'))

    # --- Scenario C: taskhostw.exe with shellcode (real network beacon, unlike noise) ---
    pid_c = 7999
    findings.extend([
        _mf('High', 'Dormant Beacon Candidate (Memory)', pid_c, 'taskhostw.exe',
            _tp_m13(cv=6, ascii_p=0.5, adj=True, head='fc 48 83 e4 f0 e8 c8 00'),
            addr='0x7d010000', offset=3000),
        _mf('High', 'Shellcode Thread (Memory)', pid_c, 'taskhostw.exe',
            'Thread start 0x7d050000 anonymous exec. Not JIT-consistent.',
            offset=3001),
        _mf('High', 'Thread-Pool / Ekko Pattern (Memory)', pid_c, 'taskhostw.exe',
            '8 ntdll-backed running thread(s) in a process with High-severity beacon region.',
            offset=3002),
        _mf('Low', 'External Network Connection', pid_c, 'taskhostw.exe',
            'ESTABLISHED 10.0.0.11:61342 -> 10.10.10.200:8080 (C2 pattern: periodic 60s)',
            mitre='T1071', offset=3003),
    ])
    edr_events.append(_edr(pid_c, 'taskhostw.exe', z=6.2, score=0.85,
        confidence=93.0, reason='taskhostw beacon: periodic 60s outbound pattern'))

    # --- Scenario D: PPID spoofed process (appears as legitimate child) ---
    pid_d = 31000
    findings.extend([
        _mf('High', 'PPID Orphan (Memory)', pid_d, 'cmd.exe',
            'Claimed parent PID 4 (System) does not match process tree. '
            'Actual creator PID 9900 (mshta.exe). Possible PPID spoofing.',
            offset=4000),
        _mf('High', 'Dormant Beacon Candidate (Memory)', pid_d, 'cmd.exe',
            _tp_m13(cv=10, ascii_p=2, adj=True), addr='0x90000000', offset=4001),
        _mf('High', 'Shellcode Thread (Memory)', pid_d, 'cmd.exe',
            'Thread start 0x90040000 anonymous exec. Cross-process from 9900.',
            offset=4002),
    ])
    event_logs.append(_log(4688, pid_d, cmd='cmd.exe /c powershell -w hidden -enc SGVsbG8=',
        parent='mshta.exe', user='MAIN-SYS\\R_Web'))
    edr_events.append(_edr(pid_d, 'cmd.exe', z=5.5, score=0.80,
        confidence=90.0, reason='PPID spoof: claimed System parent, actual mshta.exe'))

    # --- Scenario E: Unknown reflective loader (no named signature, structural only) ---
    pid_e = 44444
    findings.extend([
        _mf('High', 'Injected Memory Region', pid_e, 'dllhost.exe',
            'Executable private VAD. MZ header at offset 0. Entire PE in anon RWX.',
            addr='0xab000000', offset=5000),
        _mf('High', 'Shellcode Thread (Memory)', pid_e, 'dllhost.exe',
            'Thread start 0xab020000 anon exec. Not JIT-consistent. No loaded module covers.',
            offset=5001),
        _mf('High', 'YARA Hit (Memory)', pid_e, 'dllhost.exe',
            'YARA | Generic_Reflective_Loader | fired in ANONYMOUS exec region. '
            '3 match(es). Region is private, no backing file.',
            offset=5002),
        _mf('High', 'Dormant Beacon Candidate (Memory)', pid_e, 'dllhost.exe',
            _tp_m13(cv=11, ascii_p=1.5, adj=True, head='4d 5a 90 00'),
            addr='0xab000000', offset=5003),
    ])
    edr_events.append(_edr(pid_e, 'dllhost.exe', z=5.1, score=0.73,
        confidence=88.0, reason='Unknown reflective loader: anon RWX PE + beacon pattern'))

    # --- Scenario F: CLR execute-assembly in native process ---
    pid_f = 51200
    findings.extend([
        _mf('High', 'CLR Execute-Assembly (Memory)', pid_f, 'rundll32.exe',
            'BSJB (ECMA-335 .NET assembly) in anonymous executable VAD. '
            'rundll32.exe is native -- CLR inject confirmed. Module 16.',
            offset=6000),
        _mf('High', 'Dormant Beacon Candidate (Memory)', pid_f, 'rundll32.exe',
            _tp_m13(cv=8, ascii_p=0.9, adj=True), addr='0xfe000000', offset=6001),
        _mf('High', 'Shellcode Thread (Memory)', pid_f, 'rundll32.exe',
            'Thread start 0xfe020000 anon exec. MZ at start of region.',
            offset=6002),
    ])
    edr_events.append(_edr(pid_f, 'rundll32.exe', z=4.7, score=0.69,
        confidence=86.0, reason='execute-assembly: CLR in native process'))

    # --- Scenario G: COM VTable hijack into anon exec ---
    pid_g = 60001
    findings.extend([
        _mf('High', 'COM VTable Hijacking (Memory)', pid_g, 'explorer.exe',
            'VTable pointer 0x1234ab00 redirects to anonymous exec region 0xcd000000. '
            'No file backing. YARA hit in dst region.',
            offset=7000),
        _mf('High', 'YARA Hit (Memory)', pid_g, 'explorer.exe',
            'YARA | Heap_Spray_Pattern | fired in ANONYMOUS exec region 0xcd000000. 1 match.',
            offset=7001),
        _mf('High', 'Dormant Beacon Candidate (Memory)', pid_g, 'explorer.exe',
            _tp_m13(cv=5, ascii_p=0.3, adj=True, head='fc 48 83 e4'),
            addr='0xcd000000', offset=7002),
    ])
    edr_events.append(_edr(pid_g, 'explorer.exe', z=4.3, score=0.66,
        confidence=85.0, reason='COM VTable hijack into anon exec shellcode'))

    return {
        'findings': findings,
        'edr_events': edr_events,
        'event_logs': event_logs,
        'mwcp_hits': mwcp_hits,
    }


# ---------------------------------------------------------------------------
# EDGE CASES: Near-threshold scenarios for calibration
# ---------------------------------------------------------------------------

def generate_edge_cases() -> Dict[str, List[dict]]:
    """Near-threshold scenarios: engine should emit UNDETERMINED, not TP or FP."""
    findings, edr_events, event_logs = [], [], []

    # Edge A: Moderate CV (30-40%), unclear
    pid_a = 70001
    findings.append(_mf('High', 'Dormant Beacon Candidate (Memory)', pid_a, 'spoolsv.exe',
        'ByteDistrib: CV=32% [moderate] ASCII=18% MZ-remnant=False AdjAnonExec=True '
        'entropy=7.1 Head=00 10 00 00',
        addr='0xee000000', offset=8000))
    edr_events.append(_edr(pid_a, 'spoolsv.exe', z=2.5, score=0.4))

    # Edge B: Single JIT thread (no other corroboration)
    pid_b = 70002
    findings.append(_mf('High', 'Shellcode Thread (Memory)', pid_b, 'chrome.exe',
        'Thread start 0xfe300000 outside loaded modules. JIT-consistent (V8 JIT). '
        'No Module 19 YARA, no Module 12 hook, no cross-process creation, no MZ.',
        offset=8100))
    edr_events.append(_edr(pid_b, 'chrome.exe', z=1.0, score=0.2))

    # Edge C: Single generic YARA hit (file-backed)
    pid_c = 70003
    findings.append(_mf('High', 'YARA Hit (Memory)', pid_c, 'notepad.exe',
        'YARA | Cobalt_Generic | fired in file-backed region C:\\Windows\\System32\\notepad.exe. '
        '1 match. File-backed -- may be a signature FP on unmodified binary.',
        offset=8200))
    edr_events.append(_edr(pid_c, 'notepad.exe', z=0.8, score=0.15))

    # Edge D: EDR hook only (no anon exec redirect)
    pid_d = 70004
    findings.append(_mf('High', 'ntdll Syscall Stub Patched (Memory)', pid_d, 'teams.exe',
        'NtReadVirtualMemory hook -> crowdstrike/csagent.dll. Broad hook across all procs.',
        offset=8300))
    edr_events.append(_edr(pid_d, 'teams.exe', z=0.3, score=0.1))

    return {'findings': findings, 'edr_events': edr_events, 'mwcp_hits': [], 'event_logs': event_logs}


# ---------------------------------------------------------------------------
# Combine + export
# ---------------------------------------------------------------------------

def generate_all() -> Dict[str, Dict[str, List[dict]]]:
    return {
        'baseline': generate_baseline(),
        'admin': generate_admin_activity(),
        'adversary': generate_adversary_blending(),
        'edge': generate_edge_cases(),
    }


def save_telemetry(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    data = generate_all()
    for tier_name, tier_data in data.items():
        for source, items in tier_data.items():
            if items:
                path = os.path.join(output_dir, f'{tier_name}_{source}.json')
                with open(path, 'w') as f:
                    json.dump(items, f, indent=2)
    # Combined for single-source investigation tests
    all_findings = []
    for tier in data.values():
        all_findings.extend(tier.get('findings', []))
    with open(os.path.join(output_dir, 'all_findings.json'), 'w') as f:
        json.dump(all_findings, f, indent=2)
    print(f'Telemetry written to {output_dir}: '
          f'{len(all_findings)} total findings across 4 tiers')


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'test/windows/lab_investigation/telemetry'
    save_telemetry(out)
