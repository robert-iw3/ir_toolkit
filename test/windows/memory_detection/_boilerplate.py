#!/usr/bin/env python3
"""
Shared vmmpyc runtime for per-phase memory detection test scripts.

Unit tests import the detection function from each phase_*.py directly.
They do NOT call setup_runtime() -- no vmmpyc DLLs needed for unit tests.

Live phase scripts call:
    rt = setup_runtime(image_path, output_dir)
    n  = scan_xxx(rt)
    write_report(rt, 'phase_X_label')
"""
import sys, os, re, json, math
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared constants (detection functions receive these via rt dict or import)
# ---------------------------------------------------------------------------
KERNEL_PROCS = {
    'system', 'secure system', 'registry', 'memory compression',
    'interrupts', 'idle', 'mssmbios',
}
# Processes that legitimately hold high-entropy private RW data (AV signatures,
# crypto key material).  Phase A skips these to avoid overwhelming noise;
# all other phases still scan them normally.
HIGH_ENT_PROCS = {
    'msmpeng.exe',   # Windows Defender engine -- signature/scan data
    'lsaiso.exe',    # Credential Guard VTL1 process -- key material
    'ngciso.exe',    # Windows Hello isolation -- key material
    'nissrv.exe',    # Network Inspection Service -- pattern data
}
TOOLKIT_SCRIPTS = {
    'invoke-ircollection.ps1', 'edr_toolkit.ps1', 'edr_toolkit_deploy.ps1',
    'get-persistencesnapshot.ps1', 'get-remoteaccesstriage.ps1',
    'invoke-eventloganalysis.ps1', 'get-findingcontext.ps1',
    'analyze-memory.ps1', '00_collect-forensics.ps1',
}
# Private IP / loopback ranges for network checks
PRIVATE = re.compile(
    r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|0\.0\.0\.0$)',
    re.I,
)
USER_MAX = 0x800000000000   # x64 user-mode ceiling

# Beacon entropy / size thresholds
BEACON_MIN = 4096
BEACON_MAX = 2 * 1024 * 1024
ENTROPY_THRESHOLD = 7.0


# ---------------------------------------------------------------------------
# Shared helpers (no vmmpyc dependency -- safe to import in unit tests)
# ---------------------------------------------------------------------------
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_system_proc(p) -> bool:
    return p.name.lower() in KERNEL_PROCS or p.pid <= 8


def safe_cmdline(p) -> str:
    try:
        return p.cmdline or ''
    except Exception:
        return ''


def is_toolkit_cmd(cmd: str) -> bool:
    cl = cmd.lower()
    return any(s in cl for s in TOOLKIT_SCRIPTS)


# ---------------------------------------------------------------------------
# Runtime setup (requires vmmpyc -- do NOT import in unit tests)
# ---------------------------------------------------------------------------
def setup_runtime(image_path: str, output_dir: str) -> dict:
    """
    Wire up vmmpyc, open the image, enumerate processes.
    Returns a context dict used by all phase scan functions.
    """
    os.makedirs(output_dir, exist_ok=True)
    stamp    = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_path = os.path.join(output_dir, f'_phase_{stamp}.log')
    findings: list = []

    def log(msg, lvl='INFO'):
        ts = datetime.now().strftime('%H:%M:%S')
        s  = f'[{ts}] [{lvl}] {msg}'
        print(s)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(s + '\n')

    def add(severity, ftype, target, details, mitre):
        findings.append({
            'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'Severity':  severity,
            'Type':      ftype,
            'Target':    target,
            'Details':   details,
            'MITRE':     mitre,
        })

    # -- vmmpyc bootstrap --------------------------------------------------------
    toolkit_root = Path(__file__).parent.parent.parent.parent   # test/windows/memory_detection/../../../
    mpc_dir = str(toolkit_root / 'tools' / 'memprocfs')
    py_dir  = os.path.join(mpc_dir, 'python')
    os.add_dll_directory(mpc_dir)
    sys.path.insert(0, mpc_dir)
    import glob as _g
    for z in _g.glob(os.path.join(py_dir, 'python3*.zip')):
        if z not in sys.path:
            sys.path.insert(0, z)
    if py_dir not in sys.path:
        sys.path.append(py_dir)
    try:
        import vmmpyc
    except ImportError as e:
        log(f'Cannot import vmmpyc: {e}', 'ERROR')
        sys.exit(1)

    log(f'Opening image: {image_path}')
    try:
        vmm = vmmpyc.Vmm(['-device', image_path, '-disable-symbolserver', '-disable-python'])
    except Exception as e:
        log(f'Failed to open image: {e}', 'ERROR')
        sys.exit(1)

    log(f'Windows NT build {vmm.kernel.build}')
    procs   = vmm.process_list()
    pid_map = {p.pid: p for p in procs}
    log(f'Processes enumerated: {len(procs)}')

    return {
        'vmm':            vmm,
        'procs':          procs,
        'pid_map':        pid_map,
        'findings':       findings,
        'add':            add,
        'log':            log,
        'image_path':     image_path,
        'output_dir':     output_dir,
        'stamp':          stamp,
        'mpc_dir':        mpc_dir,
        'is_system_proc': is_system_proc,
        'safe_cmdline':   safe_cmdline,
        'is_toolkit_cmd': is_toolkit_cmd,
    }


def write_report(rt: dict, phase_label: str) -> str:
    """Write findings JSON and print summary. Returns output path."""
    findings   = rt['findings']
    output_dir = rt['output_dir']
    stamp      = rt['stamp']
    log        = rt['log']

    out_json = os.path.join(output_dir, f'{phase_label}_{stamp}.json')
    total    = len(findings)

    log('=' * 60)
    log(f'{phase_label} complete -- {total} finding(s)')
    for sev in ('Critical', 'High', 'Medium'):
        c = sum(1 for f in findings if f['Severity'] == sev)
        if c:
            log(f'  {sev}: {c}')
    log(f'Output: {out_json}')
    log('=' * 60)

    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2)

    if findings:
        print(f'\n[+] {total} finding(s) -> {Path(out_json).name}')
        for fd in sorted(findings, key=lambda x: ['Critical', 'High', 'Medium', 'Low'].index(
                x.get('Severity', 'Low') if x.get('Severity', 'Low') in
                ['Critical', 'High', 'Medium', 'Low'] else 'Low')):
            print(f'  [{fd["Severity"]:8s}] {fd["Type"]}: {fd["Target"]}')
    else:
        print(f'\n[+] No findings for {phase_label}.')

    return out_json
