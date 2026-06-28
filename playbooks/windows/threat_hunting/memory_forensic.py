#!/usr/bin/env python3
"""
Advanced forensic memory analysis using MemProcFS vmmpyc Python API.
No Dokany/WinFsp required -- pure library access.
Staged offline via: Build-OfflineToolkit.ps1 -IncludeMemProcFS

Usage: python memory_forensic.py <image.aff4> <output_dir>
Output: Memory_Findings_<stamp>.json -- concerning findings only.

Detection modules:
  1.  LOLBin cmdlines          -- encoded commands, IEX, WebClient downloads
  2.  Hidden processes         -- DKOM / PEB-unlink artifacts
  3.  Injected memory          -- executable private VAD; PE hollowing (zeroed header fields)
  4.  External network         -- established/listening connections to external IPs
  5.  Shellcode threads        -- user-mode threads starting outside any loaded module
  5b. Manual-map / stomping    -- MZ in anonymous exec; image region with exec+write
  6.  Parent-child anomalies   -- high-risk child spawned from wrong parent
  7.  Process path spoofing    -- system binary running from unexpected path
  8.  Known offensive tooling  -- credential dumping, lateral movement, C2 framework names
  9.  Suspicious network bind  -- user processes listening on non-standard ports
  10. Kernel driver check      -- BYOVD-class driver names
  11. Registry Run persistence -- LOLBin commands in live Run keys
  12. ntdll stub integrity     -- patched syscall stubs (SysWhispers, HellsGate, EDR hooks)
  13. Dormant beacon / W^X     -- high-entropy private RW regions (sleep-masked beacons)
  14. Thread-pool Ekko         -- ntdll thread-pool workers correlated with beacon PIDs
  15. PEB cmdline pointer      -- dangling CommandLine.Buffer (Argue-style PEB tamper)
  16. CLR execute-assembly     -- BSJB metadata magic in non-managed process exec region
  17. PPID orphan / spoof      -- missing parent or parent created after child
  18. COM VTable hijacking     -- image-backed data pointer into anonymous exec region
  19. YARA memory scan         -- staged rule sets per-process, crash-isolated worker
"""

import sys, os, re, json, math, struct, threading
import glob as _glob
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if len(sys.argv) < 3:
    print(f"Usage: python {Path(__file__).name} <image> <output_dir>"); sys.exit(1)

IMAGE_PATH, OUTPUT_DIR = sys.argv[1], sys.argv[2]
os.makedirs(OUTPUT_DIR, exist_ok=True)
stamp    = datetime.now().strftime('%Y%m%d_%H%M%S')
out_json = os.path.join(OUTPUT_DIR, f'Memory_Findings_{stamp}.json')
log_path = os.path.join(OUTPUT_DIR, f'_MemProcFS_{stamp}.log')

def log(msg, lvl='INFO'):
    ts = datetime.now().strftime('%H:%M:%S')
    s  = f'[{ts}] [{lvl}] {msg}'; print(s)
    with open(log_path, 'a', encoding='utf-8') as f: f.write(s + '\n')

# -- vmmpyc setup ---------------------------------------------------------------
mpc_dir = str(Path(__file__).parent.parent.parent.parent / 'tools' / 'memprocfs')
py_dir  = os.path.join(mpc_dir, 'python')
os.add_dll_directory(mpc_dir)
sys.path.insert(0, mpc_dir)
for z in _glob.glob(os.path.join(py_dir, 'python3*.zip')):
    if z not in sys.path: sys.path.insert(0, z)
if py_dir not in sys.path: sys.path.append(py_dir)
try:
    import vmmpyc
except ImportError as e:
    log(f'Cannot import vmmpyc: {e}', 'ERROR'); sys.exit(1)

findings = []
def add(severity, ftype, target, details, mitre):
    findings.append({'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                     'Severity': severity, 'Type': ftype,
                     'Target': target, 'Details': details, 'MITRE': mitre})

log(f'Opening: {IMAGE_PATH}')
try:
    vmm = vmmpyc.Vmm(['-device', IMAGE_PATH, '-disable-symbolserver', '-disable-python'])
except Exception as e:
    log(f'Failed to open: {e}', 'ERROR'); sys.exit(1)

log(f'Image: Windows NT build {vmm.kernel.build}')
procs   = vmm.process_list()
pid_map = {p.pid: p for p in procs}
log(f'Processes: {len(procs)}')

# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------
KERNEL_PROCS = {
    'system', 'secure system', 'registry', 'memory compression',
    'interrupts', 'idle', 'mssmbios',
}
TOOLKIT_SCRIPTS = {
    'invoke-ircollection.ps1', 'edr_toolkit.ps1', 'edr_toolkit_deploy.ps1',
    'get-persistencesnapshot.ps1', 'get-remoteaccesstriage.ps1',
    'invoke-eventloganalysis.ps1', 'get-findingcontext.ps1',
    'analyze-memory.ps1', '00_collect-forensics.ps1',
}
# Processes that structurally hold high-entropy private RW memory.
# AV engines store compressed signature databases; isolation processes hold key material.
# These are NOT skipped -- they are scanned with a lower severity and an annotation so
# the analyst sees the signal without it drowning out genuine findings. Skipping them
# entirely creates a blind spot: AV/EDR processes are primary injection targets precisely
# because defenders assume they are clean.
HIGH_ENT_PROCS = {
    'msmpeng.exe',  # Defender engine -- signature/scan data
    'lsaiso.exe',   # Credential Guard VTL1 -- key material
    'ngciso.exe',   # Windows Hello isolation -- key material
    'nissrv.exe',   # Network Inspection Service -- pattern data
}

# Processes known to produce anonymous executable regions via JIT compilation.
# Used in both Module 3 (injected memory region) and Module 5 (shellcode thread)
# to annotate findings rather than suppress them. Comparison uses base name only
# (no .exe suffix) because the kernel EPROCESS.ImageFileName field is 14 chars max
# and long names lose their extension (e.g. acrobatnotific.exe -> acrobatnotific).
JIT_HEAVY_PROCS = {
    # Browser V8 / Blink / Chakra JIT engines
    'msedge', 'msedgewebview2', 'chrome', 'chromium',
    'brave', 'opera', 'vivaldi',
    # Adobe JIT components
    'acrobat', 'acrord32', 'acrocef', 'acrobatnotific',
    # Windows SmartScreen (Chakra-derived JIT for web content preview)
    'smartscreen',
    # .NET CLR / RyuJIT -- allocates anonymous executable pages for compiled methods
    'pwsh', 'dotnet', 'mscorsvw', 'ngen',
    # Java HotSpot JIT
    'java', 'javaw',
}
PRIVATE = re.compile(
    r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|0\.0\.0\.0$)', re.I)
USER_MAX = 0x800000000000   # x64 user-mode ceiling

BEACON_MIN        = 4096
BEACON_MAX        = 2 * 1024 * 1024
ENTROPY_THRESHOLD = 7.0


def is_system_proc(p):
    return p.name.lower() in KERNEL_PROCS or p.pid <= 8


def safe_cmdline(p):
    try:   return p.cmdline or ''
    except: return ''


def is_toolkit_cmd(cmd):
    return any(s in cmd.lower() for s in TOOLKIT_SCRIPTS)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _vad_size(v: dict) -> int:
    """Return byte size of a VAD entry. vmmpyc uses 'end' (inclusive); mocks use 'size'."""
    start = v.get('start', 0)
    end   = v.get('end', 0) or 0
    return max(0, end - start + 1) if end else (v.get('size', 0) or 0)


def _vad_prot(v: dict) -> str:
    """Uppercase protection string. Single-char 'X'/'W'/'R' checks work for both formats."""
    return str(v.get('protection', '') or '').upper()


def _vad_type(v: dict) -> str:
    """Stripped, lower-cased type string. '' or 'private' = anonymous allocation."""
    return str(v.get('type', '') or '').strip().lower()


# PE hollowing constants (section 3 and 5b)
_PE_OFF   = 0x3C
_PE_SIG   = b'PE\x00\x00'
_TS_OFF   = 8          # TimeDateStamp offset from e_lfanew
_CHK_OFF  = 24 + 64   # CheckSum (PE32+ OptionalHeader)
_SOI_OFF  = 24 + 56   # SizeOfImage (PE32+ OptionalHeader)

# ntdll stub constants (section 12)
_HOOK_OPCODES  = frozenset({0xE9, 0xEB, 0xFF, 0xCC, 0xE8})
_CLEAN_PREFIX  = bytes([0x4C, 0x8B, 0xD1])   # mov r10,rcx
_SYSCALL_BYTES = bytes([0x0F, 0x05])          # syscall opcode
_MOV_EAX      = 0xB8                          # mov eax,imm32

# CLR execute-assembly constants (section 16)
_BSJB_MAGIC = b'BSJB'   # ECMA-335 CLI metadata root signature
_CLR_DLLS   = frozenset({'clr.dll', 'coreclr.dll', 'clrjit.dll', 'mscoree.dll', 'mscorlib.dll'})
# Genuine managed-code hosts: finding BSJB anywhere in their address space is expected.
# T1218 execution-proxy LOLBins (msbuild, regasm, regsvcs, installutil) are intentionally
# excluded so that BSJB in their private executable memory is detected (execute-assembly).
# pwsh is also excluded: CoreCLR does not put BSJB in private exec regions; an injected
# execute-assembly payload would.
_MANAGED_HOSTS = re.compile(
    r'(?i)^(powershell|dotnet|devenv|code|rider|idea64|'
    r'pycharm64|datagrip64|clion64|webstorm64|goland64|rubymine64|'
    r'csc|vbc|csi|dnspy|ilspy|dotpeek|appletviewer|java|mono|'
    r'mscorsvw|ngen)(.exe)?$',
)
# T1218 execution-proxy LOLBins that must never be skipped by the managed-host check.
# CLR DLLs in these processes are themselves a detection signal (execute-assembly setup);
# BSJB in their private executable memory is definitive evidence.
_T1218_LOLBINS = frozenset({'msbuild', 'regasm', 'regsvcs', 'installutil'})

# PEB offsets for x64 CommandLine.Buffer walk (section 15)
_PEB_PROC_PARAMS_OFF = 0x20   # PEB->ProcessParameters
_RTLUP_CMDLINE_OFF   = 0x70   # ProcessParameters->CommandLine (UNICODE_STRING)
_UNICODE_BUF_OFF     = 0x08   # UNICODE_STRING.Buffer (after Length+MaxLength)


def _find_patched_stubs(ntdll_bytes: bytes) -> list:
    """Locate syscall stubs where the mov-r10-rcx preamble has been replaced."""
    results  = []
    limit    = len(ntdll_bytes) - 12
    j        = 0
    max_hits = 10
    while j < limit and len(results) < max_hits:
        idx = ntdll_bytes.find(bytes([_MOV_EAX]), j, limit)
        if idx < 3:
            j = max(j + 1, idx + 1) if idx >= 0 else limit
            continue
        if idx + 6 >= len(ntdll_bytes):
            break
        ssn_hi = ntdll_bytes[idx + 3]
        if ssn_hi not in (0x00, 0x01):
            j = idx + 1; continue
        if ntdll_bytes[idx + 5: idx + 7] != _SYSCALL_BYTES:
            j = idx + 1; continue
        prefix = ntdll_bytes[idx - 3: idx]
        if prefix == _CLEAN_PREFIX:
            j = idx + 7; continue
        hook_byte = ntdll_bytes[idx - 3]
        if hook_byte not in _HOOK_OPCODES:
            j = idx + 7; continue
        ssn = int.from_bytes(ntdll_bytes[idx + 1: idx + 3], 'little')
        results.append((idx - 3, ssn, hook_byte))
        j = idx + 7
    return results


def _high_beacon_pids(prior_findings: list) -> set:
    """PIDs with at least one High-severity dormant beacon finding (shellcode-sized regions)."""
    pids = set()
    for f in prior_findings:
        if 'Dormant Beacon Candidate' not in f.get('Type', ''):
            continue
        if f.get('Severity') != 'High':
            continue
        parts = f.get('Target', '').split(' ')
        if len(parts) >= 2:
            try:
                pids.add(int(parts[1]))
            except ValueError:
                pass
    return pids


# ==============================================================================
# 1. LOLBin / suspicious command lines
# ==============================================================================
log('=== 1. LOLBin cmdline scan ===')
LOL_PATS = [
    (r'-enc\b|-encodedcommand',             2, '-EncodedCommand'),
    (r'\bIEX\b|Invoke-' + 'Expression',     2, 'IEX/Invoke-Expression'),
    (r'\bmshta\b',                          2, 'mshta'),
    (r'certutil.+(-decode|-urlcache|-f)',   2, 'certutil decode/download'),
    (r'bitsadmin.+/transfer',               2, 'bitsadmin transfer'),
    (r'Down'+'loadString|Down'+'loadFile|WebClient', 2, 'WebClient download'),
    (r'-w\s+hid|-windowstyle\s+hid',        1, '-WindowStyle Hidden'),
    (r'-nop\b|-noprofile\b',                1, '-NoProfile'),
    (r'FromBase64String',                   1, 'Base64'),
    (r'regsvr32\b',                         1, 'regsvr32'),
    (r'\brundll32\b',                       1, 'rundll32'),
]
n = 0
for p in procs:
    cmd = safe_cmdline(p)
    if not cmd or is_toolkit_cmd(cmd): continue
    score, hits = 0, []
    for pat, pts, lbl in LOL_PATS:
        if re.search(pat, cmd, re.I): score += pts; hits.append(lbl)
    if score >= 3:
        sev = 'Critical' if score >= 6 else 'High' if score >= 4 else 'Medium'
        add(sev, 'Suspicious Command Line (Memory)',
            f'PID {p.pid} ({p.name})',
            f'Score={score} [{", ".join(hits)}] CMD={cmd[:300]}',
            'T1059.001, T1027')
        n += 1
log(f'  Suspicious cmdlines: {n}')

# ==============================================================================
# 2. Hidden processes
# ==============================================================================
log('=== 2. Hidden process detection ===')
n = 0
for p in procs:
    state = str(getattr(p, 'state', '') or '')
    if 'hidden' in state.lower():
        add('High', 'Hidden Process (Memory)',
            f'PID {p.pid} ({p.name})',
            f'DKOM/PEB-unlink artifact. state={state} PPID={p.ppid}',
            'T1014, T1055')
        n += 1
log(f'  Hidden: {n}')

# ==============================================================================
# 3. Injected memory -- anonymous executable VAD + PE hollowing check
# ==============================================================================
log('=== 3. Injected memory (private exec VAD + hollowing) ===')
n_anon = 0
n_hollow = 0
for p in procs:
    if is_system_proc(p): continue
    try: vads = p.maps.vad()
    except: continue
    for v in vads:
        prot  = _vad_prot(v)
        typ_s = _vad_type(v)
        addr  = v.get('start', 0)

        if 'X' not in prot:
            continue

        # Anonymous exec (no image or file backing) -- shellcode / reflective load
        is_private = not typ_s or typ_s == 'private'
        if is_private:
            proc_stem3 = p.name.lower().split('.')[0]
            if proc_stem3 in JIT_HEAVY_PROCS:
                region_note = (
                    f'Executable private VAD (no backing file). Protection={prot}. '
                    f'JIT-consistent (known JIT/managed-code host) -- corroborate via '
                    f'YARA match or shellcode thread start in same address range.'
                )
            else:
                region_note = f'Executable private VAD (no backing file). Protection={prot}'
            add('High', 'Injected Memory Region',
                f'PID {p.pid} ({p.name}) @ {addr:#x}',
                region_note,
                'T1055, T1027')
            n_anon += 1
            if n_anon >= 30:
                log('  3: WARN: anonymous exec cap (30) reached -- remaining regions not reported', 'WARN')
                break

        # Hollowing: image-backed executable region with multiple zeroed PE header fields.
        # Classic process hollowing erases TimeDateStamp, CheckSum, SizeOfImage before
        # overwriting the region with a replacement payload.
        if typ_s == 'image':
            try:
                hdr = p.memory.read(addr, 512)
                if not hdr or len(hdr) < 256 or hdr[0:2] != b'MZ':
                    continue
                e_lfanew = struct.unpack_from('<I', hdr, _PE_OFF)[0]
                if not (0x40 <= e_lfanew <= 0x400):
                    continue
                if hdr[e_lfanew: e_lfanew + 4] != _PE_SIG:
                    continue
                ts_off  = e_lfanew + _TS_OFF
                chk_off = e_lfanew + _CHK_OFF
                soi_off = e_lfanew + _SOI_OFF
                if max(ts_off, chk_off, soi_off) + 4 > len(hdr):
                    continue
                ts  = struct.unpack_from('<I', hdr, ts_off)[0]
                chk = struct.unpack_from('<I', hdr, chk_off)[0]
                soi = struct.unpack_from('<I', hdr, soi_off)[0]
                zeroed = sum(1 for x in (ts, chk, soi) if x == 0)
                if zeroed < 2:
                    continue
                add('High', 'Process Hollowing Indicator (Memory)',
                    f'PID {p.pid} ({p.name}) @ {addr:#x}',
                    f'Image-backed executable region: {zeroed}/3 PE header fields zeroed '
                    f'(TimeDateStamp={ts:#x} CheckSum={chk:#x} SizeOfImage={soi:#x}). '
                    f'Consistent with hollowing erase pass before payload write.',
                    'T1055.012 (Process Hollowing), T1036')
                n_hollow += 1
            except Exception:
                pass

    if n_anon >= 30: break
log(f'  Anonymous exec regions: {n_anon}  Hollowing indicators: {n_hollow}')

# ==============================================================================
# 4. External network connections
# ==============================================================================
log('=== 4. External network connections ===')
n = 0
try:
    for conn in vmm.maps.net():
        dst   = str(conn.get('dst-ip', '') or '')
        dport = conn.get('dst-port', 0)
        state = str(conn.get('state', '') or '')
        pid_n = conn.get('pid', 0)
        pname = pid_map.get(pid_n, type('', (), {'name': 'unknown'})()).name
        if not dst or PRIVATE.match(dst) or dst in ('', '0.0.0.0', '::', '*', 'N/A'): continue
        if state.upper() not in ('ESTABLISHED', 'LISTEN', 'CLOSE_WAIT', 'SYN_SENT', 'CLOSE'): continue
        sev = 'High' if state.upper() == 'ESTABLISHED' else 'Medium'
        add(sev, 'Network Connection (Memory)',
            f'PID {pid_n} ({pname})',
            f'{state} -> {dst}:{dport}',
            'T1071, T1021')
        n += 1
except Exception as e: log(f'  Net error: {e}', 'WARN')
log(f'  External connections: {n}')

# ==============================================================================
# 5. Shellcode threads -- start address outside any loaded module (user-mode only)
# ==============================================================================
log('=== 5. Shellcode thread detection ===')
# NTDLL_LOW removed: the hardcoded 2 GB threshold excluded most x64 user-space addresses.
# The module-range check (in_mod) already correctly excludes threads starting inside ntdll
# or any other loaded DLL regardless of address, making the threshold redundant.
SKIP_PROCS = KERNEL_PROCS | {'memcompression', 'smss.exe', 'csrss.exe'}
# JIT_HEAVY_PROCS is defined at module level above Module 3 so both Module 3
# and Module 5 use the same set (includes .NET CLR hosts: pwsh, dotnet, etc.)
n = 0
for p in procs:
    if p.name.lower() in SKIP_PROCS or is_system_proc(p): continue
    try:
        mods    = p.module_list()
        mod_set = {(m.base, m.base + m.image_size) for m in mods}
        threads = p.maps.thread()
    except: continue
    is_jit = p.name.lower().split('.')[0] in JIT_HEAVY_PROCS
    for t in threads:
        start = t.get('va-win32start', 0)
        if not start or start <= 0x10000 or start >= USER_MAX: continue
        if t.get('exitstatus', 0) != 0: continue
        in_mod = any(lo <= start < hi for lo, hi in mod_set)
        if not in_mod:
            if is_jit:
                detail = (f'Thread start {start:#x} falls outside all loaded modules. '
                          f'JIT-consistent (known JIT host) -- corroborate via YARA match, '
                          f'AMSI/ntdll hook, or cross-process creator before confirming.')
            else:
                detail = (f'Thread start {start:#x} falls outside all loaded modules '
                          f'-- likely shellcode injection.')
            add('High', 'Shellcode Thread (Memory)',
                f'PID {p.pid} ({p.name}) TID={t.get("tid")}',
                detail,
                'T1055.003 (Thread Hijacking), T1055')
            n += 1
log(f'  Shellcode threads: {n}')

# ==============================================================================
# 5b. Manual-map PE injection and module stomping
# ==============================================================================
log('=== 5b. Manual-map PE / Module Stomping ===')
n_mmap  = 0
n_stomp = 0
for p in procs:
    if is_system_proc(p): continue
    try: vads = p.maps.vad()
    except: continue
    for v in vads:
        prot  = _vad_prot(v)
        typ_s = _vad_type(v)
        addr  = v.get('start', 0)

        # Manual-map: MZ header in an anonymous executable region
        if 'X' in prot and (not typ_s or typ_s == 'private'):
            try:
                hdr = p.memory.read(addr, 2)
                if hdr and len(hdr) >= 2 and hdr[0] == 0x4D and hdr[1] == 0x5A:
                    add('Critical', 'Manually-Mapped PE (Memory)',
                        f'PID {p.pid} ({p.name}) @ {addr:#x}',
                        f'MZ header in private executable VAD (no backing image). '
                        f'Protection={prot}',
                        'T1055.004 (APC Injection), T1055')
                    n_mmap += 1
            except Exception:
                pass

        # Module stomping: image-backed region with explicit read+write+execute protection.
        # vmmpyc reports '---wxc' for all image sections (section-attribute CoW+exec) --
        # that pattern has no 'R', so requiring 'R' avoids firing on every image VAD.
        # A truly stomped page where VirtualProtect set PAGE_EXECUTE_READWRITE shows
        # an explicit 'R' alongside 'W' and 'X' in the protection string.
        if typ_s == 'image' and 'R' in prot and 'W' in prot and 'X' in prot:
            add('High', 'Module Stomping Indicator (Memory)',
                f'PID {p.pid} ({p.name}) @ {addr:#x}',
                f'Image-backed region with execute+write protection -- consistent with '
                f'stomped module. Protection={prot}',
                'T1055.001 (DLL Injection), T1055')
            n_stomp += 1
log(f'  Manually-mapped PEs: {n_mmap}  Module-stomping indicators: {n_stomp}')

# ==============================================================================
# 6. Parent-child anomalies
# ==============================================================================
log('=== 6. Parent-child relationship anomalies ===')
EXPECTED_PARENTS = {
    'services.exe':   {'svchost.exe', 'dllhost.exe', 'taskhost.exe', 'taskhostw.exe',
                       'msiexec.exe', 'msdtc.exe'},
    'svchost.exe':    {'werfault.exe', 'dllhost.exe', 'backgroundtransferhst.exe',
                       'backgroundtaskhost.exe', 'conhost.exe', 'runtimebroker.exe',
                       'securityhealthservice.exe', 'wuauclt.exe', 'tiworker.exe'},
    'wininit.exe':    {'services.exe', 'lsass.exe', 'lsaiso.exe'},
    'winlogon.exe':   {'userinit.exe', 'fontdrvhost.exe', 'dwm.exe', 'logonui.exe'},
    'explorer.exe':   {'*'},
    'userinit.exe':   {'explorer.exe'},
    'smss.exe':       {'csrss.exe', 'wininit.exe', 'winlogon.exe', 'smss.exe'},
    'lsass.exe':      {'werfault.exe'},
    'taskeng.exe':    {'*'},
    'taskhostw.exe':  {'*'},
    'mmc.exe':        {'*'},
    'msiexec.exe':    {'*'},
}
HIGH_RISK_CHILDREN = {
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
    'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe',
}
n = 0
for p in procs:
    if is_system_proc(p): continue
    child = p.name.lower()
    if child not in HIGH_RISK_CHILDREN: continue
    parent = pid_map.get(p.ppid)
    if not parent: continue
    pname   = parent.name.lower()
    allowed = EXPECTED_PARENTS.get(pname, set())
    if '*' in allowed: continue
    if child not in allowed and pname not in ('explorer.exe', 'taskhostw.exe',
                                               'taskeng.exe', 'mmc.exe'):
        cmd = safe_cmdline(p)
        if is_toolkit_cmd(cmd): continue
        add('High', 'Suspicious Parent-Child Relationship (Memory)',
            f'PID {p.pid} ({p.name}) <- PPID {p.ppid} ({parent.name})',
            f'Unusual parent "{parent.name}" spawned high-risk "{p.name}". CMD={cmd[:200]}',
            'T1059, T1204 (User Execution)')
        n += 1
log(f'  Anomalous parent-child: {n}')

# ==============================================================================
# 7. Process path spoofing
# ==============================================================================
log('=== 7. Process path spoofing ===')
SYSTEM32_PROCS = {
    'lsass.exe', 'svchost.exe', 'services.exe', 'csrss.exe', 'smss.exe',
    'wininit.exe', 'winlogon.exe', 'lsaiso.exe', 'spoolsv.exe', 'taskhostw.exe',
    'taskhost.exe', 'dwm.exe', 'conhost.exe', 'dllhost.exe', 'userinit.exe',
}
SYS_PATHS = re.compile(r'(?i)^[a-z]:\\windows\\(system32|syswow64)\\')
n = 0
for p in procs:
    if p.name.lower() not in SYSTEM32_PROCS: continue
    try:    pu = str(p.pathuser   or '')
    except: pu = ''
    try:    pk = str(p.pathkernel or '')
    except: pk = ''
    raw  = pu if pu else pk
    full = re.sub(r'\\Device\\HarddiskVolume\d+', 'C:', raw)
    full = re.sub(r'^\\\?\?\\', '', full)
    full = full.replace('\\SystemRoot\\', 'C:\\Windows\\')
    if not full: continue
    if not SYS_PATHS.match(full):
        add('Critical', 'Process Path Spoofing (Memory)',
            f'PID {p.pid} ({p.name})',
            f'System process running from unexpected path: {full}',
            'T1036.005 (Masquerading: Match Legitimate Name)')
        n += 1
log(f'  Path-spoofed system procs: {n}')

# ==============================================================================
# 8. Known offensive tooling
# ==============================================================================
log('=== 8. Known offensive tooling ===')
TOOL_PATTERNS = [
    (r'(?i)mimi' + r'katz|sekur' + r'lsa|wce\.exe|fgdump|cachedump|wdigest', 'Credential dumping tool'),
    (r'(?i)psexec|wmiexec|smbexec|atexec|dcomexec', 'Lateral movement tool'),
    (r'(?i)cobalt.?strike|cobaltstrike|beacon\.', 'Cobalt Strike'),
    (r'(?i)meterpreter|metasploit', 'Metasploit'),
    (r'(?i)empire\.ps1|invoke-empire', 'PowerShell Empire'),
    (r'(?i)covenant|brute.?ratel', 'C2 framework'),
    (r'(?i)nmap|masscan|fscan|netcat\b|nc\.exe', 'Network scanner/listener'),
    (r'(?i)bloodhound|sharphound|powerview|powermad|rubeus|kerber' + r'oast', 'AD attack tool'),
    (r'(?i)mavinject|installutil.*\.exe|appsync' + r'publisher', 'LOLBAS abuse'),
]
n = 0
for p in procs:
    cmd  = safe_cmdline(p)
    text = (p.name + ' ' + cmd).lower()
    for pattern, label in TOOL_PATTERNS:
        if re.search(pattern, text):
            add('Critical', 'Known Offensive Tool (Memory)',
                f'PID {p.pid} ({p.name})',
                f'Matches {label} signature. CMD={cmd[:200]}',
                'T1588 (Obtain Capabilities), T1059')
            n += 1
            break
log(f'  Known offensive tools: {n}')

# ==============================================================================
# 9. Suspicious network listeners
# ==============================================================================
log('=== 9. Suspicious network listeners ===')
LISTENER_ALLOWLIST = {
    'svchost.exe', 'system', 'lsass.exe', 'wininit.exe',
    'microsoftedge', 'msedge.exe', 'chrome.exe', 'firefox.exe',
    'onedrive.exe', 'teams.exe', 'slack.exe', 'zoom.exe',
    'msseces.exe', 'searchindexer', 'spoolsv.exe',
    'vmware', 'virtualbox', 'hyper-v',
}
n = 0
try:
    for conn in vmm.maps.net():
        state = str(conn.get('state', '') or '')
        if state.upper() != 'LISTEN': continue
        src_port = conn.get('src-port', 0) or 0
        if src_port < 1024: continue
        src_ip = str(conn.get('src-ip', '') or '')
        if src_ip.startswith('127.'): continue
        pid_n  = conn.get('pid', 0)
        pname  = (pid_map.get(pid_n, type('', (), {'name': 'unknown'})()).name or '').lower()
        if any(a in pname for a in LISTENER_ALLOWLIST): continue
        add('Medium', 'Suspicious Network Listener (Memory)',
            f'PID {pid_n} ({pname})',
            f'User process listening on {src_ip}:{src_port} -- potential bind shell.',
            'T1071 (Application Layer Protocol), T1571 (Non-Standard Port)')
        n += 1
except Exception as e: log(f'  Listener check error: {e}', 'WARN')
log(f'  Suspicious listeners: {n}')

# ==============================================================================
# 10. Kernel driver check -- BYOVD-class names
# ==============================================================================
log('=== 10. Kernel driver scan ===')
VULN_DRV = re.compile(
    r'(?i)(RTCore64|WinRing0|GDRV|ASMIO|cpuz\d|nvoclock|kprocesshacker|'
    r'physmem|gmer|dbutil|AsUpio|HwRwDrv|HwOs2Ec|iqvw64e|cpuz141)', re.I)
n = 0
try:
    for d in vmm.maps.kdriver():
        name = str(d.get('name', '') or d.get('module', '') or '')
        base = d.get('base', d.get('va', 0))
        if VULN_DRV.search(name):
            add('Critical', 'Vulnerable Kernel Driver (Memory)', name,
                f'BYOVD-class driver at {base:#x}',
                'T1068, T1543.003')
            n += 1
except Exception as e: log(f'  Driver scan error: {e}', 'WARN')
log(f'  Suspicious drivers: {n}')

# ==============================================================================
# 11. Registry Run key persistence
# ==============================================================================
log('=== 11. Registry Run persistence ===')
RUN_KEYS = [
    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
]
LOL_BIN_RE = re.compile(
    r'(?i)(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin)')
n = 0
for rk in RUN_KEYS:
    try:
        key = vmm.reg_key(rk)
        if not key: continue
        for val in key.values():
            data = str(val.get('data', '') or '')
            if LOL_BIN_RE.search(data):
                add('High', 'Suspicious Run Key (Memory)', f'{rk}\\{val.get("name", "")}',
                    f'LOLBin in Run key: {data[:200]}',
                    'T1547.001 (Registry Run Keys)')
                n += 1
    except: pass
log(f'  Suspicious Run keys: {n}')

# ==============================================================================
# 12. ntdll syscall stub integrity
# Patched stubs indicate EDR user-mode hook overwrites or indirect-syscall frameworks.
# Clean stub: 4C 8B D1 B8 <SSN> 0F 05 C3  (mov r10,rcx; mov eax,ssn; syscall; ret)
# Patched:    E9/EB/FF/CC/E8 replaces the 4C 8B D1 preamble with a redirect.
# ==============================================================================
log('=== 12. ntdll stub integrity ===')
n = 0
for p in procs:
    if is_system_proc(p): continue
    try:
        mods = p.module_list()
    except Exception:
        continue
    ntdll = next((m for m in mods if m.name.lower() == 'ntdll.dll'), None)
    if not ntdll:
        continue
    try:
        ntdll_bytes = p.memory.read(ntdll.base, min(0x40000, ntdll.image_size))
        if not ntdll_bytes:
            continue
    except Exception:
        continue
    for offset, ssn, hook_byte in _find_patched_stubs(ntdll_bytes):
        add('Critical', 'ntdll Syscall Stub Patched (Memory)',
            f'PID {p.pid} ({p.name}) ntdll+{offset:#x}',
            f'Syscall stub SSN={ssn:#x} has hook opcode {hook_byte:#04x} instead of '
            f'expected mov r10,rcx (4C 8B D1). EDR user-mode hook or '
            f'indirect-syscall bypass (SysWhispers / HellsGate / TartarusGate).',
            'T1106 (Native API), T1562 (Impair Defenses), T1055')
        n += 1
log(f'  Patched ntdll stubs: {n}')

# ==============================================================================
# 13. Dormant beacon / W^X region scan
# A sleep-masked beacon (Ekko, Gargoyle, Foliage) holds its payload in a private
# RW region with no execute flag at snapshot time. High entropy confirms obfuscation.
# Byte-distribution CV and adjacent anonymous exec presence distinguish encrypted
# shellcode from legitimate high-entropy data buffers.
# ==============================================================================
log('=== 13. Dormant beacon / W^X entropy scan ===')
n_beacon = 0
beacon_findings_ref = []   # shared with section 14 (Ekko correlation)
_ADJ_WINDOW = 65536        # proximity window for adjacent anon-exec check

for p in procs:
    if is_system_proc(p):
        continue
    is_high_ent = p.name.lower() in HIGH_ENT_PROCS
    try:
        vads = p.maps.vad()
    except Exception:
        continue

    # Pass 1: collect anonymous executable ranges for adjacency check.
    anon_exec_ranges = []
    for v in vads:
        prot_v = _vad_prot(v)
        typ_v  = _vad_type(v)
        if 'X' not in prot_v:
            continue
        if typ_v and typ_v != 'private':
            continue
        s_v = v.get('start', 0)
        z_v = _vad_size(v)
        if z_v > 0:
            anon_exec_ranges.append((s_v, s_v + z_v))

    # Pass 2: beacon scan.
    for v in vads:
        prot  = _vad_prot(v)
        addr  = v.get('start', 0)
        size  = _vad_size(v)
        typ_s = _vad_type(v)

        if 'X' in prot:
            continue
        if typ_s and typ_s != 'private':
            continue
        if 'W' not in prot:
            continue
        if not (BEACON_MIN <= size <= BEACON_MAX):
            continue

        try:
            sample = p.memory.read(addr, min(size, 8192))
            if not sample or len(sample) < 512:
                continue
            ent = _entropy(sample)
        except Exception:
            continue

        if ent < ENTROPY_THRESHOLD:
            continue

        # Byte-distribution corroboration.
        # CV of per-byte frequencies across 256 buckets:
        #   CV < 15%  -- very uniform -- XOR/AES encrypted shellcode-likely
        #   CV 15-40% -- moderately uniform -- compressed data
        #   CV > 40%  -- non-uniform -- structured data or strings (benign hint)
        freq = [0] * 256
        for b in sample:
            freq[b] += 1
        expected = len(sample) / 256.0
        cv_pct = (sum((f - expected) ** 2 for f in freq) / 256.0) ** 0.5 / expected * 100
        ascii_pct = sum(1 for b in sample if 0x20 <= b <= 0x7e) / len(sample) * 100
        has_mz    = b'\x4d\x5a' in sample[:512]
        head_hex  = sample[:16].hex(' ')

        if cv_pct < 15:
            distrib_label = 'UNIFORM(crypto-likely)'
        elif cv_pct < 40:
            distrib_label = 'moderate'
        else:
            distrib_label = 'non-uniform(data-likely)'

        region_end = addr + size
        adj_exec = any(
            lo < region_end + _ADJ_WINDOW and hi > addr - _ADJ_WINDOW
            for lo, hi in anon_exec_ranges
        )

        sev = 'High' if size <= 262144 else 'Medium'
        f_dict = {
            'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'Severity':  sev,
            'Type':      'Dormant Beacon Candidate (Memory)',
            'Target':    f'PID {p.pid} ({p.name}) @ {addr:#x}',
            'Details': (
                f'Private RW region entropy={ent:.2f} size={size} bytes. '
                f'No execute flag at snapshot time -- consistent with sleep-mask '
                f'or Gargoyle W^X beacon resting between execution windows. '
                f'Prot={prot}. '
                f'ByteDistrib: CV={cv_pct:.0f}% [{distrib_label}] '
                f'ASCII={ascii_pct:.0f}% '
                f'MZ-remnant={has_mz} '
                f'AdjAnonExec={adj_exec} '
                f'Head={head_hex}. '
                f'Corroborate: APC/timer targeting this address.'
            ),
            'MITRE': 'T1027 (Obfuscated Files), T1055 (Process Injection), T1027.013',
        }
        if is_high_ent:
            f_dict['Severity'] = 'Low'
            f_dict['Details'] += (
                ' SECURITY-PROC: security process (AV/EDR/VTL1 component) has expected '
                'high-entropy content from signature/key material; these processes are '
                'also prime injection targets -- corroborate with cross-process writes, '
                'thread injection evidence, or YARA match before dismissing.'
            )
        findings.append(f_dict)
        beacon_findings_ref.append(f_dict)
        n_beacon += 1
        if n_beacon >= 50:
            break
    if n_beacon >= 50:
        break

log(f'  Dormant beacon candidates: {n_beacon}')

# ==============================================================================
# 14. Thread-pool / Ekko sleep-mask correlation
# Ekko-style sleep obfuscation uses CreateTimerQueueTimer (ntdll thread-pool) to
# schedule callbacks that decrypt and re-execute the beacon. A process with ntdll-
# backed pool workers AND a High-severity beacon region (shellcode-sized, <256 KB)
# matches this pattern.  Medium-severity beacon regions (>256 KB) are excluded --
# large encrypted data stores legitimately appear in many applications.
# ==============================================================================
log('=== 14. Thread-pool / Ekko correlation ===')
n_ekko = 0
high_pids = _high_beacon_pids(beacon_findings_ref)

if not high_pids:
    log('  No High-severity beacon PIDs -- Ekko check skipped')
else:
    for p in procs:
        if is_system_proc(p) or p.pid not in high_pids:
            continue
        try:
            mods    = p.module_list()
            threads = p.maps.thread()
        except Exception:
            continue
        ntdll = next((m for m in mods if m.name.lower() == 'ntdll.dll'), None)
        if not ntdll:
            continue
        ntdll_lo = ntdll.base
        ntdll_hi = ntdll.base + ntdll.image_size
        pool_threads = [
            t for t in threads
            if ntdll_lo <= t.get('va-win32start', 0) < ntdll_hi
            and t.get('exitstatus', 1) == 0
        ]
        if len(pool_threads) < 2:
            continue
        add('High', 'Thread-Pool Injection / Ekko Pattern (Memory)',
            f'PID {p.pid} ({p.name})',
            f'{len(pool_threads)} ntdll-backed running thread(s) in a process that '
            f'also has a High-severity dormant beacon region. Matches Ekko/Foliage '
            f'sleep-obfuscation: payload encrypted at rest, thread-pool workers hold '
            f'pending timer callback to decrypt and resume execution.',
            'T1055.004 (APC), T1055 (Process Injection), T1106')
        n_ekko += 1

log(f'  Thread-pool Ekko candidates: {n_ekko}')

# ==============================================================================
# 15. PEB CommandLine.Buffer pointer integrity
# Cobalt Strike "Argue" spoofs the cmdline by tampering with
# PEB.ProcessParameters->CommandLine.Buffer. A buffer pointer that falls outside
# all mapped VAD regions indicates post-launch PEB modification.
# ==============================================================================
log('=== 15. PEB cmdline pointer integrity ===')
n_peb    = 0
peb_avail = False
for p in procs:
    if is_system_proc(p):
        continue
    peb_addr = None
    try:
        peb_addr = getattr(p, 'peb', None) or getattr(p, 'peb_address', None)
    except Exception:
        pass
    if peb_addr is None:
        if not peb_avail:
            break
        continue
    peb_avail = True
    try:
        pp_bytes = p.memory.read(peb_addr + _PEB_PROC_PARAMS_OFF, 8)
        if not pp_bytes or len(pp_bytes) < 8:
            continue
        pp_ptr = int.from_bytes(pp_bytes, 'little')
        if pp_ptr < 0x10000:
            continue
        cl_bytes = p.memory.read(pp_ptr + _RTLUP_CMDLINE_OFF + _UNICODE_BUF_OFF, 8)
        if not cl_bytes or len(cl_bytes) < 8:
            continue
        cl_buf = int.from_bytes(cl_bytes, 'little')
        if cl_buf < 0x10000:
            continue
        vads   = p.maps.vad()
        in_vad = False
        for v in vads:
            s = v.get('start', 0)
            e = v.get('end', 0) or 0
            z = v.get('size', 0) or 0
            if e:
                if s <= cl_buf <= e:
                    in_vad = True; break
            elif z:
                if s <= cl_buf < s + z:
                    in_vad = True; break
        if in_vad:
            continue
        add('High', 'PEB CommandLine Buffer Pointer Anomaly (Memory)',
            f'PID {p.pid} ({p.name})',
            f'PEB.RtlUserProcessParameters->CommandLine.Buffer={cl_buf:#x} does not '
            f'resolve to any mapped VAD region. PEB tampered or cmdline buffer '
            f'freed/remapped post-launch.',
            'T1055.012 (Process Doppelganging), T1036 (Masquerading)')
        n_peb += 1
    except Exception:
        continue
if not peb_avail:
    log('  PEB address not exposed by this vmmpyc build -- cmdline pointer check skipped', 'WARN')
log(f'  PEB cmdline pointer anomalies: {n_peb}')

# ==============================================================================
# 16. CLR execute-assembly (BSJB metadata magic)
# Donut / execute-assembly load a .NET assembly into a native process at runtime.
# The ECMA-335 CLI metadata root signature "BSJB" (0x424A5342) is mandatory in
# every valid .NET assembly -- it cannot appear in a legitimate non-.NET process.
# Finding it in a private executable region of a non-managed host is definitive.
# ==============================================================================
log('=== 16. CLR execute-assembly (BSJB) ===')
n_clr = 0
_CLR_SCAN_LIMIT = 64   # max pages per process
_CLR_PAGE       = 0x1000
for p in procs:
    if is_system_proc(p) or _MANAGED_HOSTS.match(p.name):
        continue
    proc_stem16 = p.name.lower().split('.')[0]
    is_lolbin   = proc_stem16 in _T1218_LOLBINS
    try:
        mods      = p.module_list()
        mod_names = {m.name.lower() for m in mods}
    except Exception:
        mod_names = set()
    clr_found = _CLR_DLLS & mod_names
    # Skip the fully-managed-host check for T1218 LOLBins: CLR DLLs in msbuild/
    # regasm/regsvcs/installutil are the execute-assembly setup signal, not a reason
    # to suppress. For all other non-LOLBin processes, a full classic CLR load is
    # expected and not worth scanning.
    if not is_lolbin and 'mscoree.dll' in mod_names and 'clr.dll' in mod_names:
        continue
    if is_lolbin and clr_found:
        cmd16 = safe_cmdline(p)
        add('High', 'CLR Assembly in T1218 LOLBin (Memory)',
            f'PID {p.pid} ({p.name})',
            f'CLR module(s) {sorted(clr_found)} loaded in T1218 execution-proxy LOLBin. '
            f'execute-assembly / Donut indicator -- native process should not host a CLR. '
            f'CMD={cmd16[:200]}',
            'T1218 (Signed Binary Proxy Execution), T1620 (Reflective Code Loading)')
        n_clr += 1
    bsjb_addr  = 0
    bsjb_found = False
    pages_scanned = 0
    try:
        vads = p.maps.vad()
        for vad in vads:
            prot_v = _vad_prot(vad)
            typ_v  = _vad_type(vad)
            if 'X' not in prot_v:
                continue
            if typ_v == 'image' or 'file' in typ_v:
                continue
            base = int(vad.get('start', 0))
            size = _vad_size(vad)
            if size == 0 or pages_scanned >= _CLR_SCAN_LIMIT:
                break
            scan_size = min(size, _CLR_SCAN_LIMIT * _CLR_PAGE)
            try:
                data = p.memory.read(base, scan_size) or b''
            except Exception:
                data = b''
            if data and _BSJB_MAGIC in data:
                bsjb_found = True
                bsjb_addr  = base
                break
            pages_scanned += max(1, scan_size // _CLR_PAGE)
    except Exception:
        pass
    if not clr_found and not bsjb_found:
        continue
    if bsjb_found:
        cmd = safe_cmdline(p)
        add('High', 'CLR Assembly in Non-Managed Process (Memory)',
            f'PID {p.pid} ({p.name})',
            f'CLR CLI metadata (BSJB magic) found in private EXECUTE region at '
            f'{bsjb_addr:#x}. ECMA-335 metadata root signature cannot appear in a '
            f'legitimate non-.NET process. '
            f'CLR DLLs present: {sorted(clr_found) or "none (CLR unloaded post-exec)"}. '
            f'CMD={cmd[:200]}',
            'T1620 (Reflective Code Loading), T1055 (Process Injection)')
        n_clr += 1
    else:
        log(f'  16: PID {p.pid} ({p.name}) has CLR DLLs {sorted(clr_found)} '
            f'but no BSJB found -- context only, not firing')
log(f'  CLR execute-assembly candidates: {n_clr}')

# ==============================================================================
# 17. PPID orphan / parent-timestamp spoof
# Signal 1: claimed parent PID not in live process list (parent exited or PPID spoofed).
# Signal 2: parent created after child -- temporally impossible (forged with
#            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).
# smss.exe exits after spawning winlogon/wininit -- winlogon appears orphaned
# on live images; this is expected. PID 0/4 parents are also expected.
# ==============================================================================
log('=== 17. PPID orphan / spoof ===')
PPID_SKIP = {
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'secure system',
    'registry', 'memory compression', 'interrupts', 'idle',
}
n_ppid    = 0
time_avail = False
for p in procs:
    if is_system_proc(p) or p.name.lower() in PPID_SKIP:
        continue
    parent = pid_map.get(p.ppid)
    if not parent:
        if p.ppid not in (0, 4):
            add('Medium', 'Orphaned Parent / Potential PPID Spoof (Memory)',
                f'PID {p.pid} ({p.name}) <- PPID {p.ppid}',
                f'Claimed parent PID {p.ppid} is not present in the process list. '
                f'Parent exited (may be benign) or PPID spoofed to a recycled PID. '
                f'Corroborate via process-creation event log.',
                'T1134.004 (Parent PID Spoofing)')
            n_ppid += 1
        continue
    # Temporal: parent created after child
    p_ct   = None
    par_ct = None
    for attr in ('create_time', 'time_create', 'ftCreateTime'):
        try:
            v = getattr(p, attr, None)
            if v is not None:
                p_ct = v; break
        except Exception:
            pass
    for attr in ('create_time', 'time_create', 'ftCreateTime'):
        try:
            v = getattr(parent, attr, None)
            if v is not None:
                par_ct = v; break
        except Exception:
            pass
    if p_ct is None or par_ct is None:
        continue
    time_avail = True
    if par_ct > p_ct:
        add('High', 'PPID Spoofing -- Parent Created After Child (Memory)',
            f'PID {p.pid} ({p.name}) <- PPID {p.ppid} ({parent.name})',
            f'Claimed parent {parent.name} (PID {p.ppid}) was created AFTER this '
            f'process -- temporally impossible. PPID forged via '
            f'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.',
            'T1134.004 (Parent PID Spoofing), T1134')
        n_ppid += 1
if not time_avail:
    log('  create_time not available in this vmmpyc build -- temporal PPID check skipped', 'WARN')
log(f'  PPID orphan/spoof candidates: {n_ppid}')

# ==============================================================================
# 18. COM VTable pointer into anonymous executable region
# An attacker crafts a fake VTable in shellcode memory, then overwrites a COM
# interface pointer in an image-backed data section so that standard COM method
# calls redirect to shellcode. No on-disk changes are required.
# ==============================================================================
log('=== 18. COM VTable hijacking ===')
_PTR_SIZE = 8
_MAX_VTBL  = 3   # max suspicious pointers per process before emitting
n_vtbl = 0
for p in procs:
    if is_system_proc(p):
        continue
    try:
        vads = p.maps.vad()
    except Exception:
        continue
    anon_exec = []
    rw_image  = []
    for v in vads:
        prot  = _vad_prot(v)
        addr  = v.get('start', 0)
        size  = _vad_size(v)
        typ_s = _vad_type(v)
        is_private = not typ_s or typ_s == 'private'
        if 'X' in prot and is_private:
            anon_exec.append((addr, addr + size))
        elif typ_s == 'image' and 'W' in prot:
            rw_image.append((addr, size))
    if not anon_exec or not rw_image:
        continue
    hits = []
    for (sec_addr, sec_size) in rw_image:
        if sec_size < _PTR_SIZE or sec_size > 0x100000:
            continue
        try:
            data = p.memory.read(sec_addr, min(sec_size, 4096))
            if not data or len(data) < _PTR_SIZE:
                continue
        except Exception:
            continue
        for off in range(0, len(data) - _PTR_SIZE, _PTR_SIZE):
            val = int.from_bytes(data[off: off + _PTR_SIZE], 'little')
            if val < 0x10000:
                continue
            for lo, hi in anon_exec:
                if lo <= val < hi:
                    hits.append((sec_addr + off, val))
                    break
            if len(hits) >= _MAX_VTBL:
                break
        if hits:
            break
    if not hits:
        continue
    sample = ', '.join(f'{src:#x}->{dst:#x}' for src, dst in hits)
    add('Medium', 'COM VTable Pointer to Anon-Exec Region (Memory)',
        f'PID {p.pid} ({p.name})',
        f'Image-backed data section contains {len(hits)} pointer(s) into anonymous '
        f'executable region(s). Consistent with in-memory COM VTable hijacking. '
        f'Corroborate: YARA the target exec region. Pointers: {sample}',
        'T1574 (Hijack Execution Flow), T1055 (Process Injection)')
    n_vtbl += 1
log(f'  COM VTable hijacking candidates: {n_vtbl}')

# ==============================================================================
# 19. YARA memory scan -- staged rule sets per-process, crash-isolated worker
# ==============================================================================
log('=== 19. YARA memory scan ===')

_carve_dir = os.environ.get('IR_CARVE_DIR')
if _carve_dir:
    log(f'  Carve ON: true-positive regions -> {_carve_dir}'
        + ('  (IR_CARVE_ANY=1: carving ALL hit regions)' if os.environ.get('IR_CARVE_ANY') == '1' else ''))

try:
    import memory_yara as myara
except Exception as e:
    myara = None
    log(f'  SKIP: memory_yara import failed ({e}) - YARA scan skipped', 'WARN')

YARA_RULES_DIR = Path(mpc_dir).parent / 'yara_rules'
YARAC_EXE      = Path(mpc_dir).parent / 'yarac64.exe'
YARA_TIMEOUT   = 15
YARA_MAX_HITS  = 200
YARA_MAX_CRASH = 25
YARA_WORKER    = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'memory_yara_worker.py')

yara_count = 0
if myara is None:
    pass
elif not YARA_RULES_DIR.is_dir():
    log(f'  SKIP: {YARA_RULES_DIR} not found -- run Build-OfflineToolkit.ps1 -IncludeYaraRules', 'WARN')
elif not YARAC_EXE.is_file():
    log(f'  SKIP: yarac64.exe not staged at {YARAC_EXE}', 'WARN')
elif not os.path.isfile(YARA_WORKER):
    log(f'  SKIP: worker not found at {YARA_WORKER}', 'WARN')
else:
    import subprocess as _sp
    all_rules = myara.collect_rule_files(str(YARA_RULES_DIR))
    win_rules = myara.filter_windows_rules(all_rules)
    win_rules = myara.exclude_memory_noise(win_rules)
    log(f'  Rules: {len(win_rules)} Windows-applicable (of {len(all_rules)} staged)')

    canary_src = os.path.join(OUTPUT_DIR, f'_yara_canary_{stamp}.yar')
    with open(canary_src, 'w', encoding='utf-8') as cf:
        cf.write(myara.canary_rule_source())
    real_yac = os.path.join(OUTPUT_DIR, f'_yara_win_{stamp}.yac')
    yac, n_ok, n_fail = myara.compile_ruleset(win_rules + [canary_src], str(YARAC_EXE), real_yac)
    if not yac:
        log('  SKIP: ruleset failed to compile', 'WARN')
    else:
        log(f'  Compiled {n_ok} rule file(s)' + (f' ({n_fail} excluded)' if n_fail else ''),
            'WARN' if n_fail else 'INFO')
        results_path = os.path.join(OUTPUT_DIR, f'_yara_results_{stamp}.jsonl')
        open(results_path, 'w').close()
        skip    = set()
        crashes = 0
        for _attempt in range(YARA_MAX_CRASH + 1):
            rc = _sp.call([sys.executable, YARA_WORKER, IMAGE_PATH, yac, results_path,
                           ','.join(str(s) for s in sorted(skip)), mpc_dir, str(YARA_TIMEOUT)])
            try:
                with open(results_path, encoding='utf-8') as rf:
                    summary = myara.parse_worker_jsonl(rf.read().splitlines())
            except OSError:
                summary = {'done': False, 'started_pids': set(), 'finished_pids': set(),
                           'finished': [], 'canary_hits': 0}
            if summary['done']:
                break
            bad = myara.crashing_pid(summary['started_pids'], summary['finished_pids'] | skip)
            if bad is None:
                break
            skip.add(bad); skip |= summary['finished_pids']
            crashes += 1
            log(f'  YARA worker crashed on PID {bad} -- skipping and resuming', 'WARN')

        for pid, name, hits in summary['finished']:
            if yara_count >= YARA_MAX_HITS: break
            seen = set()
            for hit in hits:
                rule_name = hit.get('rule', '')
                if myara.is_noise_rule(rule_name): continue
                if (pid, rule_name) in seen: continue
                seen.add((pid, rule_name))
                region = hit.get('region', '')
                perms  = myara.normalize_perms(hit.get('perms', ''))
                path   = hit.get('path', '')
                count  = hit.get('n', 0)
                base   = myara.severity_for_rule(rule_name)
                sev    = myara.classify_yara_hit(region, perms, base)
                ftype  = 'Injected Code (memory YARA)' if (region == 'anon' and 'x' in perms) \
                         else 'YARA Match (Memory)'
                ctx    = myara.hit_context_note(region, perms, path)
                add(sev, ftype,
                    f'PID {pid} ({name})',
                    f'Rule: {rule_name} | {count} match(es) | {ctx}',
                    'T1055 (Process Injection), T1027 (Obfuscated Files)')
                yara_count += 1

        for f in (real_yac, canary_src, results_path):
            try: os.unlink(f)
            except OSError: pass

        procs_scanned = len(summary['finished_pids'])
        if crashes:
            log(f'  YARA: {crashes} process(es) skipped after native crashes', 'WARN')
        verdict = myara.yara_trust_verdict(procs_scanned, summary['canary_hits'], crashes)
        log(f'  {verdict["message"]}', 'INFO' if verdict['trusted'] else 'ERROR')
        log(f'  YARA findings: {yara_count}')

# ==============================================================================
# Summary
# ==============================================================================
total = len(findings)
log('=' * 60)
log(f'Analysis complete -- {total} finding(s) | build {vmm.kernel.build}')
for sev in ('Critical', 'High', 'Medium'):
    c = sum(1 for f in findings if f['Severity'] == sev)
    if c: log(f'  {sev}: {c}')
log(f'Output: {out_json}')
log('=' * 60)

with open(out_json, 'w', encoding='utf-8') as f:
    json.dump(findings, f, indent=2)

if findings:
    print(f'\n[+] {total} finding(s) -> {Path(out_json).name}')
    for f in sorted(findings, key=lambda x: ['Critical', 'High', 'Medium', 'Low'].index(
            x.get('Severity', 'Low') if x.get('Severity', 'Low') in
            ['Critical', 'High', 'Medium', 'Low'] else 'Low')):
        print(f'  [{f["Severity"]:8s}] {f["Type"]}: {f["Target"]}')
else:
    print(f'\n[+] No concerning findings.')
