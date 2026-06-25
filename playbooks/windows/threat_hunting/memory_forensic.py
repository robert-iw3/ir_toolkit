#!/usr/bin/env python3
"""
Advanced forensic memory analysis using MemProcFS vmmpyc Python API.
No Dokany/WinFsp required  - pure library access.
Staged offline via: Build-OfflineToolkit.ps1 -IncludeMemProcFS

Usage: python memory_forensic.py <image.aff4> <output_dir>
Output: Memory_Findings_<stamp>.json  - concerning findings only.

Detection modules:
  1.  LOLBin cmdlines             - encoded commands, IEX, WebClient downloads
  2.  Hidden processes            - DKOM / PEB-unlink artifacts
  3.  Injected memory             - executable private VAD (no backing file)
  4.  External network            - established/listening connections to external IPs
  5.  Shellcode threads           - user-mode threads starting outside any loaded module
  6.  Parent-child anomalies      - processes spawned from unexpected parents
  7.  Process path spoofing       - mismatched image path vs expected location
  8.  Credential tooling          - known dumping/lateral-movement tool names in cmdline
  9.  Suspicious network bind     - user processes listening on non-standard ports
  10. Kernel driver check         - BYOVD-class driver names
  11. Registry Run persistence    - LOLBin commands in live Run keys
  12. YARA memory scan            - staged rule sets (Elastic/ReversingLabs/Neo23x0) per-process,
                                   15s per-process timeout, noise-rule suppression
"""

import sys, os, re, json, threading
import glob as _glob
from datetime import datetime
from pathlib import Path

# The bundled embeddable Python does not put this script's own directory on
# sys.path (its ._pth disables that), so sibling imports like memory_yara fail.
# Add it explicitly.
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
    with open(log_path, 'a', encoding='utf-8') as f: f.write(s+'\n')

# -- vmmpyc setup --------------------------------------------------------------
mpc_dir = str(Path(__file__).parent.parent.parent.parent / 'tools' / 'memprocfs')
py_dir  = os.path.join(mpc_dir, 'python')
os.add_dll_directory(mpc_dir)
sys.path.insert(0, mpc_dir)
import glob as _g
for z in _g.glob(os.path.join(py_dir, 'python3*.zip')):
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

# Known system/kernel-mode processes  - skip user-mode checks for these
KERNEL_PROCS = {'system', 'secure system', 'registry', 'memory compression',
                'interrupts', 'idle', 'mssmbios'}
# Toolkit's own scripts  - exclude from LOLBin self-detection
TOOLKIT_SCRIPTS = {
    'invoke-ircollection.ps1', 'edr_toolkit.ps1', 'edr_toolkit_deploy.ps1',
    'get-persistencesnapshot.ps1', 'get-remoteaccesstriage.ps1',
    'invoke-eventloganalysis.ps1', 'get-findingcontext.ps1',
    'analyze-memory.ps1', '00_collect-forensics.ps1',
}

def is_system_proc(p):
    return p.name.lower() in KERNEL_PROCS or p.pid <= 8

def safe_cmdline(p):
    try:   return p.cmdline or ''
    except: return ''

def is_toolkit_cmd(cmd):
    cl = cmd.lower()
    return any(s in cl for s in TOOLKIT_SCRIPTS)

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
# 3. Injected memory  - executable private VAD without backing file
# ==============================================================================
log('=== 3. Injected memory (private exec VAD) ===')
EXEC_RE = re.compile(r'(?i)\bX\b|EXECUTE|EXEC_READ|EXEC_READWRITE')
n = 0
for p in procs:
    if is_system_proc(p): continue
    try: vads = p.maps.vad()
    except: continue
    for v in vads:
        prot = str(v.get('protection', ''))
        typ  = str(v.get('type', ''))
        tag  = str(v.get('tag', ''))
        if not EXEC_RE.search(prot): continue
        if 'image' in tag.lower() or 'mapped' in typ.lower(): continue
        if typ.lower() in ('private', '') and 'image' not in tag.lower():
            addr = v.get('start', 0)
            add('High', 'Injected Memory Region',
                f'PID {p.pid} ({p.name}) @ {addr:#x}',
                f'Executable private VAD (no backing file). Protection={prot} Type={typ}',
                'T1055, T1027')
            n += 1
            if n > 30: break
    if n > 30: break
log(f'  Injected regions: {n}')

# ==============================================================================
# 4. External network connections
# ==============================================================================
log('=== 4. External network connections ===')
PRIVATE = re.compile(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|0\.0\.0\.0$)', re.I)
n = 0
try:
    for conn in vmm.maps.net():
        dst   = str(conn.get('dst-ip', '') or '')
        dport = conn.get('dst-port', 0)
        state = str(conn.get('state', '') or '')
        pid_n = conn.get('pid', 0)
        pname = pid_map.get(pid_n, type('', (), {'name': 'unknown'})()).name
        if not dst or PRIVATE.match(dst) or dst in ('', '0.0.0.0', '::', '*', 'N/A'): continue
        if state.upper() not in ('ESTABLISHED','LISTEN','CLOSE_WAIT','SYN_SENT','CLOSE'): continue
        sev = 'High' if state.upper() == 'ESTABLISHED' else 'Medium'
        add(sev, 'Network Connection (Memory)',
            f'PID {pid_n} ({pname})',
            f'{state} -> {dst}:{dport}',
            'T1071, T1021')
        n += 1
except Exception as e: log(f'  Net error: {e}', 'WARN')
log(f'  External connections: {n}')

# ==============================================================================
# 5. Shellcode threads  - start address outside any loaded module (user-mode only)
# ==============================================================================
log('=== 5. Shellcode thread detection ===')
# Filter: user-mode address range, exclude kernel-mode procs and ntdll-like ranges
USER_MAX  = 0x800000000000        # x64 user-mode ceiling
NTDLL_LOW = 0x7FFE0000            # Windows shared user data / ntdll stub area (FPs)
SKIP_PROCS = KERNEL_PROCS | {'memcompression', 'smss.exe', 'csrss.exe'}
n = 0
for p in procs:
    if p.name.lower() in SKIP_PROCS or is_system_proc(p): continue
    try:
        mods    = p.module_list()
        mod_set = {(m.base, m.base + m.image_size) for m in mods}
        threads = p.maps.thread()
    except: continue
    for t in threads:
        start = t.get('va-win32start', 0)
        if not start or start <= 0x10000 or start >= USER_MAX: continue
        if start >= NTDLL_LOW: continue    # ntdll user-shared area  - expected
        if t.get('exitstatus', 0) != 0: continue   # only running threads
        in_mod = any(lo <= start < hi for lo, hi in mod_set)
        if not in_mod:
            add('High', 'Shellcode Thread (Memory)',
                f'PID {p.pid} ({p.name}) TID={t.get("tid")}',
                f'Thread start {start:#x} falls outside all loaded modules  - likely shellcode injection',
                'T1055.003 (Thread Hijacking), T1055')
            n += 1
log(f'  Shellcode threads: {n}')

# ==============================================================================
# 6. Parent-child anomalies
# ==============================================================================
log('=== 6. Parent-child relationship anomalies ===')
# Expected parent -> {set of child names}
EXPECTED_PARENTS = {
    'services.exe':   {'svchost.exe', 'dllhost.exe', 'taskhost.exe', 'taskhostw.exe',
                       'msiexec.exe', 'msdtc.exe'},
    'svchost.exe':    {'werfault.exe', 'dllhost.exe', 'backgroundtransferhst.exe',
                       'backgroundtaskhost.exe', 'conhost.exe', 'runtimebroker.exe',
                       'securityhealthservice.exe', 'wuauclt.exe', 'tiworker.exe'},
    'wininit.exe':    {'services.exe', 'lsass.exe', 'lsaiso.exe'},
    'winlogon.exe':   {'userinit.exe', 'fontdrvhost.exe', 'dwm.exe', 'logonui.exe'},
    'explorer.exe':   {'*'},   # explorer can spawn anything legitimately
    'userinit.exe':   {'explorer.exe'},
    'smss.exe':       {'csrss.exe', 'wininit.exe', 'winlogon.exe', 'smss.exe'},
    'lsass.exe':      {'werfault.exe'},
    'taskeng.exe':    {'*'},
    'taskhostw.exe':  {'*'},
    'mmc.exe':        {'*'},
    'msiexec.exe':    {'*'},
}
# High-risk process spawned from unusual parent
HIGH_RISK_CHILDREN = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
                      'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
                      'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe'}
n = 0
for p in procs:
    if is_system_proc(p): continue
    child = p.name.lower()
    if child not in HIGH_RISK_CHILDREN: continue
    parent = pid_map.get(p.ppid)
    if not parent: continue
    pname = parent.name.lower()
    allowed = EXPECTED_PARENTS.get(pname, set())
    if '*' in allowed: continue                  # any child OK
    if child not in allowed and pname not in ('explorer.exe', 'taskhostw.exe',
                                               'taskeng.exe', 'mmc.exe'):
        cmd = safe_cmdline(p)
        if is_toolkit_cmd(cmd): continue         # suppress own toolkit activity
        add('High', 'Suspicious Parent-Child Relationship (Memory)',
            f'PID {p.pid} ({p.name}) <- PPID {p.ppid} ({parent.name})',
            f'Unusual parent "{parent.name}" spawned high-risk "{p.name}". CMD={cmd[:200]}',
            'T1059, T1204 (User Execution)')
        n += 1
log(f'  Anomalous parent-child: {n}')

# ==============================================================================
# 7. Process path spoofing  - image not in expected system directory
# ==============================================================================
log('=== 7. Process path spoofing ===')
# Well-known system processes that must live in System32 or SysWOW64
SYSTEM32_PROCS = {
    'lsass.exe', 'svchost.exe', 'services.exe', 'csrss.exe', 'smss.exe',
    'wininit.exe', 'winlogon.exe', 'lsaiso.exe', 'spoolsv.exe', 'taskhostw.exe',
    'taskhost.exe', 'dwm.exe', 'conhost.exe', 'dllhost.exe', 'userinit.exe',
}
SYS_PATHS = re.compile(r'(?i)^[a-z]:\\windows\\(system32|syswow64)\\', re.I)
n = 0
for p in procs:
    if p.name.lower() not in SYSTEM32_PROCS: continue
    try:    pu = str(p.pathuser  or '')
    except: pu = ''
    try:    pk = str(p.pathkernel or '')
    except: pk = ''
    raw  = pu if pu else pk
    # Normalise Windows NT namespace paths to standard C:\ form
    full = re.sub(r'\\Device\\HarddiskVolume\d+', 'C:', raw)     # device object form
    full = re.sub(r'^\\\?\?\\', '', full)                        # \??\ NT prefix
    full = full.replace('\\SystemRoot\\', 'C:\\Windows\\')       # early-boot alias
    if not full: continue
    if not SYS_PATHS.match(full):
        add('Critical', 'Process Path Spoofing (Memory)',
            f'PID {p.pid} ({p.name})',
            f'System process running from unexpected path: {full}',
            'T1036.005 (Masquerading: Match Legitimate Name)')
        n += 1
log(f'  Path-spoofed system procs: {n}')

# ==============================================================================
# 8. Known offensive tooling in process names / cmdlines
# ==============================================================================
log('=== 8. Known offensive tooling ===')
TOOL_PATTERNS = [
    # Credential dumping
    (r'(?i)mimi' + r'katz|sekur' + r'lsa|wce\.exe|fgdump|cachedump|wdigest', 'Credential dumping tool'),
    # Lateral movement
    (r'(?i)psexec|wmiexec|smbexec|atexec|dcomexec', 'Lateral movement tool'),
    # C2 frameworks
    (r'(?i)cobalt.?strike|cobaltstrike|beacon\.', 'Cobalt Strike'),
    (r'(?i)meterpreter|metasploit', 'Metasploit'),
    (r'(?i)empire\.ps1|invoke-empire', 'PowerShell Empire'),
    (r'(?i)covenant|brute.?ratel', 'C2 framework'),
    # Recon / scanning
    (r'(?i)nmap|masscan|fscan|netcat\b|nc\.exe', 'Network scanner/listener'),
    # AD attack tools
    (r'(?i)bloodhound|sharphound|powerview|powermad|rubeus|kerber' + r'oast', 'AD attack tool'),
    # LOLBAS bypasses
    (r'(?i)mavinject|installutil.*\.exe|appsync' + r'publisher', 'LOLBAS abuse'),
]
n = 0
for p in procs:
    cmd  = safe_cmdline(p)
    name = p.name
    text = (name + ' ' + cmd).lower()
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
# 9. Suspicious network listeners  - user processes on non-standard ports
# ==============================================================================
log('=== 9. Suspicious network listeners ===')
# Processes legitimately listening on high ports
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
        if src_port < 1024: continue            # system ports are expected
        src_ip = str(conn.get('src-ip', '') or '')
        if src_ip.startswith('127.'): continue  # loopback listeners are low risk
        pid_n  = conn.get('pid', 0)
        pname  = (pid_map.get(pid_n, type('', (), {'name': 'unknown'})()).name or '').lower()
        if any(a in pname for a in LISTENER_ALLOWLIST): continue
        add('Medium', 'Suspicious Network Listener (Memory)',
            f'PID {pid_n} ({pname})',
            f'User process listening on {src_ip}:{src_port}  - potential backdoor bind shell',
            'T1071 (Application Layer Protocol), T1571 (Non-Standard Port)')
        n += 1
except Exception as e: log(f'  Listener check error: {e}', 'WARN')
log(f'  Suspicious listeners: {n}')

# ==============================================================================
# 10. Kernel driver check  - BYOVD-class names
# ==============================================================================
log('=== 10. Kernel driver scan ===')
VULN_DRV = re.compile(
    r'(?i)(RTCore64|WinRing0|GDRV|ASMIO|cpuz\d|nvoclock|kprocesshacker|'
    r'physmem|gmer|dbutil|AsUpio|HwRwDrv|HwOs2Ec|iqvw64e|cpuz141)', re.I)
n = 0
try:
    for d in vmm.maps.kdriver():
        name = str(d.get('name','') or d.get('module','') or '')
        base = d.get('base', d.get('va', 0))
        if VULN_DRV.search(name):
            add('Critical', 'Vulnerable Kernel Driver (Memory)', name,
                f'BYOVD-class driver at {base:#x}',
                'T1068, T1543.003')
            n += 1
except Exception as e: log(f'  Driver scan error: {e}', 'WARN')
log(f'  Suspicious drivers: {n}')

# ==============================================================================
# 11. Registry Run key persistence (live hive)
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
            data = str(val.get('data','') or '')
            if LOL_BIN_RE.search(data):
                add('High', 'Suspicious Run Key (Memory)', f'{rk}\\{val.get("name","")}',
                    f'LOLBin in Run key: {data[:200]}',
                    'T1547.001 (Registry Run Keys)')
                n += 1
    except: pass
log(f'  Suspicious Run keys: {n}')

# ==============================================================================
# 12. YARA memory scan  - staged rules from tools/yara_rules/
# ==============================================================================
log('=== 12. YARA memory scan ===')

# Optional: carve true-positive (Private+exec / injected) regions to tools\binja\data\<id>\ for
# offline Binary Ninja RE. Enabled by Analyze-Memory.ps1 -Carve via IR_CARVE_DIR (inherited by the
# worker subprocess). The worker does the actual carving; this just surfaces it in the run log.
_carve_dir = os.environ.get('IR_CARVE_DIR')
if _carve_dir:
    log(f'  Carve ON: true-positive regions -> {_carve_dir}'
        + ('  (IR_CARVE_ANY=1: carving ALL hit regions)' if os.environ.get('IR_CARVE_ANY') == '1' else ''))

try:
    import memory_yara as myara   # vmmpyc-free: rule handling, canary, trust verdict
except Exception as e:
    myara = None
    log(f'  SKIP: memory_yara import failed ({e}) - YARA scan skipped', 'WARN')

YARA_RULES_DIR  = Path(mpc_dir).parent / 'yara_rules'
YARAC_EXE       = Path(mpc_dir).parent / 'yarac64.exe'
YARA_TIMEOUT    = 15        # seconds per process before abort
YARA_MAX_HITS   = 200       # cap findings to avoid noise explosion
YARA_MAX_CRASH  = 25        # max worker restarts (skips one crashing PID each)
YARA_WORKER     = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'memory_yara_worker.py')

yara_count = 0
if myara is None:
    pass   # import failure already logged above
elif not YARA_RULES_DIR.is_dir():
    log(f'  SKIP: {YARA_RULES_DIR} not found  - run Build-OfflineToolkit.ps1 -IncludeYaraRules', 'WARN')
elif not YARAC_EXE.is_file():
    log(f'  SKIP: yarac64.exe not staged at {YARAC_EXE} - cannot compile ruleset', 'WARN')
elif not os.path.isfile(YARA_WORKER):
    log(f'  SKIP: worker not found at {YARA_WORKER}', 'WARN')
else:
    import subprocess as _sp
    all_rules = myara.collect_rule_files(str(YARA_RULES_DIR))
    win_rules = myara.filter_windows_rules(all_rules)      # drop Linux/macOS rules
    win_rules = myara.exclude_memory_noise(win_rules)      # drop file-oriented feeds (abuse.ch)
    log(f'  Rules: {len(win_rules)} Windows-applicable (of {len(all_rules)} staged)')

    # Compile the Windows ruleset + DOS-stub canary into ONE .yac. search_yara needs
    # compiled rules (a list of source paths silently compiles to nothing); the canary
    # rides along so every per-process result proves the engine inspected memory.
    canary_src = os.path.join(OUTPUT_DIR, f'_yara_canary_{stamp}.yar')
    with open(canary_src, 'w', encoding='utf-8') as cf:
        cf.write(myara.canary_rule_source())
    real_yac = os.path.join(OUTPUT_DIR, f'_yara_win_{stamp}.yac')
    yac, n_ok, n_fail = myara.compile_ruleset(win_rules + [canary_src], str(YARAC_EXE), real_yac)
    if not yac:
        log('  SKIP: ruleset failed to compile - YARA scan skipped', 'WARN')
    else:
        log(f'  Compiled {n_ok} rule file(s) into one ruleset'
            + (f' ({n_fail} excluded)' if n_fail else ''),
            'WARN' if n_fail else 'INFO')

        # Run the scan in an isolated worker subprocess. A native MemProcFS segfault
        # on a pathological process (e.g. dwm.exe GPU mappings) only kills the worker;
        # we restart it with the crashing PID skipped and resume past it.
        results_path = os.path.join(OUTPUT_DIR, f'_yara_results_{stamp}.jsonl')
        open(results_path, 'w').close()
        skip = set()
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
            # Treat already-skipped PIDs as resolved so we flag the NEW crasher, not
            # a stale 'start' record left in the appended results file by a prior run.
            bad = myara.crashing_pid(summary['started_pids'], summary['finished_pids'] | skip)
            if bad is None:
                break   # exited without 'done' and no clear crasher - stop
            skip.add(bad); skip |= summary['finished_pids']   # skip crasher + already-scanned
            crashes += 1
            log(f'  YARA worker crashed (native) on PID {bad} - skipping and resuming', 'WARN')

        # Build findings from the accumulated results, enriched with VAD context.
        for pid, name, hits in summary['finished']:
            if yara_count >= YARA_MAX_HITS: break
            seen = set()
            for hit in hits:
                rule_name = hit.get('rule', '')
                if myara.is_noise_rule(rule_name): continue
                if (pid, rule_name) in seen: continue        # one finding per PID+rule
                seen.add((pid, rule_name))
                region = hit.get('region', '')
                perms  = myara.normalize_perms(hit.get('perms', ''))
                path   = hit.get('path', '')
                count  = hit.get('n', 0)
                base   = myara.severity_for_rule(rule_name)
                sev    = myara.classify_yara_hit(region, perms, base)   # anon+exec -> Critical
                ftype  = 'Injected Code (memory YARA)' if (region == 'anon' and 'x' in perms) \
                         else 'YARA Match (Memory)'
                ctx    = myara.hit_context_note(region, perms, path)
                add(sev, ftype,
                    f'PID {pid} ({name})',
                    f'Rule: {rule_name} | {count} match(es) | {ctx}',
                    'T1055 (Process Injection), T1027 (Obfuscated Files)')
                yara_count += 1

        for f in (real_yac, canary_src, results_path):   # clean up temp artifacts
            try: os.unlink(f)
            except OSError: pass

        procs_scanned = len(summary['finished_pids'])
        if crashes:
            log(f'  YARA: {crashes} process(es) skipped after native scanner crashes', 'WARN')
        verdict = myara.yara_trust_verdict(procs_scanned, summary['canary_hits'], crashes)
        log(f'  {verdict["message"]}', 'INFO' if verdict['trusted'] else 'ERROR')
        log(f'  YARA findings: {yara_count}')

# ==============================================================================
# Summary
# ==============================================================================
total = len(findings)
log('=' * 60)
log(f'Analysis complete  - {total} concerning finding(s)  |  build {vmm.kernel.build}')
for sev in ('Critical','High','Medium'):
    c = sum(1 for f in findings if f['Severity'] == sev)
    if c: log(f'  {sev}: {c}')
log(f'Output: {out_json}')
log('=' * 60)

with open(out_json, 'w', encoding='utf-8') as f:
    json.dump(findings, f, indent=2)

if findings:
    print(f'\n[+] {total} finding(s) -> {Path(out_json).name}')
    for f in sorted(findings, key=lambda x: ['Critical','High','Medium','Low'].index(x['Severity'])):
        print(f'  [{f["Severity"]:8s}] {f["Type"]}: {f["Target"]}')
else:
    print(f'\n[+] No concerning findings.')
