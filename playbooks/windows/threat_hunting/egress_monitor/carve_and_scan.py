"""
carve_and_scan.py -- On-beacon-confirmation: carve memory → mwcp → persistence hunt.

Called when beacon_classifier emits CONFIRMED_BEACON or SUSPECTED_BEACON.

Pipeline:
  1. Carve all private exec-anonymous VAD regions of suspect PID via proc.memory.read()
  2. Run mwcp_scan.py (CobaltStrikeConfig + GenericC2 + PowerShellDecoder) on carved regions
  3. Parse mwcp results: extract C2 host, UserAgent, SpawnTo, PipeName, KillDate
  4. Persistence hunt using SpawnTo process name + PipeName as additional search terms
  5. Return CarveResult with all findings

Requirements:
  - tools/memprocfs/         staged by Build-OfflineToolkit.ps1 -IncludeEgressMonitor
  - tools/mwcp/lib/          mwcp + parsers including CobaltStrikeConfig.py
  - tools/memprocfs/python/python.exe  embedded Python runtime
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger('egress.carve')


@dataclass
class CarveResult:
    pid: int
    process_name: str
    timestamp: float
    regions_carved: int
    regions_with_findings: int
    c2_addresses: list[str] = field(default_factory=list)
    cs_config: dict         = field(default_factory=dict)
    decoded_strings: list[str] = field(default_factory=list)
    spawn_to: str           = ''
    pipe_name: str          = ''
    kill_date: str          = ''
    user_agent: str         = ''
    host_header: str        = ''
    persistence_hints: list[str] = field(default_factory=list)
    carved_paths: list[str] = field(default_factory=list)
    error: str              = ''


def _find_tool(tool_dir: Path, name: str) -> Optional[Path]:
    for candidate in [
        tool_dir / name,
        tool_dir / 'memprocfs' / name,
        tool_dir / 'memprocfs' / 'python' / name,
    ]:
        if candidate.exists():
            return candidate
    return None


def carve_pid(vmm, pid: int, out_dir: Path) -> list[Path]:
    """
    Carve all private executable anonymous VAD regions from the given PID.
    Returns list of paths to carved .bin files.

    VAD API: proc.maps.vad() returns list of dicts (call with (), entries are dicts).
    Memory read: proc.memory.read(va_start, size) — NOT .file_data, NOT vmm.memory_read().
    """
    carved = []
    try:
        proc = vmm.process(pid)
        vads = proc.maps.vad()   # call as method, returns list of dicts

        for vad in vads:
            prot     = vad.get('protection', '') or ''
            fn       = vad.get('filename', '') or vad.get('file', '') or ''
            va_start = vad.get('start', 0)
            va_end   = vad.get('end', 0)
            size     = va_end - va_start

            # Target: executable private anonymous regions only
            if not ('x' in prot.lower()):
                continue
            if fn:        # skip file-backed (DLLs loaded normally)
                continue
            if size < 0x1000 or size > 50 * 1024 * 1024:
                continue

            try:
                data = proc.memory.read(va_start, size)
            except Exception as e:
                log.debug(f'PID {pid} VAD 0x{va_start:x} read error: {e}')
                continue

            fname = out_dir / f'carved_pid{pid}_{va_start:010x}.bin'
            fname.write_bytes(data)
            carved.append(fname)
            hdr = data[:4].hex()
            has_mz = data[:2] == b'MZ'
            log.debug(f'  carved {fname.name} {size//1024}KB hdr={hdr}{" [MZ]" if has_mz else ""}')

    except Exception as e:
        log.warning(f'VAD enumeration failed for PID {pid}: {e}')

    return carved


def run_mwcp(carved_paths: list[Path], tool_dir: Path, out_dir: Path) -> list[dict]:
    """
    Run mwcp_scan.py against carved regions via --filelist.
    Returns list of per-file result dicts.
    """
    python_exe = _find_tool(tool_dir, 'python.exe')
    if not python_exe:
        log.warning('Embedded Python not found; skipping mwcp scan')
        return []

    # mwcp_scan.py search order:
    #   1. Same dir as this file -- correct after deployment to %ProgramData%\IRToolkit\egress-<id>\
    #   2. Parent dir -- correct when running from source tree (threat_hunting/)
    #   3. tool_dir -- last resort
    for candidate in [
        Path(__file__).parent / 'mwcp_scan.py',
        Path(__file__).parent.parent / 'mwcp_scan.py',
        tool_dir / 'mwcp_scan.py',
    ]:
        if candidate.exists():
            script = candidate
            break
    else:
        script = None
    if not script:
        log.warning(f'mwcp_scan.py not found; skipping mwcp scan')
        return []

    lib_path = tool_dir / 'mwcp' / 'lib'
    if not lib_path.exists():
        lib_path = tool_dir / 'mwcp'

    # Write file list
    list_file = out_dir / '_mwcp_filelist.txt'
    list_file.write_text('\n'.join(str(p) for p in carved_paths), encoding='utf-8')

    try:
        r = subprocess.run(
            [str(python_exe), str(script), str(lib_path), str(out_dir), '--filelist', str(list_file)],
            capture_output=True, text=True, timeout=300
        )
        list_file.unlink(missing_ok=True)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout.strip())
    except Exception as e:
        log.warning(f'mwcp_scan.py error: {e}')
        try: list_file.unlink(missing_ok=True)
        except: pass

    return []


def _parse_cs_config(decoded_strings: list[str]) -> dict:
    """Extract structured CS config fields from [CS-*] decoded strings."""
    cfg = {}
    for s in decoded_strings:
        if s.startswith('[CS-UserAgent]'):
            cfg['user_agent'] = s.split(']', 1)[1].strip()
        elif s.startswith('[CS-HostHeader]'):
            cfg['host_header'] = s.split(']', 1)[1].strip()
        elif s.startswith('[CS-Timing]'):
            cfg['timing'] = s.split(']', 1)[1].strip()
        elif s.startswith('[CS-BeaconType]'):
            cfg['beacon_type'] = s.split(']', 1)[1].strip()
        elif s.startswith('[CS-PipeName]'):
            cfg['pipe_name'] = s.split(']', 1)[1].strip()
        elif s.startswith('[CS-SpawnTo]'):
            cfg['spawn_to'] = s.split(']', 1)[1].strip()
        elif s.startswith('[CS-KillDate]'):
            cfg['kill_date'] = s.split(']', 1)[1].strip()
        elif s.startswith('[CS-Config]'):
            cfg['full_config'] = s
    return cfg


def hunt_persistence(spawn_to: str, pipe_name: str, out_dir: Path) -> list[str]:
    """
    Quick persistence check using SpawnTo process name + PipeName from beacon config.
    Returns list of finding strings.
    """
    hints = []
    try:
        import winreg
        run_keys = [
            (winreg.HKEY_CURRENT_USER,  r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
        ]
        for hive, subkey in run_keys:
            try:
                with winreg.OpenKey(hive, subkey) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                            val_lower = str(val).lower()
                            if spawn_to and spawn_to.lower() in val_lower:
                                hints.append(f'[REGISTRY RUN] {subkey}\\{name} = {val}  (matches SpawnTo: {spawn_to})')
                            i += 1
                        except OSError:
                            break
            except Exception:
                pass
    except ImportError:
        pass  # Not on Windows

    # Scheduled tasks: check task XML for SpawnTo matches
    if spawn_to:
        task_dir = Path(r'C:\Windows\System32\Tasks')
        if task_dir.exists():
            for task_file in task_dir.rglob('*'):
                try:
                    if task_file.is_file():
                        content = task_file.read_text(encoding='utf-16', errors='ignore')
                        if spawn_to.lower() in content.lower():
                            hints.append(f'[SCHEDULED TASK] {task_file} references {spawn_to}')
                except Exception:
                    pass

    # Named pipe check
    if pipe_name:
        try:
            import ctypes
            # List named pipes via CreateFile approach
            pipe_dir = Path('\\\\.\\pipe\\')
            hints.append(f'[PIPE] CobaltStrike config contains pipe name: {pipe_name} '
                         f'(check \\\\.\\pipe\\ for active instance)')
        except Exception:
            pass

    return hints


def run(vmm, pid: int, process_name: str, tool_dir: Path, out_dir: Path) -> CarveResult:
    """
    Full pipeline: carve → mwcp → parse config → hunt persistence.
    """
    result = CarveResult(pid=pid, process_name=process_name, timestamp=time.time())
    carve_out = out_dir / f'carved_{process_name}_{pid}'
    carve_out.mkdir(parents=True, exist_ok=True)

    log.info(f'[carve] Starting pipeline for PID {pid} ({process_name})')

    # Step 1: Carve VAD regions
    carved = carve_pid(vmm, pid, carve_out)
    result.regions_carved = len(carved)
    result.carved_paths = [str(p) for p in carved]
    log.info(f'[carve] {len(carved)} regions carved from PID {pid}')

    if not carved:
        result.error = 'No carvable VAD regions found'
        return result

    # Step 2: Run mwcp
    mwcp_results = run_mwcp(carved, tool_dir, carve_out)
    hits = [r for r in mwcp_results if r.get('address') or r.get('decoded') or r.get('mutex')]
    result.regions_with_findings = len(hits)
    log.info(f'[carve] mwcp: {len(hits)}/{len(mwcp_results)} regions with findings')

    # Step 3: Aggregate findings
    for r in mwcp_results:
        for addr in r.get('address', []):
            if addr not in result.c2_addresses:
                result.c2_addresses.append(addr)
        for ds in r.get('decoded', []):
            if ds not in result.decoded_strings:
                result.decoded_strings.append(ds)

    # Step 4: Parse CS config fields if CobaltStrikeConfig fired
    cs_cfg = _parse_cs_config(result.decoded_strings)
    result.cs_config   = cs_cfg
    result.spawn_to    = cs_cfg.get('spawn_to', '')
    result.pipe_name   = cs_cfg.get('pipe_name', '')
    result.kill_date   = cs_cfg.get('kill_date', '')
    result.user_agent  = cs_cfg.get('user_agent', '')
    result.host_header = cs_cfg.get('host_header', '')

    if cs_cfg:
        log.info(f'[carve] CobaltStrike config extracted: '
                 f'SpawnTo={result.spawn_to!r} PipeName={result.pipe_name!r} '
                 f'KillDate={result.kill_date!r}')

    # Step 5: Persistence hunt (only if we got SpawnTo or PipeName)
    if result.spawn_to or result.pipe_name:
        result.persistence_hints = hunt_persistence(result.spawn_to, result.pipe_name, out_dir)
        if result.persistence_hints:
            log.warning(f'[carve] Persistence indicators: {result.persistence_hints}')

    return result
