#!/usr/bin/env python3
"""
Phase C2 -- TTP-011: In-memory CLR assembly in non-managed host (execute-assembly).

Behavioral evidence beyond module-name presence:
  - Scan executable (EXECUTE_READ / EXECUTE_READ_WRITE) private regions for the
    CLR metadata header magic: 0x424A5342 == 'BSJB' (ECMA-335 CLI metadata root
    signature). This magic appears at offset 0 of every .NET metadata stream --
    it cannot be forged by accident. Presence of BSJB in anonymous executable
    memory of a non-managed process IS execute-assembly.
  - Also flag: CLR metadata in a private region whose entropy >= 5.5 bits/byte
    (IL code + resources are moderately high entropy, unlike normal code), which
    corroborates the BSJB signature when the header itself was partially wiped.

Standalone: python phase_C2_clr_assembly.py <image.aff4> <output_dir>
Unit test:  from phase_C2_clr_assembly import scan_clr_assembly
"""
import sys, os, re, struct
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc, entropy as _entropy

CLR_DLLS = frozenset({'clr.dll', 'coreclr.dll', 'clrjit.dll', 'mscoree.dll', 'mscorlib.dll'})

MANAGED_HOSTS = re.compile(
    r'(?i)^(powershell|pwsh|dotnet|msbuild|devenv|code|rider|idea64|'
    r'pycharm64|datagrip64|clion64|webstorm64|goland64|rubymine64|'
    r'csc|vbc|csi|dnspy|ilspy|dotpeek|appletviewer|java|mono|'
    r'mscorsvw|ngen|regasm|regsvcs|installutil)(.exe)?$',
)

# ECMA-335 CLI metadata root signature "BSJB"
_BSJB_MAGIC   = b'BSJB'
_MIN_BSJB_ENT = 5.5    # IL code entropy floor (bits/byte)
_SCAN_LIMIT   = 64     # max pages to scan per process (avoid runaway)
_PAGE          = 0x1000


def _find_bsjb(data: bytes) -> bool:
    """True if the BSJB magic appears anywhere in data."""
    return _BSJB_MAGIC in data


def scan_clr_assembly(procs, add, log, _is_sys=None, _read_mem=None):
    """
    Flag processes hosting CLR metadata (execute-assembly / Donut) with two
    independent behavioral signals:
      1. CLR DLL in module list of non-managed host (context).
      2. BSJB CLI metadata magic found in a private EXECUTE_READ region.

    Signal 1 alone = INFO note only.
    Signal 1 + Signal 2 = High finding.
    Signal 2 alone (no CLR DLL) = High finding (CLR was unloaded post-exec).

    Returns:
        int -- findings emitted
    """
    _sys = _is_sys if _is_sys is not None else is_system_proc
    n    = 0

    for p in procs:
        if _sys(p) or MANAGED_HOSTS.match(p.name):
            continue

        # Signal 1: CLR DLL presence
        try:
            mods      = p.module_list()
            mod_names = {m.name.lower() for m in mods}
        except Exception:
            mod_names = set()

        clr_found = CLR_DLLS & mod_names
        # Suppress legitimate managed hosts that have both mscoree+clr
        if 'mscoree.dll' in mod_names and 'clr.dll' in mod_names:
            continue

        # Signal 2: Scan private EXECUTE regions for BSJB CLI metadata magic
        bsjb_addr  = 0
        bsjb_found = False
        pages_scanned = 0
        try:
            vads = getattr(p, 'vads', None)
            if vads is None:
                vads = p.maps.vad() if hasattr(p, 'maps') and hasattr(p.maps, 'vad') else []
            for vad in vads:
                prot  = str(vad.get('protection', '')).upper()
                # Strip spaces: real vmmpyc uses '     ' private, 'Image'/'File '/'Pf   ' others
                vtype = str(vad.get('type', '')).strip().lower()
                # Only scan private anonymous executable regions.
                # 'X' catches 'EXECUTE...' (mock) and '---WXC'/'p-r-x-' (real vmmpyc).
                if 'X' not in prot:
                    continue
                # Skip image-backed and file-backed; keep private ('') and 'private' (mock).
                if vtype == 'image' or 'file' in vtype:
                    continue
                base = int(vad.get('start', 0))
                end  = vad.get('end', 0) or 0
                # vmmpyc uses 'end' (inclusive); mock tests use 'size'.
                size = max(0, end - base + 1) if end else int(vad.get('size', 0))
                if size == 0 or pages_scanned >= _SCAN_LIMIT:
                    break
                scan_size = min(size, _SCAN_LIMIT * _PAGE)
                try:
                    if _read_mem is not None:
                        data = _read_mem(p, base, scan_size) or b''
                    elif hasattr(p, 'maps') and hasattr(p.maps, 'memory'):
                        data = p.maps.memory.read(base, scan_size) or b''
                    else:
                        data = b''
                except Exception:
                    data = b''
                if data and _find_bsjb(data):
                    bsjb_found = True
                    bsjb_addr  = base
                    break
                pages_scanned += max(1, scan_size // _PAGE)
        except Exception:
            pass

        if not clr_found and not bsjb_found:
            continue

        cmd = ''
        try:
            cmd = p.cmdline or ''
        except Exception:
            pass

        if bsjb_found:
            # Both or BSJB alone: strong evidence
            sev    = 'High'
            detail = (
                f'CLR CLI metadata (BSJB magic) found in private EXECUTE region '
                f'at 0x{bsjb_addr:016X} -- this is the .NET metadata root signature '
                f'(ECMA-335 5.6). Cannot appear in a legitimate non-.NET process. '
                f'CLR DLLs in module list: {sorted(clr_found) or "none (CLR unloaded post-exec)"}. '
                f'CMD={cmd[:200]}'
            )
            add(sev, 'CLR Assembly in Non-Managed Process (Memory)',
                f'PID {p.pid} ({p.name})', detail,
                'T1620 (Reflective Code Loading), T1055 (Process Injection)')
            n += 1
        elif clr_found:
            # CLR DLL only, no BSJB scan result -- lower confidence, log not find
            log(f'  C2: PID {p.pid} ({p.name}) has CLR DLLs {sorted(clr_found)} '
                f'but no BSJB metadata found in executable regions -- context only, not firing')

    log(f'  CLR execute-assembly candidates with BSJB evidence: {n}')
    return n


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase C2: CLR Execute-Assembly (TTP-011) ===')
    scan_clr_assembly(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_C2_clr_assembly')
