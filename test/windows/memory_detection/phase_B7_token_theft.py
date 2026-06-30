#!/usr/bin/env python3
"""
Phase B7 -- TTP-015: EPROCESS token theft / kernel privilege escalation.

Detection: user-mode processes holding SYSTEM-level token privileges
(via p.token, if available) without a SYSTEM-lineage parent. Token theft
via kernel EPROCESS.Token overwrite leaves no user-mode API trace.

API coverage is vmmpyc-build-dependent. Graceful degradation with WARN.

Standalone: python phase_B7_token_theft.py <image.aff4> <output_dir>
Unit test:  from phase_B7_token_theft import scan_token_theft
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

LEGIT_SYSTEM_PROCS = {
    'services.exe', 'lsass.exe', 'wininit.exe', 'smss.exe', 'csrss.exe',
    'svchost.exe', 'spoolsv.exe', 'lsm.exe', 'winlogon.exe', 'taskhost.exe',
    'taskhostw.exe', 'system', 'registry', 'dllhost.exe', 'msdtc.exe',
    'lsaiso.exe', 'fontdrvhost.exe', 'dwm.exe',
}

# Privilege bitmask: SeDebugPrivilege=bit 20, SeTcbPrivilege=bit 7
_SE_DEBUG = 0x100000
_SE_TCB   = 0x80
_SYSTEM_SID = 'S-1-5-18'


def _get_token_attrs(tok):
    """Extract (sid, integrity, privmask) from a token object or dict. Returns None on failure."""
    try:
        sid     = str(getattr(tok, 'user_sid', '') or tok.get('user_sid', '') or '')
        integ   = getattr(tok, 'integrity_level', None) or tok.get('integrity_level', None)
        pmask   = getattr(tok, 'privileges_enabled', None) or tok.get('privileges_enabled', None)
        return sid, integ, pmask
    except Exception:
        return None


def scan_token_theft(procs, pid_map, add, log, _is_sys=None):
    """
    Look for user processes with SYSTEM-grade token but non-SYSTEM parent lineage.

    Returns:
        (int findings, bool api_available)
    """
    _sys   = _is_sys if _is_sys is not None else is_system_proc
    n      = 0
    api_ok = False

    for p in procs:
        if _sys(p) or p.name.lower() in LEGIT_SYSTEM_PROCS:
            continue

        tok = None
        try:
            tok = getattr(p, 'token', None)
        except Exception:
            pass
        if tok is None:
            if not api_ok:
                break
            continue

        api_ok   = True
        attrs    = _get_token_attrs(tok)
        if attrs is None:
            continue
        sid, integ, pmask = attrs

        is_system_sid  = _SYSTEM_SID in sid
        is_high_integ  = integ is not None and int(integ) >= 0x4000
        has_se_debug   = pmask is not None and (int(pmask) & _SE_DEBUG) != 0
        has_se_tcb     = pmask is not None and (int(pmask) & _SE_TCB) != 0

        if not (is_system_sid or (has_se_debug and has_se_tcb)):
            continue

        parent      = pid_map.get(p.ppid)
        parent_name = parent.name.lower() if parent else ''
        if parent_name in LEGIT_SYSTEM_PROCS:
            continue

        add(
            'Critical',
            'EPROCESS Token Theft / Kernel Privilege Escalation (Memory)',
            f'PID {p.pid} ({p.name})',
            f'Process holds SYSTEM-level token (SID={sid} integrity={integ:#x} if integ else "?" '
            f'privmask={pmask:#x} if pmask else "?") but was not spawned from a SYSTEM-lineage '
            f'parent (parent={parent_name or "unknown"} PPID={p.ppid}). '
            f'Consistent with EPROCESS.Token overwrite via kernel write primitive.',
            'T1134.001 (Token Impersonation/Theft), T1134, T1068',
        )
        n += 1

    if not api_ok:
        log('  p.token not available in this vmmpyc build -- token theft scan skipped', 'WARN')
    log(f'  Token theft candidates: {n}')
    return n, api_ok


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B7: EPROCESS Token Theft (TTP-015) ===')
    scan_token_theft(rt['procs'], rt['pid_map'], rt['add'], rt['log'])
    write_report(rt, 'phase_B7_token_theft')
