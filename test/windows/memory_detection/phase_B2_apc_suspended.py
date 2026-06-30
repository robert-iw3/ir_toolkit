#!/usr/bin/env python3
"""
Phase B2 -- TTP-005: Early-bird APC / suspended thread injection.

Detection: threads in SUSPENDED state inside user processes where the start
address is ntdll-backed (the early-bird APC pattern). An injector creates a
suspended process, writes shellcode, queues an APC targeting it, and resumes.
The window where it is detectable: the thread is still suspended before resume.

Standalone: python phase_B2_apc_suspended.py <image.aff4> <output_dir>
Unit test:  from phase_B2_apc_suspended import scan_apc_suspended
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

APC_SKIP = {
    'csrss.exe', 'smss.exe', 'wininit.exe', 'winlogon.exe',
    'userinit.exe', 'services.exe',
}


def scan_apc_suspended(procs, add, log, _is_sys=None):
    """
    Look for suspended threads whose start is inside ntdll (early-bird APC).

    Returns:
        int -- findings emitted
        bool -- whether suspendcount API was available
    """
    _sys    = _is_sys if _is_sys is not None else is_system_proc
    n       = 0
    api_ok  = False

    for p in procs:
        if _sys(p) or p.name.lower() in APC_SKIP:
            continue
        try:
            threads = p.maps.thread()
            mods    = p.module_list()
        except Exception:
            continue

        ntdll = next((m for m in mods if m.name.lower() == 'ntdll.dll'), None)
        if not ntdll:
            continue
        ntdll_lo = ntdll.base
        ntdll_hi = ntdll.base + ntdll.image_size
        mod_set  = [(m.base, m.base + m.image_size) for m in mods]

        suspended = []
        for t in threads:
            try:
                sc = t.get('suspendcount', None)
                st = str(t.get('state', '') or '').lower()
            except Exception:
                break
            if sc is None and 'suspend' not in st:
                continue
            api_ok = True
            is_susp = (sc is not None and int(sc) > 0) or ('suspend' in st)
            if not is_susp:
                continue
            start = t.get('va-win32start', 0)
            tid   = t.get('tid', '?')
            # Only flag threads whose start IS inside a module (ntdll-backed = early-bird).
            # Threads outside modules are already caught by the shellcode-thread scan.
            in_mod = any(lo <= start < hi for lo, hi in mod_set)
            if not in_mod:
                continue
            # Prefer ntdll-backed, but flag any module-backed suspended thread.
            in_ntdll = ntdll_lo <= start < ntdll_hi
            suspended.append((tid, start, in_ntdll))

        if not suspended:
            continue

        tids_str = ', '.join(
            f'TID={tid} start={s:#x}{"[ntdll]" if ntdll else ""}' for tid, s, ntdll in suspended[:5]
        )
        add(
            'Medium',
            'Suspended Thread / APC Injection Candidate (Memory)',
            f'PID {p.pid} ({p.name})',
            f'{len(suspended)} suspended thread(s) with module-backed start address. '
            f'Consistent with early-bird APC or suspended-process injection. '
            f'Corroborate: check for private exec VAD in same PID. {tids_str}',
            'T1055.003 (Thread Hijacking), T1055.004 (Asynchronous Procedure Call)',
        )
        n += 1

    if not api_ok:
        log('  suspendcount not available in this vmmpyc build -- APC scan limited', 'WARN')
    log(f'  APC/suspended thread candidates: {n}')
    return n, api_ok


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B2: Suspended Thread / APC Injection (TTP-005) ===')
    scan_apc_suspended(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_B2_apc_suspended')
