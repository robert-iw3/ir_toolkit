#!/usr/bin/env python3
"""
Phase B3 -- TTP-006: Hardware breakpoint hooks via Dr7 debug register.

Detection: threads with non-zero Dr7 in a process that is not a known debugger.
SetThreadContext can arm Dr0-Dr3 + Dr7 without any in-memory code patch -- the
entire hook lives in CPU debug registers and is forensically invisible to byte
scanners. Only a debug-register dump exposes it.

Standalone: python phase_B3_dr7_hooks.py <image.aff4> <output_dir>
Unit test:  from phase_B3_dr7_hooks import scan_dr7_hooks
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

DEBUGGER_NAMES = {
    'windbg.exe', 'x64dbg.exe', 'x32dbg.exe', 'ollydbg.exe',
    'ida.exe', 'ida64.exe', 'ghidra.exe', 'devenv.exe', 'msbuild.exe',
    'vsdebug.exe', 'msvsmon.exe',
}


def scan_dr7_hooks(procs, add, log, _is_sys=None):
    """
    Flag threads with non-zero Dr7 in non-debugger processes.

    Returns:
        (int findings, bool api_available)
    """
    _sys   = _is_sys if _is_sys is not None else is_system_proc
    n      = 0
    api_ok = False

    for p in procs:
        if _sys(p) or p.name.lower() in DEBUGGER_NAMES:
            continue
        try:
            threads = p.maps.thread()
        except Exception:
            continue

        for t in threads:
            try:
                dr7 = t.get('dr7', None)
            except Exception:
                break
            if dr7 is None:
                break
            api_ok = True
            if int(dr7) == 0:
                continue
            tid = t.get('tid', '?')
            add(
                'High',
                'Hardware Breakpoint Hook / Dr7 Armed (Memory)',
                f'PID {p.pid} ({p.name}) TID={tid}',
                f'Thread debug register Dr7={int(dr7):#x} is non-zero in a non-debugger '
                f'process. Consistent with SetThreadContext hardware breakpoint hook. '
                f'No code patch exists -- byte scanners see nothing.',
                'T1574 (Hijack Execution Flow), T1562 (Impair Defenses)',
            )
            n += 1

    if not api_ok:
        log('  Dr7 register not exposed by this vmmpyc build -- hardware breakpoint scan skipped', 'WARN')
    log(f'  Dr7 hook candidates: {n}')
    return n, api_ok


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B3: Hardware Breakpoint / Dr7 Hooks (TTP-006) ===')
    scan_dr7_hooks(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_B3_dr7_hooks')
