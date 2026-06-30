#!/usr/bin/env python3
"""
Phase C3 -- TTP-012: PPID / parent-process spoofing.

Detection (two signals):
  1. Claimed parent PID not in live process list (orphaned -- benign or spoofed).
  2. Claimed parent was created AFTER the child (temporally impossible -- forged).
     Requires p.create_time; degrades gracefully if absent.

Standalone: python phase_C3_ppid_spoof.py <image.aff4> <output_dir>
Unit test:  from phase_C3_ppid_spoof import scan_ppid_spoof
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

PPID_SKIP = {
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'secure system',
    'registry', 'memory compression', 'interrupts', 'idle',
}


def _create_time(p):
    """Return process create_time as a comparable value, or None."""
    for attr in ('create_time', 'time_create', 'ftCreateTime'):
        try:
            val = getattr(p, attr, None)
            if val is not None:
                return val
        except Exception:
            pass
    return None


def scan_ppid_spoof(procs, pid_map, add, log, _is_sys=None):
    """
    Check for orphaned parents and temporally impossible parent-child timestamps.

    Returns:
        (int findings, bool time_api_available)
    """
    _sys    = _is_sys if _is_sys is not None else is_system_proc
    n       = 0
    time_ok = False

    for p in procs:
        if _sys(p) or p.name.lower() in PPID_SKIP:
            continue

        parent = pid_map.get(p.ppid)

        if not parent:
            # PID 0 (idle), PID 4 (system) are expected orphan parents.
            if p.ppid not in (0, 4):
                cmd = ''
                try:
                    cmd = p.cmdline or ''
                except Exception:
                    pass
                add(
                    'Medium',
                    'Orphaned Parent / Potential PPID Spoof (Memory)',
                    f'PID {p.pid} ({p.name}) <- PPID {p.ppid}',
                    f'Claimed parent PID {p.ppid} is not present in the process list. '
                    f'Parent exited (may be benign) OR PPID was spoofed to a '
                    f'recycled/exited PID. Corroborate via process-creation event log.',
                    'T1134.004 (Parent PID Spoofing)',
                )
                n += 1
            continue

        # Temporal check: parent created after child is impossible.
        p_ct  = _create_time(p)
        par_ct = _create_time(parent)
        if p_ct is None or par_ct is None:
            continue
        time_ok = True
        if par_ct > p_ct:
            add(
                'High',
                'PPID Spoofing -- Parent Created After Child (Memory)',
                f'PID {p.pid} ({p.name}) <- PPID {p.ppid} ({parent.name})',
                f'Claimed parent {parent.name} (PID {p.ppid}) was created AFTER this '
                f'process -- temporally impossible in a real parent-child relationship. '
                f'PPID was forged via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.',
                'T1134.004 (Parent PID Spoofing), T1134',
            )
            n += 1

    if not time_ok:
        log('  create_time not available in this vmmpyc build -- temporal PPID check skipped', 'WARN')
    log(f'  PPID spoofing candidates: {n}')
    return n, time_ok


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase C3: PPID Spoofing (TTP-012) ===')
    scan_ppid_spoof(rt['procs'], rt['pid_map'], rt['add'], rt['log'])
    write_report(rt, 'phase_C3_ppid_spoof')
