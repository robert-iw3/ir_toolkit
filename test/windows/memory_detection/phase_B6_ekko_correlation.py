#!/usr/bin/env python3
"""
Phase B6 -- TTP-013: Thread-pool / timer-queue injection (Ekko, Foliage, Deathant).

Detection: correlation pass. A process that BOTH has a high-entropy private RW
region (dormant beacon -- phase A finding) AND has multiple ntdll-backed running
threads (pool workers) matches the Ekko sleep-obfuscation signature.

NOTE: This phase imports and re-runs the phase A scan so it can cross-reference.
Run after phase A or pass pre-built findings via the 'prior_findings' argument.

Standalone: python phase_B6_ekko_correlation.py <image.aff4> <output_dir>
Unit test:  from phase_B6_ekko_correlation import scan_ekko_correlation
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import (
    is_system_proc, entropy, BEACON_MIN, BEACON_MAX, ENTROPY_THRESHOLD,
    HIGH_ENT_PROCS,
)


def _high_beacon_pids(prior_findings: list) -> set:
    """
    Return PIDs that have at least one HIGH-severity Dormant Beacon finding.
    Medium findings (large regions) are excluded -- they are too broad to
    corroborate the Ekko sleep-mask pattern, which uses shellcode-sized regions.
    """
    pids = set()
    for f in prior_findings:
        if 'Dormant Beacon Candidate' not in f.get('Type', ''):
            continue
        if f.get('Severity') != 'High':
            continue
        # Target format: "PID NNNN (name) @ 0x..."
        parts = f.get('Target', '').split(' ')
        if len(parts) >= 2:
            try:
                pids.add(int(parts[1]))
            except ValueError:
                pass
    return pids


def scan_ekko_correlation(procs, add, log, prior_findings=None, _is_sys=None):
    """
    Cross-reference dormant beacon PIDs against processes with ntdll-backed threads.

    Args:
        prior_findings: list of finding dicts already emitted (from phase A).
                        If None, re-scans for high-entropy RW regions internally.
    Returns:
        int -- findings emitted
    """
    _sys = _is_sys if _is_sys is not None else is_system_proc
    n    = 0

    # If no prior findings supplied, identify HIGH-severity beacon PIDs by re-scanning.
    # (Only High severity = shellcode-sized regions < 256 KB are Ekko-relevant.)
    if prior_findings is None:
        beacon_pids = set()
        for p in procs:
            if _sys(p):
                continue
            if p.name.lower() in HIGH_ENT_PROCS:
                continue
            try:
                vads = p.maps.vad()
            except Exception:
                continue
            for v in vads:
                prot  = str(v.get('protection', '') or '').upper()
                addr  = v.get('start', 0)
                end   = v.get('end', 0) or 0
                # vmmpyc uses 'end' (inclusive); mock tests use 'size'.
                size  = max(0, end - addr + 1) if end else (v.get('size', 0) or 0)
                typ_s = str(v.get('type', '') or '').strip().lower()
                # Only private anonymous RW regions, no execute flag.
                if 'X' in prot:
                    continue
                if typ_s and typ_s != 'private':
                    continue
                if 'W' not in prot:
                    continue
                # High severity only (beacon-sized < 256 KB).
                if not (BEACON_MIN <= size <= 262144):
                    continue
                try:
                    sample = p.memory.read(addr, min(size, 8192))
                    if sample and len(sample) >= 512 and entropy(sample) >= ENTROPY_THRESHOLD:
                        beacon_pids.add(p.pid)
                        break
                except Exception:
                    pass
    else:
        beacon_pids = _high_beacon_pids(prior_findings)

    if not beacon_pids:
        log('  No dormant beacon PIDs to correlate -- skipping Ekko check')
        return 0

    # Build pid_map for name lookups.
    pid_map = {p.pid: p for p in procs}

    for p in procs:
        if _sys(p) or p.pid not in beacon_pids:
            continue
        try:
            threads = p.module_list()  # need module list for ntdll range
            mods    = threads           # alias for clarity below
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

        add(
            'High',
            'Thread-Pool Injection / Ekko Pattern (Memory)',
            f'PID {p.pid} ({p.name})',
            f'{len(pool_threads)} ntdll-backed running thread(s) in a process that '
            f'also has a high-entropy private RW region (dormant beacon candidate). '
            f'Matches Ekko/Foliage sleep-obfuscation: payload encrypted at rest, '
            f'thread-pool workers hold pending APC/timer callback.',
            'T1055.004 (APC), T1055 (Process Injection), T1106',
        )
        n += 1

    log(f'  Thread-pool injection (Ekko) candidates: {n}')
    return n


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B6: Thread-Pool / Ekko Correlation (TTP-013) ===')
    # Phase A scan first to populate prior_findings.
    from phase_A_dormant_beacon import scan_dormant_beacons
    scan_dormant_beacons(rt['procs'], rt['add'], rt['log'])
    scan_ekko_correlation(rt['procs'], rt['add'], rt['log'], prior_findings=rt['findings'])
    write_report(rt, 'phase_B6_ekko_correlation')
