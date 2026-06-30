#!/usr/bin/env python3
"""
Phase B8 -- TTP-016: Kernel callback / ETW-Ti blinding / pool-tag connection carving.

Three sub-checks:
  A. Kernel callback arrays (PspCreateProcessNotifyRoutine etc.) -- NULL or
     out-of-module pointers indicate BYOVD callback stripping.
  B. ETW-Ti provider state -- patched handle = kernel telemetry blind.
  C. Pool-tag connection carving -- TCPT/TCPe tags surface connections
     unlinked from tcpip.sys official table (DKOM network hiding).

All three are vmmpyc-build-dependent; each degrades gracefully.

Standalone: python phase_B8_kernel_integrity.py <image.aff4> <output_dir>
Unit test:  from phase_B8_kernel_integrity import (
                scan_callback_integrity, scan_etw_ti, scan_pool_connections)
"""
import sys, os, re
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import PRIVATE


# ---------------------------------------------------------------------------
# A: Kernel callback array integrity
# ---------------------------------------------------------------------------
def scan_callback_integrity(vmm, add, log):
    """
    Validate PspCreate*NotifyRoutine callback pointers.

    Returns:
        (int findings, bool api_available)
    """
    n      = 0
    api_ok = False
    try:
        kcb = (
            getattr(vmm.kernel, 'notify_callbacks', None)
            or getattr(vmm.kernel, 'process_notify_routines', None)
        )
        if kcb is None:
            log('  Kernel callback array not available in this vmmpyc build -- check skipped', 'WARN')
            return 0, False

        api_ok = True
        # Build kernel module address ranges.
        kern_mods = []
        try:
            for d in vmm.maps.kdriver():
                base = d.get('base', d.get('va', 0)) or 0
                size = d.get('size', 0) or 0
                if base:
                    kern_mods.append((base, base + size))
        except Exception:
            pass

        for entry in kcb:
            ptr = int(entry) if not isinstance(entry, dict) else entry.get('va', 0)
            if ptr == 0:
                add(
                    'Critical',
                    'Kernel Callback Stripped (Memory)',
                    'PspCreateProcessNotifyRoutine',
                    'NULL pointer in kernel process-notify callback array. '
                    'EDR callback zeroed -- BYOVD driver blind spot.',
                    'T1562.001 (Impair Defenses), T1014 (Rootkit), T1068',
                )
                n += 1
                continue
            in_mod = any(lo <= ptr < hi for lo, hi in kern_mods)
            if not in_mod:
                add(
                    'Critical',
                    'Kernel Callback Redirected (Memory)',
                    f'Callback pointer {ptr:#x}',
                    f'PspCreateProcessNotifyRoutine entry {ptr:#x} does not resolve '
                    f'to any known kernel module. Pointer into anonymous allocation -- '
                    f'BYOVD callback redirect.',
                    'T1562.001, T1014, T1068',
                )
                n += 1
    except Exception as e:
        log(f'  Callback array check error: {e}', 'WARN')

    log(f'  Stripped/redirected callbacks: {n}')
    return n, api_ok


# ---------------------------------------------------------------------------
# B: ETW-Ti state
# ---------------------------------------------------------------------------
def scan_etw_ti(vmm, add, log):
    """
    Check EtwThreatIntProvRegHandle state.

    Returns:
        (int findings, bool api_available)
    """
    n      = 0
    api_ok = False
    try:
        etw_state = getattr(vmm.kernel, 'etw_ti_state', None)
        if etw_state is None:
            log('  ETW-Ti state attribute not available -- check skipped', 'WARN')
            return 0, False
        api_ok = True
        if not bool(etw_state):
            add(
                'Critical',
                'ETW Threat Intelligence Blinded (Memory)',
                'EtwThreatIntProvRegHandle',
                'ETW-Ti provider registration handle is NULL or disabled. '
                'Consistent with EtwpDebuggerData patch via BYOVD -- kernel telemetry blind.',
                'T1562.001 (Impair Defenses), T1014',
            )
            n += 1
    except Exception as e:
        log(f'  ETW-Ti check error: {e}', 'WARN')

    log(f'  ETW-Ti anomalies: {n}')
    return n, api_ok


# ---------------------------------------------------------------------------
# C: Pool-tag connection carving
# ---------------------------------------------------------------------------
def scan_pool_connections(vmm, add, log):
    """
    Carve TCPT/TCPe pool tags and diff against vmm.maps.net() OS table.

    Returns:
        (int findings, bool api_available)
    """
    n      = 0
    api_ok = False
    try:
        carved = (
            getattr(vmm, 'maps_pool', None)
            or getattr(vmm.kernel, 'pool_connections', None)
        )
        if carved is None:
            log('  Pool-tag carving not available in this vmmpyc build -- hidden connection carve skipped', 'WARN')
            return 0, False

        api_ok  = True
        os_conns: set = set()
        try:
            for conn in vmm.maps.net():
                dst   = str(conn.get('dst-ip',   '') or '')
                dport = conn.get('dst-port', 0) or 0
                src   = str(conn.get('src-ip',   '') or '')
                sport = conn.get('src-port', 0) or 0
                os_conns.add((src, sport, dst, dport))
        except Exception:
            pass

        for entry in carved:
            tag   = str(entry.get('tag', '') or '').upper()
            if tag not in ('TCPT', 'TCPE', 'UDPA'):
                continue
            dst   = str(entry.get('dst-ip',   '') or '')
            dport = entry.get('dst-port', 0) or 0
            src   = str(entry.get('src-ip',   '') or '')
            sport = entry.get('src-port', 0) or 0
            if not dst or PRIVATE.match(dst):
                continue
            if (src, sport, dst, dport) in os_conns:
                continue
            add(
                'Critical',
                'Hidden Network Connection (Pool-Tag Carve)',
                f'{src}:{sport} -> {dst}:{dport}',
                f'TCP/UDP endpoint found via pool-tag carving (tag={tag}) but absent '
                f'from vmm.maps.net() OS table. Connection has been unlinked from '
                f'tcpip.sys -- DKOM network hiding.',
                'T1014 (Rootkit), T1071 (Application Layer Protocol)',
            )
            n += 1
    except Exception as e:
        log(f'  Pool-tag carving error: {e}', 'WARN')

    log(f'  Hidden network connections (pool-tag): {n}')
    return n, api_ok


# ---------------------------------------------------------------------------
# Standalone entry point (runs all three sub-checks)
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    log = rt['log']
    vmm = rt['vmm']
    add = rt['add']

    log('=== Phase B8A: Kernel Callback Integrity (TTP-016) ===')
    scan_callback_integrity(vmm, add, log)

    log('=== Phase B8B: ETW-Ti State (TTP-016) ===')
    scan_etw_ti(vmm, add, log)

    log('=== Phase B8C: Pool-Tag Connection Carving (TTP-016) ===')
    scan_pool_connections(vmm, add, log)

    write_report(rt, 'phase_B8_kernel_integrity')
