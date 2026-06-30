#!/usr/bin/env python3
"""
Phase B9 -- TTP-017: PEB command-line pointer integrity (Cobalt Strike Argue).

Detection (memory side): verify that PEB.RtlUserProcessParameters->CommandLine.Buffer
points into a valid VAD region. A dangling pointer indicates PEB tampering or the
buffer was freed/remapped post-launch.

The cross-reference against creation-time cmdline from processes.csv is handled
in the companion Pester test (Get-FindingContext.ps1 augmentation).

Standalone: python phase_B9_peb_cmdline.py <image.aff4> <output_dir>
Unit test:  from phase_B9_peb_cmdline import scan_peb_cmdline
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

# x64 PEB offsets
_PEB_PROC_PARAMS_OFF = 0x20   # PEB->ProcessParameters pointer
_RTLUP_CMDLINE_OFF   = 0x70   # ProcessParameters->CommandLine (UNICODE_STRING)
_UNICODE_BUF_OFF     = 0x08   # UNICODE_STRING.Buffer (after Length+MaxLength)


def scan_peb_cmdline(procs, add, log, _is_sys=None):
    """
    Validate PEB CommandLine.Buffer pointer is mapped for each user process.

    Returns:
        (int findings, bool api_available)
    """
    _sys   = _is_sys if _is_sys is not None else is_system_proc
    n      = 0
    api_ok = False

    for p in procs:
        if _sys(p):
            continue

        peb_addr = None
        try:
            peb_addr = getattr(p, 'peb', None) or getattr(p, 'peb_address', None)
        except Exception:
            pass
        if peb_addr is None:
            if not api_ok:
                break
            continue

        api_ok = True

        try:
            # Read ProcessParameters pointer.
            pp_bytes = p.memory.read(peb_addr + _PEB_PROC_PARAMS_OFF, 8)
            if not pp_bytes or len(pp_bytes) < 8:
                continue
            pp_ptr = int.from_bytes(pp_bytes, 'little')
            if pp_ptr < 0x10000:
                continue

            # Read CommandLine.Buffer pointer.
            cl_bytes = p.memory.read(pp_ptr + _RTLUP_CMDLINE_OFF + _UNICODE_BUF_OFF, 8)
            if not cl_bytes or len(cl_bytes) < 8:
                continue
            cl_buf = int.from_bytes(cl_bytes, 'little')
            if cl_buf < 0x10000:
                continue

            # Verify the buffer is mapped (falls inside a known VAD).
            # vmmpyc uses 'end' (inclusive end addr); mock tests use 'size' (byte count).
            vads = p.maps.vad()
            in_vad = False
            for v in vads:
                s = v.get('start', 0)
                e = v.get('end', 0)
                z = v.get('size', 0) or 0
                if e:
                    if s <= cl_buf <= e:
                        in_vad = True
                        break
                elif z:
                    if s <= cl_buf < s + z:
                        in_vad = True
                        break
            if in_vad:
                continue

            add(
                'High',
                'PEB CommandLine Buffer Pointer Anomaly (Memory)',
                f'PID {p.pid} ({p.name})',
                f'PEB.RtlUserProcessParameters->CommandLine.Buffer={cl_buf:#x} does not '
                f'resolve to any mapped VAD region. PEB tampered or cmdline buffer '
                f'was freed/remapped post-launch (TTP-017 Argue variant).',
                'T1055.012 (Process Doppelganging), T1036 (Masquerading)',
            )
            n += 1
        except Exception:
            continue

    if not api_ok:
        log('  PEB address not exposed by this vmmpyc build -- cmdline pointer check skipped', 'WARN')
    log(f'  PEB cmdline pointer anomalies: {n}')
    return n, api_ok


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B9: PEB CommandLine Pointer Integrity (TTP-017) ===')
    scan_peb_cmdline(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_B9_peb_cmdline')
