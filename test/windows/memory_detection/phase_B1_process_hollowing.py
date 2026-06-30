#!/usr/bin/env python3
"""
Phase B1 -- TTP-004: Process hollowing / herpaderping / ghosting.

Detection: image-backed executable VADs whose PE header has multiple zeroed
fields (TimeDateStamp, CheckSum, SizeOfImage). Classic hollowing erases these
before writing a replacement payload into the same region.

Standalone: python phase_B1_process_hollowing.py <image.aff4> <output_dir>
Unit test:  from phase_B1_process_hollowing import scan_hollowing
"""
import sys, os, struct
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc


PE_OFF           = 0x3C          # DOS header: e_lfanew offset
PE_SIG           = b'PE\x00\x00'
# Offsets from e_lfanew:
#   +8  = TimeDateStamp (FileHeader)
#   +24 = start of OptionalHeader
#   +24+64 = CheckSum (OptionalHeader+64 for PE32+)
#   +24+56 = SizeOfImage (OptionalHeader+56 for PE32+)
_TS_OFF  = 8
_CHK_OFF = 24 + 64
_SOI_OFF = 24 + 56


def scan_hollowing(procs, add, log, _is_sys=None):
    """
    Scan image-backed executable VADs for zeroed PE header fields.

    Returns:
        int -- findings emitted
    """
    _sys = _is_sys if _is_sys is not None else is_system_proc
    n    = 0

    for p in procs:
        if _sys(p):
            continue
        try:
            vads = p.maps.vad()
        except Exception:
            continue

        for v in vads:
            typ  = str(v.get('type',       '') or '').strip().lower()
            prot = str(v.get('protection', '') or '').upper()
            addr = v.get('start', 0)

            # 'image' matches 'Image' (real vmmpyc) and 'image' (mock); drop 'mapped' filter.
            if typ != 'image':
                continue
            # 'X' catches 'EXECUTE...' (mock) and '---WXC' (real vmmpyc image sections).
            if 'X' not in prot:
                continue

            try:
                header = p.memory.read(addr, 512)
                if not header or len(header) < 256:
                    continue
                if header[0:2] != b'MZ':
                    continue
                e_lfanew = struct.unpack_from('<I', header, PE_OFF)[0]
                if not (0x40 <= e_lfanew <= 0x400):
                    continue
                if header[e_lfanew: e_lfanew + 4] != PE_SIG:
                    continue
                ts_off  = e_lfanew + _TS_OFF
                chk_off = e_lfanew + _CHK_OFF
                soi_off = e_lfanew + _SOI_OFF
                if max(ts_off, chk_off, soi_off) + 4 > len(header):
                    continue
                ts  = struct.unpack_from('<I', header, ts_off)[0]
                chk = struct.unpack_from('<I', header, chk_off)[0]
                soi = struct.unpack_from('<I', header, soi_off)[0]
                zeroed = sum(1 for x in (ts, chk, soi) if x == 0)
                if zeroed < 2:
                    continue
            except Exception:
                continue

            add(
                'High',
                'Process Hollowing Indicator (Memory)',
                f'PID {p.pid} ({p.name}) @ {addr:#x}',
                f'Image-backed executable region: {zeroed}/3 PE header fields zeroed '
                f'(TimeDateStamp={ts:#x} CheckSum={chk:#x} SizeOfImage={soi:#x}). '
                f'Consistent with hollowing erase pass before payload write.',
                'T1055.012 (Process Hollowing), T1036',
            )
            n += 1

    log(f'  Hollowing indicators: {n}')
    return n


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B1: Process Hollowing (TTP-004) ===')
    scan_hollowing(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_B1_process_hollowing')
