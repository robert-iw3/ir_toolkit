#!/usr/bin/env python3
"""
Phase B4 -- TTP-007: Call-stack spoofing / synthetic frames.

Detection: threads whose callstack (where exposed by vmmpyc) contains a return
address that falls outside every loaded module. Attackers build fake return-
address chains so stack walkers see only legitimate module addresses while
execution lives in unbacked memory.

Standalone: python phase_B4_callstack_spoof.py <image.aff4> <output_dir>
Unit test:  from phase_B4_callstack_spoof import scan_callstack_spoof
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc


def scan_callstack_spoof(procs, add, log, _is_sys=None):
    """
    Walk thread callstack frames looking for return addresses outside all modules.

    Returns:
        (int findings, bool api_available)
    """
    _sys   = _is_sys if _is_sys is not None else is_system_proc
    n      = 0
    api_ok = False

    for p in procs:
        if _sys(p):
            continue
        try:
            mods    = p.module_list()
            threads = p.maps.thread()
            mod_set = [(m.base, m.base + m.image_size) for m in mods]
        except Exception:
            continue

        for t in threads:
            frames = t.get('callstack', None)
            if frames is None:
                break
            api_ok = True

            for i, frame in enumerate(frames):
                ra = frame.get('va', 0) if isinstance(frame, dict) else int(frame)
                if not ra:
                    continue
                in_mod = any(lo <= ra < hi for lo, hi in mod_set)
                if in_mod:
                    continue

                # Check if the frame ABOVE is module-backed (sandwich pattern = spoofing).
                above_clean = False
                if i > 0:
                    prev = frames[i - 1]
                    prev_va = prev.get('va', 0) if isinstance(prev, dict) else int(prev)
                    above_clean = any(lo <= prev_va < hi for lo, hi in mod_set)

                tid = t.get('tid', '?')
                sev = 'High' if above_clean else 'Medium'
                add(
                    sev,
                    'Call-Stack Spoofing / Unbacked Frame (Memory)',
                    f'PID {p.pid} ({p.name}) TID={tid}',
                    f'Return address {ra:#x} in frame {i} falls outside all loaded modules. '
                    f'{"Sandwiched by module frames -- strong spoofing indicator." if above_clean else "Isolated unbacked return address."}',
                    'T1055 (Process Injection), T1027 (Obfuscated Files)',
                )
                n += 1
                break  # one finding per thread

    if not api_ok:
        log('  callstack frames not available in this vmmpyc build -- spoof scan skipped', 'WARN')
    log(f'  Spoofed call-stack candidates: {n}')
    return n, api_ok


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B4: Call-Stack Spoofing (TTP-007) ===')
    scan_callstack_spoof(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_B4_callstack_spoof')
