#!/usr/bin/env python3
"""
Phase C4 -- TTP-018: In-memory COM VTable hijacking.

Detection: image-backed data sections containing pointer-sized values that
resolve into anonymous executable regions. An attacker crafts a fake VTable
in shellcode memory and overwrites a COM interface pointer inside the process's
data segment so that standard COM method calls (Release, QueryInterface) redirect
to shellcode. No on-disk file changes occur.

Standalone: python phase_C4_com_vtable.py <image.aff4> <output_dir>
Unit test:  from phase_C4_com_vtable import scan_com_vtable
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

_PTR_SIZE  = 8
_MAX_HITS  = 3   # pointers per process before we emit and stop scanning that process


def scan_com_vtable(procs, add, log, _is_sys=None):
    """
    Scan image-backed RW sections for pointers into anonymous executable regions.

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

        # Collect anonymous executable ranges.
        anon_exec = []
        rw_image  = []
        for v in vads:
            prot  = str(v.get('protection', '') or '').upper()
            addr  = v.get('start', 0)
            end   = v.get('end', 0) or 0
            # vmmpyc uses 'end' (inclusive); mock tests use 'size'.
            size  = max(0, end - addr + 1) if end else (v.get('size', 0) or 0)
            # Strip spaces: real vmmpyc '     '=private, 'Image'/'File '/'Pf   '=backed.
            typ_s = str(v.get('type', '') or '').strip().lower()
            # Private/anonymous = no type string (real) or 'private' (mock); not image/file/pf.
            is_private = not typ_s or typ_s == 'private'
            # 'X' catches 'EXECUTE...' (mock) and '---WXC'/'p-r-x-' (real vmmpyc).
            if 'X' in prot and is_private:
                anon_exec.append((addr, addr + size))
            elif typ_s == 'image' and 'W' in prot:
                rw_image.append((addr, size))

        if not anon_exec or not rw_image:
            continue

        hits = []
        for (sec_addr, sec_size) in rw_image:
            if sec_size < _PTR_SIZE or sec_size > 0x100000:
                continue
            try:
                data = p.memory.read(sec_addr, min(sec_size, 4096))
                if not data or len(data) < _PTR_SIZE:
                    continue
            except Exception:
                continue

            for off in range(0, len(data) - _PTR_SIZE, _PTR_SIZE):
                val = int.from_bytes(data[off: off + _PTR_SIZE], 'little')
                if val < 0x10000:
                    continue
                for lo, hi in anon_exec:
                    if lo <= val < hi:
                        hits.append((sec_addr + off, val))
                        break
                if len(hits) >= _MAX_HITS:
                    break
            if hits:
                break

        if not hits:
            continue

        sample = ', '.join(f'{src:#x}->{dst:#x}' for src, dst in hits)
        add(
            'Medium',
            'COM VTable Pointer to Anon-Exec Region (Memory)',
            f'PID {p.pid} ({p.name})',
            f'Image-backed data section contains {len(hits)} pointer(s) into anonymous '
            f'executable region(s). Consistent with in-memory COM VTable hijacking. '
            f'Corroborate: YARA the target exec region. Pointers: {sample}',
            'T1574 (Hijack Execution Flow), T1055 (Process Injection)',
        )
        n += 1

    log(f'  COM VTable hijacking candidates: {n}')
    return n


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase C4: COM VTable Hijacking (TTP-018) ===')
    scan_com_vtable(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_C4_com_vtable')
