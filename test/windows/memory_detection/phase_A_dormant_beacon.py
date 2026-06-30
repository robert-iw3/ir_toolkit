#!/usr/bin/env python3
"""
Phase A -- TTP-009 / TTP-014: Encrypted dormant regions (Gargoyle, Ekko, Foliage).

Detection: private committed RW regions with high Shannon entropy.
A beacon resting between execution windows has NO execute flag at snapshot time --
invisible to every EXECUTE-based scanner. Only entropy exposes it.

Standalone: python phase_A_dormant_beacon.py <image.aff4> <output_dir>
Unit test:  from phase_A_dormant_beacon import scan_dormant_beacons
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import (
    entropy, is_system_proc, BEACON_MIN, BEACON_MAX, ENTROPY_THRESHOLD,
    HIGH_ENT_PROCS,
)


# ==============================================================================
# Detection function (no vmmpyc dependency -- fully unit-testable)
# ==============================================================================
def scan_dormant_beacons(procs, add, log, _is_sys=None):
    """
    Scan all process VADs for high-entropy private RW regions.

    Args:
        procs:   iterable of vmmpyc process objects (or mocks)
        add:     callable(severity, ftype, target, details, mitre)
        log:     callable(msg, level='INFO')
        _is_sys: override for is_system_proc (used by unit tests)

    Returns:
        int -- number of findings emitted
    """
    _sys = _is_sys if _is_sys is not None else is_system_proc
    n    = 0

    for p in procs:
        if _sys(p):
            continue
        # Skip processes where high-entropy private RW is structurally expected
        # (AV signature databases, crypto key isolation).  All other phases still
        # scan these processes.
        if p.name.lower() in HIGH_ENT_PROCS:
            log(f'  A: PID {p.pid} ({p.name}) -- known high-entropy process; skipping entropy scan')
            continue
        try:
            vads = p.maps.vad()
        except Exception:
            continue

        # Pass 1: collect anonymous executable VAD ranges for adjacency check.
        # An Ekko loader stub lives in an anon-exec region adjacent to its encrypted payload.
        _ADJ = 65536  # 64 KB proximity window
        anon_exec_ranges = []
        for v in vads:
            prot_v = str(v.get('protection', '') or '').upper()
            typ_v  = str(v.get('type',       '') or '').strip().lower()
            if 'X' not in prot_v:
                continue
            if typ_v and typ_v != 'private':
                continue  # only anonymous/private exec; skip image-backed
            s_v = v.get('start', 0)
            e_v = v.get('end', 0) or 0
            z_v = max(0, e_v - s_v + 1) if e_v else (v.get('size', 0) or 0)
            if z_v > 0:
                anon_exec_ranges.append((s_v, s_v + z_v))

        # Pass 2: beacon scan.
        for v in vads:
            prot = str(v.get('protection', '') or '').upper()
            addr = v.get('start', 0)
            end  = v.get('end', 0) or 0
            # vmmpyc uses 'end' (inclusive); mock tests use 'size'
            size = max(0, end - addr + 1) if end else (v.get('size', 0) or 0)
            # Strip spaces: real vmmpyc uses '     ' for private, 'Image'/'File '/'Pf   ' for others
            typ_s = str(v.get('type', '') or '').strip().lower()

            # Private committed RW only -- not executable, not image/file/pagefile-backed.
            # 'X' catches both 'EXECUTE...' (mock) and '---WXC'/'p-r-x-' (real vmmpyc).
            if 'X' in prot:
                continue
            # Accept only private/anonymous: '' (real) or 'private' (mock); skip Image/File/Pf/mapped.
            if typ_s and typ_s != 'private':
                continue
            # 'W' catches 'READWRITE' (mock) and 'p-rw--'/'--rw--' (real vmmpyc).
            if 'W' not in prot:
                continue
            if not (BEACON_MIN <= size <= BEACON_MAX):
                continue

            try:
                sample = p.memory.read(addr, min(size, 8192))
                if not sample or len(sample) < 512:
                    continue
                ent = entropy(sample)
            except Exception:
                continue

            if ent < ENTROPY_THRESHOLD:
                continue

            # Byte-distribution corroboration.
            # CV (coefficient of variation) of per-byte frequencies across 256 buckets:
            #   CV < 15% => very uniform => XOR/AES encrypted shellcode-likely
            #   CV 15-40% => moderately uniform => compressed data or mixed
            #   CV > 40%  => non-uniform => strings / structured data => benign hint
            freq = [0] * 256
            for b in sample:
                freq[b] += 1
            expected = len(sample) / 256.0
            cv_pct = (sum((f - expected) ** 2 for f in freq) / 256.0) ** 0.5 / expected * 100
            ascii_pct = sum(1 for b in sample if 0x20 <= b <= 0x7e) / len(sample) * 100
            has_mz = b'\x4d\x5a' in sample[:512]   # MZ PE remnant
            # First 16 bytes hex for analyst triage
            head_hex = sample[:16].hex(' ')

            if cv_pct < 15:
                distrib_label = 'UNIFORM(crypto-likely)'
            elif cv_pct < 40:
                distrib_label = 'moderate'
            else:
                distrib_label = 'non-uniform(data-likely)'

            # Adjacency: any anonymous EXECUTE region within _ADJ bytes is the loader/stub.
            region_end = addr + size
            adj_exec = any(
                lo < region_end + _ADJ and hi > addr - _ADJ
                for lo, hi in anon_exec_ranges
            )

            # High when in the common beacon stage range (4-256 KB).
            sev = 'High' if size <= 262144 else 'Medium'
            add(
                sev,
                'Dormant Beacon Candidate (Memory)',
                f'PID {p.pid} ({p.name}) @ {addr:#x}',
                f'Private RW region entropy={ent:.2f} size={size} bytes. '
                f'No execute flag at snapshot time -- consistent with sleep-mask '
                f'or Gargoyle W^X beacon resting between execution windows. '
                f'Prot={prot}. '
                f'ByteDistrib: CV={cv_pct:.0f}% [{distrib_label}] '
                f'ASCII={ascii_pct:.0f}% '
                f'MZ-remnant={has_mz} '
                f'AdjAnonExec={adj_exec} '
                f'Head={head_hex}. '
                f'Corroborate: APC/timer targeting this address.',
                'T1027 (Obfuscated Files), T1055 (Process Injection), T1027.013',
            )
            n += 1
            if n >= 50:
                break
        if n >= 50:
            break

    log(f'  Dormant beacon candidates: {n}')
    return n


# ==============================================================================
# Standalone live-test entry point
# ==============================================================================
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])

    rt['log']('=== Phase A: Dormant Beacon / W^X Region Scan (TTP-009/014) ===')
    scan_dormant_beacons(rt['procs'], rt['add'], rt['log'])

    write_report(rt, 'phase_A_dormant_beacon')
