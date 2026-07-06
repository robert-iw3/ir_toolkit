"""Module 2 -- hidden process (DKOM / /proc listing suppression).

Toolkit signals: Hidden Process (memory), Hidden Process.

edr_hunt.py's live check already re-confirms against a fresh listing to rule
out a race (process that merely spawned after the first snapshot); the
memory engine's check (analyze_memory_linux.py's analyze_processes()) compares
the kernel's PID HASHTABLE -- a live lookup structure the kernel actively
maintains for every currently-valid PID -- against pslist's linked-list walk.
This is deliberately not a psscan-vs-pslist comparison: psscan finds
task_struct-shaped byte patterns anywhere in physical memory, including
freed-but-not-yet-reused slab remnants from an already-EXITED process, which
would be a false "hidden process" with no rootkit involved. The pidhashtable
only contains genuinely live PIDs, so a PID present there but absent from the
pslist walk is a real list-unlinking (DKOM) result, not a stale-memory
artifact. Tier 1 (DEFINITIVE): no benign mechanism produces that asymmetry.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    is_memory = 'memory' in ftype.lower()
    return [Dimension(
        name='M2_HiddenProcess', positive=True, source_module=2,
        tier=Tier.DEFINITIVE,
        rationale=(
            f'{ftype}: task present in the kernel/PID-hashtable view but absent from '
            f'{"pslist" if is_memory else "/proc listing"} -- DKOM/unlink rootkit hiding a '
            f'running process. No benign mechanism produces this asymmetry. {details[:200]}'
        )
    )]
