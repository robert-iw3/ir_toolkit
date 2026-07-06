"""Module 16 -- ptrace attachment.

Toolkit signals: Ptrace Attachment (memory), Ptrace Injection - Thread IP in
Injected Memory (memory), Corroborated Injected Thread (memory+live).

A tracer attached to a process is dual-use (gdb/strace debugging is normal;
a tracer attached to sshd/lsass-equivalent credential-bearing processes, or
one with an untrusted backing path, is credential-dumping/injection shaped).
This module cannot see the tracer's own path from the finding text alone in
every case, so plain attachment stays at STRONG_BEHAVIORAL pending that
corroboration rather than assuming malice from the mechanism alone.

"Ptrace Injection" is a different, stronger fact: the traced thread's OWN
instruction pointer is observed (out-of-band, from the memory image)
executing inside anonymous/unbacked memory. A debugger reads/writes a
tracee; it doesn't put the tracee's IP register inside anonymous memory
unless the tracee is genuinely running injected code. Tier 1 (DEFINITIVE).

"Corroborated Injected Thread" is the same underlying fact reached a second,
independent way: thread_inventory.py's live TID enumeration matched a TID
analyze_memory_linux.py's pscallstack analysis already flagged with a stack
frame returning into unbacked memory. Two independent mechanisms (kernel
stack walk from the memory image, live /proc enumeration) agreeing on the
same TID is at least as strong as the single memory-derived fact above --
also Tier 1 (DEFINITIVE).
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    target = finding.get('Target', '')

    if ftype == 'Corroborated Injected Thread (memory+live)':
        return [Dimension(
            name='M16_Ptrace_CorroboratedInjectedThread', positive=True, source_module=16,
            tier=Tier.DEFINITIVE,
            rationale=(f'{ftype}: {details[:220]} -- independently confirmed by both a '
                       'memory-forensic kernel-stack walk and live /proc enumeration.')
        )]

    if 'Ptrace Injection' in ftype:
        return [Dimension(
            name='M16_Ptrace_InjectionConfirmed', positive=True, source_module=16,
            tier=Tier.DEFINITIVE,
            rationale=(f'{ftype}: {details[:220]} -- traced thread\'s instruction pointer is '
                       'executing inside anonymous/unbacked memory, observed out-of-band. Active '
                       'shellcode/payload injection via ptrace, not routine debugging.')
        )]

    sensitive_target = any(s in (target + details).lower()
                           for s in ('sshd', 'gpg-agent', 'ssh-agent', 'vault', 'keyring'))
    return [Dimension(
        name='M16_Ptrace_Attachment', positive=True, source_module=16,
        tier=Tier.STRONG_BEHAVIORAL if sensitive_target else Tier.WEAK_STRUCTURAL,
        rationale=(f'{ftype}: {details[:220]}' +
                  (' -- tracer attached to a credential-bearing process.' if sensitive_target
                   else ' -- dual-use (debugging tools attach routinely); confirm the tracer\'s '
                        'own provenance before escalating.'))
    )]
