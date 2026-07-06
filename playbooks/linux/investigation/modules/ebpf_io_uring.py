"""Module 7 -- eBPF / io_uring anti-EDR surface.

Toolkit signals: eBPF Network C2 Correlated (memory), eBPF Object Held By
Implant, Pinned eBPF Objects (verify), io_uring Anti-EDR I/O (memory/live),
io_uring In Use (memory, verify) / (verify).

From DETAILED-FOLLOW-ON-LINUX.md Section 7 and the Quick Reference FP table:
io_uring on a known service (nginx/postgres/systemd/...) is legitimate
high-performance I/O and is *designed to be downgraded, not suppressed*.
eBPF Network C2 Correlated is already a cross-plugin correlation upstream
(network-hook eBPF + hooked netfilter co-occurring) -- treat it as Tier 1.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier
from ..models.linux_noise import IO_URING_EXPECTED, OBSERVABILITY_AGENTS


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    target = finding.get('Target', '')

    if ftype == 'eBPF Network C2 Correlated (memory)':
        return [Dimension(
            name='M7_eBPF_C2_Correlated', positive=True, source_module=7, tier=Tier.DEFINITIVE,
            rationale=(f'{ftype}: a network-hook eBPF program co-occurs with a hooked netfilter '
                       f'hook -- bpfdoor-class magic-packet C2 pattern, already correlated across '
                       f'two independent kernel surfaces upstream. {details[:180]}')
        )]

    if 'io_uring' in ftype:
        is_verify = 'verify' in ftype.lower()
        comm = next((w.strip('()') for w in target.split() if '(' in w), '').lower()
        expected = comm in IO_URING_EXPECTED
        if is_verify and expected:
            return [Dimension(
                name='M7_ioUring_ExpectedService', positive=False, source_module=7,
                tier=Tier.WEAK_STRUCTURAL,
                rationale=f'{ftype}: owning process {comm!r} has documented legitimate io_uring '
                          'use -- downgraded per design, confirm binary path before final FP close.'
            )]
        if is_verify:
            return [Dimension(
                name='M7_ioUring_Unattributed', positive=True, source_module=7,
                tier=Tier.WEAK_STRUCTURAL,
                rationale=f'{ftype}: {details[:160]} -- ring holder is not a documented '
                          'io_uring-using service; capability without demonstrated abuse yet.'
            )]
        # "Anti-EDR I/O" (non-verify): the collector already applied writable-path/
        # deleted-binary corroboration before emitting this type.
        return [Dimension(
            name='M7_ioUring_AntiEDR', positive=True, source_module=7, tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:200]} -- io_uring used from a writable-path/deleted '
                      'binary to bypass syscall-based EDR hooking.'
        )]

    if ftype == 'eBPF Program (memory)':
        # Baseline listing: every loaded eBPF program is flagged (every type is
        # abusable), so plain presence is ambiguous by design -- only escalate
        # when the collector's own severity says High/Critical (it already
        # checked for process/file/network-hiding name/tag patterns).
        #
        # A loader-name match against OBSERVABILITY_AGENTS is NOT used to
        # override that escalation down to WEAK_STRUCTURAL: the loader name is
        # attacker-controlled (comm/argv[0]) and this finding carries no path
        # to verify identity against. Downgrading a collector-escalated
        # High/Critical hit purely on a name string would let an implant
        # calling itself "falco" or "cilium-agent" silently drop the exact
        # dimension that would otherwise count toward the TP threshold --
        # kept as context in the rationale only.
        agent_match = next((a for a in OBSERVABILITY_AGENTS if a in details.lower()), None)
        severity = finding.get('Severity', 'Medium')
        context = (f' NOTE: loader name matches known agent {agent_match!r} -- name match only, '
                   'not verified against the real binary path; not auto-downgraded.'
                  ) if agent_match else ''
        if severity in ('High', 'Critical'):
            return [Dimension(
                name='M7_eBPF_Program_HidingPattern', positive=True, source_module=7,
                tier=Tier.STRONG_BEHAVIORAL,
                rationale=(f'{ftype}: {details[:200]} -- collector escalated to {severity}: name/tag '
                          f'matches a process/file/network-hiding pattern.{context}')
            )]
        return [Dimension(
            name='M7_eBPF_Program_Baseline', positive=True, source_module=7,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=(f'{ftype}: {details[:200]} -- baseline listing; every eBPF program type is '
                      f'abusable, so presence alone is not escalatory.{context}')
        )]

    # eBPF Object Held By Implant / Pinned eBPF Objects (verify) -- same
    # rationale as above: a loader-name match is context, not an automatic
    # downgrade, since it would otherwise let a same-named implant suppress
    # its own detection.
    agent_match = next((a for a in OBSERVABILITY_AGENTS if a in details.lower()), None)
    context = (f' NOTE: loader matches known agent {agent_match!r} -- name match only, not '
              'verified against the real binary path; not auto-downgraded.') if agent_match else ''
    return [Dimension(
        name='M7_eBPF_Unattributed', positive=True, source_module=7, tier=Tier.STRONG_BEHAVIORAL,
        rationale=f'{ftype}: {details[:200]} -- eBPF program/pinned object.{context}'
    )]
