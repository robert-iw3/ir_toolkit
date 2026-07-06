"""Module 4 -- reverse shell / offensive tooling / suspicious execution.

Toolkit signals: Reverse Shell (memory), Reverse Shell, Offensive Tooling
(memory), Service-Spawned Shell, Suspicious Process Execution, Webshell,
Reverse Shell Indicator, Suspicious Sudo Command, Unauthorized Sudo Attempt.

These are already command-line/behavior matches from the collector (regex
against argv or a sudo log line) -- the module's job is less "is this
suspicious" (the collector already decided that) and more "is this
corroborated enough to cross the TP threshold on its own," since a single
regex hit on a command line is Tier 2, not Tier 1: false positives happen
(a pentest tool intentionally run by an authorized tester, a string that
coincidentally matches a GTFOBins pattern in a benign script).

analyze_memory_linux.py's own REVSHELL_RE bundles `socat\\b` into the same
match class as `bash -i`/`/dev/tcp/`/`nc -e` -- but bare socat is one of the
most common legitimate sysadmin tools (port forwarding, protocol bridging,
container network debugging) and its mere presence in a command line proves
nothing on its own; only socat invoked WITH an exec/system/pty argument is a
reverse-shell shape. The collector doesn't make that distinction at match
time, so this module reads the captured command-line text back out of
Details to make it -- taking the collector's classification at face value
here would flag routine `socat TCP-LISTEN:...,fork TCP:...` proxying as a
near-TP-grade finding.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension, Tier

# Types whose collector-side match is already high-fidelity enough to be
# DEFINITIVE on its own -- an actual reverse-shell command line or webshell
# content match has no benign explanation once corroborated by nothing else
# still being wrong (kept at STRONG_BEHAVIORAL, not DEFINITIVE, because a
# string match can be a copy-pasted example in a doc/comment/test fixture).
_HIGH_FIDELITY_TYPES = {
    'Reverse Shell (memory)', 'Reverse Shell', 'Reverse Shell Indicator', 'Webshell',
}

# Unambiguous reverse-shell command-line patterns: essentially no legitimate
# sysadmin use produces these exact shapes.
_UNAMBIGUOUS_RE = re.compile(
    r'bash\s+-i|/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|mkfifo\b.*\bnc\b|'
    r'import\s+socket', re.IGNORECASE)
# socat is legitimate dual-use (proxying/tunneling); only becomes a reverse-
# shell shape when paired with a shell-spawning argument.
_SOCAT_RE = re.compile(r'\bsocat\b', re.IGNORECASE)
_SOCAT_SHELL_ARG_RE = re.compile(r'exec:|system:|pty\b|/bin/(ba)?sh', re.IGNORECASE)


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype in _HIGH_FIDELITY_TYPES:
        if _SOCAT_RE.search(details) and not _UNAMBIGUOUS_RE.search(details):
            if _SOCAT_SHELL_ARG_RE.search(details):
                return [Dimension(
                    name='M4_ShellTooling_HighFidelity', positive=True, source_module=4,
                    tier=Tier.STRONG_BEHAVIORAL,
                    rationale=f'{ftype}: socat invoked with a shell-spawning argument (exec:/system:/'
                              f'pty/shell path) -- reverse-shell shape, not ordinary proxying. {details[:180]}'
                )]
            return [Dimension(
                name='M4_ShellTooling_SocatAmbiguous', positive=True, source_module=4,
                tier=Tier.WEAK_STRUCTURAL,
                rationale=(f'{ftype}: socat present but with no exec:/system:/pty/shell argument in '
                           f'the captured command line -- socat is common legitimate tooling '
                           f'(port forwarding, protocol bridging); this alone does not distinguish '
                           f'a reverse shell from ordinary proxying. {details[:180]}')
            )]
        return [Dimension(
            name='M4_ShellTooling_HighFidelity', positive=True, source_module=4,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: reverse-shell/webshell command-line or content pattern matched -- '
                      f'{details[:200]}'
        )]

    if ftype == 'Offensive Tooling (memory)':
        return [Dimension(
            name='M4_OffensiveTooling', positive=True, source_module=4,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: known offensive tool invocation in command line -- {details[:200]}'
        )]

    if ftype in ('Suspicious Sudo Command', 'Unauthorized Sudo Attempt', 'Sudo Authentication Failure'):
        return [Dimension(
            name='M4_SuspiciousSudo', positive=True, source_module=4,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- a single sudo log line needs corroboration '
                      '(who, from where, followed by what) before this alone is actionable.'
        )]

    # Service-Spawned Shell / Suspicious Process Execution: context-dependent
    return [Dimension(
        name='M4_SuspiciousExecution', positive=True, source_module=4,
        tier=Tier.STRONG_BEHAVIORAL,
        rationale=f'{ftype}: {details[:200]}'
    )]
