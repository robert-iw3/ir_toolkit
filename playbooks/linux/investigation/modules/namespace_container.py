"""Module 8 -- namespace escape / container breakout.

Toolkit signals: Namespace Escape (memory), Bind Mount Over System Path
(memory), plus container_hunt.py's static-posture findings (Container Host
Namespace, Docker Socket Mount, Privileged Container, Sensitive Host Mount,
Dangerous Container Capabilities, Pod Host Namespace, Pod hostPath Mount,
Privileged Pod Container, Pod Privilege Escalation Allowed, Pod Dangerous
Capabilities, ClusterAdmin Binding).

From DETAILED-FOLLOW-ON-LINUX.md Section 8: a task containerized in some
namespaces but sharing the HOST namespace in others is a breakout/host-reach
indicator unless it's a known monitoring sidecar that intentionally shares
host ns -- the guide's own wording is "FP after confirming the container's
purpose," not an automatic close. The memory-sourced runtime signals (actual
observed ns sharing) are stronger than container_hunt.py's posture findings
(a privileged container config is a capability, not proof it was used
maliciously) -- posture findings are Tier 3 (weak/structural) on their own.

A common real-world source of "Namespace Escape (memory)" is systemd's own
per-service sandboxing (`PrivateMounts=`/`ProtectSystem=`) on ordinary
daemons (systemd-oomd, NetworkManager, bluetoothd, etc.), not container
escape. This is deliberately NOT auto-downgraded on a `comm` name match: this
finding's Target/Details carry no executable path to verify against, `comm`
is attacker-controlled (`prctl(PR_SET_NAME)`, argv[0]), and this dimension is
one of the few STRONG_BEHAVIORAL signals namespace-escape findings can
contribute -- downgrading on name alone would let an implant named
`systemd-udevd` or `falco` drop out of the evidence count needed to cross the
TP threshold. The name is recorded as context for the analyst, not used to
change tier or polarity. Real corroboration for "is this the packaged
daemon" comes from `correlator.py`'s package-integrity check
(Adjudication_*.json's PkgOwner/PkgModified/FileExists) when available --
that verifies the actual binary, not a string an attacker controls.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension, Tier
from ..models.linux_noise import OBSERVABILITY_AGENTS, KNOWN_SYSTEM_PROCESSES

_RUNTIME_TYPES = {'Namespace Escape (memory)', 'Bind Mount Over System Path (memory)'}
# Posture-only findings from container_hunt.py: a capability, not demonstrated use.
_POSTURE_TYPES = {
    'Container Host Namespace', 'Docker Socket Mount', 'Privileged Container',
    'Sensitive Host Mount', 'Dangerous Container Capabilities', 'Pod Host Namespace',
    'Pod hostPath Mount', 'Privileged Pod Container', 'Pod Privilege Escalation Allowed',
    'Pod Dangerous Capabilities', 'ClusterAdmin Binding',
}
# Docker-socket mount and ClusterAdmin binding are one step from full host/cluster
# compromise by design (mount the socket, launch a privileged container) -- these
# earn STRONG_BEHAVIORAL instead of WEAK_STRUCTURAL even without demonstrated use.
_HIGH_IMPACT_POSTURE = {'Docker Socket Mount', 'ClusterAdmin Binding', 'Privileged Container'}


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    target = finding.get('Target', '')

    if ftype in _RUNTIME_TYPES:
        comm_m = re.search(r'\(([^)]+)\)', target)
        comm = (comm_m.group(1) if comm_m else '').lower()
        context = ''
        if comm in OBSERVABILITY_AGENTS:
            context = (f' NOTE: {comm!r} matches a known observability/security agent name -- '
                       'commonly legitimate (hostPID/hostNetwork sidecar pattern), but this is a '
                       'name match only (no path in this finding to verify against, and comm is '
                       'attacker-controlled) -- NOT auto-downgraded; check the real binary path/'
                       'package before closing.')
        elif comm in KNOWN_SYSTEM_PROCESSES:
            context = (f' NOTE: {comm!r} matches a known core system daemon name -- commonly '
                       'systemd\'s own per-service sandboxing (PrivateMounts=/ProtectSystem=), not '
                       'container escape, but this is a name match only (attacker-controlled, no '
                       'path to verify here) -- NOT auto-downgraded; check the real binary path/'
                       'package before closing.')
        return [Dimension(
            name='M8_NamespaceEscape_Runtime', positive=True, source_module=8,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: {details[:220]} -- observed runtime namespace/mount anomaly, '
                      f'not just a configuration capability.{context}')
        )]

    if ftype in _POSTURE_TYPES:
        tier = Tier.STRONG_BEHAVIORAL if ftype in _HIGH_IMPACT_POSTURE else Tier.WEAK_STRUCTURAL
        return [Dimension(
            name='M8_ContainerPosture', positive=True, source_module=8, tier=tier,
            rationale=f'{ftype}: {details[:200]} -- configuration-level exposure; confirm this is '
                      'not an intentional monitoring/CI sidecar before escalating.'
        )]

    return [Dimension(
        name='M8_NamespaceContainer_Other', positive=True, source_module=8,
        tier=Tier.STRONG_BEHAVIORAL, rationale=f'{ftype}: {details[:200]}'
    )]
