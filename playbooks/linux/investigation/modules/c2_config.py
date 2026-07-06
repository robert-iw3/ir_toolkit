"""Module 18 -- recovered C2/implant configuration (memory_enrich.py +
c2_config_extract.py output).

Toolkit signals (dynamic Type strings): 'C2 Config Recovered (<Family>)',
'BPFDoor Config Artifact (memory)', 'Botnet Config Recovered (memory)', 'SSH
Backdoor Artifact (memory)', 'Cryptominer Config Recovered (memory)',
'Cryptominer C2 (memory)', 'Cryptominer Wallet (memory)', 'Exfiltration
Channel (memory)', 'Cloud Credential in Memory', 'Private Key Material
(memory)', 'Tor C2 (memory)', 'C2 Endpoint (memory)', 'Memory Capabilities
(capa)' is routed separately (Module 12).

These findings are the product of a recovery pipeline that already applied
structural/mechanism gates (see c2_config_extract.py's docstring: XOR-table
detection for Mirai, keyutils/network capability mismatch for Ebury-class,
protocol-required field names for the named C2 frameworks, magic-sequence
match for BPFDoor) -- by the time a finding of this Type exists, the
identification work is done. This module's only job is tiering by how
unforgeable the underlying mechanism was.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier

# Mechanism-gated recoveries where the underlying check is a structural
# capability-mismatch or protocol-invariant match (see c2_config_extract.py) --
# effectively as strong as a named-framework config recovery gets without
# live kernel corroboration.
_DEFINITIVE_PREFIXES = ('SSH Backdoor Artifact', 'BPFDoor Config Artifact')
_STRONG_PREFIXES = (
    'C2 Config Recovered', 'Botnet Config Recovered', 'Cryptominer Config Recovered',
    'Cryptominer C2', 'Exfiltration Channel', 'Cloud Credential in Memory',
    'Tor C2', 'C2 Endpoint',
)
_WEAK_PREFIXES = ('Cryptominer Wallet', 'Private Key Material')


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype.startswith(_DEFINITIVE_PREFIXES):
        return [Dimension(
            name='M18_C2Config_MechanismGated', positive=True, source_module=18,
            tier=Tier.DEFINITIVE,
            rationale=(f'{ftype}: {details[:220]} -- recovered via a structural capability-'
                       f'mismatch or protocol-invariant match (see c2_config_extract.py); no '
                       f'benign object produces this shape.')
        )]

    if ftype.startswith(_STRONG_PREFIXES):
        return [Dimension(
            name='M18_C2Config_Recovered', positive=True, source_module=18,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:220]}'
        )]

    if ftype.startswith(_WEAK_PREFIXES):
        return [Dimension(
            name='M18_C2Config_WeakArtifact', positive=True, source_module=18,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- a wallet/key fragment alone doesn\'t confirm '
                      'active C2; corroborate with the owning process\'s other findings.'
        )]

    return [Dimension(
        name='M18_C2Config_Other', positive=True, source_module=18,
        tier=Tier.STRONG_BEHAVIORAL, rationale=f'{ftype}: {details[:200]}'
    )]
