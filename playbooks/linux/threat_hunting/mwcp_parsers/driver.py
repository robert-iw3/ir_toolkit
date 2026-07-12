"""Driver: runs every family parser across every category over one region's bytes and
converts hits into the common finding schema.

Usage:
    from mwcp_parsers.driver import extract_all, to_findings
    hits = extract_all(data)              # [{'family': 'Sliver', 'fields': {...}}, ...]
    findings = to_findings(hits, where)   # common-schema findings list
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List

from . import c2_frameworks, cloud_saas, delivery, native, ransomware, specialized

# Every (identify-implicit) single-hit extractor, across every category. Order doesn't
# matter -- extract_all() never suppresses; multiple families can legitimately hit the
# same region (a rule grazing shared library bytes, or a genuinely multi-stage
# implant), and every hit is surfaced for the analyst/adjudicator to weigh.
_FAMILY_EXTRACTORS = tuple(
    m.extract for pkg in (c2_frameworks, native, ransomware, cloud_saas, delivery, specialized)
    for m in pkg.MODULES
)

# Multi-hit extractors (return a list, not Optional[dict]) -- handled separately.
_MULTI_HIT_EXTRACTORS = (native.smtp_exfil.extract,)


def extract_all(data: bytes) -> List[Dict[str, Any]]:
    """Run every family parser over one region's bytes. Returns a list of per-family
    config dicts (never suppresses -- multiple families can 'hit' the same region if a
    rule grazes shared library bytes; each hit is surfaced and left for the
    analyst/adjudicator to weigh)."""
    if not data:
        return []
    hits = []
    for fn in _FAMILY_EXTRACTORS:
        try:
            r = fn(data)
        except Exception:
            r = None
        if r:
            hits.append(r)
    for fn in _MULTI_HIT_EXTRACTORS:
        try:
            hits.extend(fn(data) or [])
        except Exception:
            pass
    return hits


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# Per-family Type/Severity/MITRE overrides. Families not listed fall through to the
# generic "structured config recovered" finding shape. 'type' is a template taking
# {source} -- extract_all()/to_findings() run against BOTH memory-carved regions
# (memory_enrich.py) and live on-disk binaries (edr_hunt.py's structural-config check),
# so the Type string must say which one actually happened, not hardcode "memory".
_FAMILY_FINDING_SPEC = {
    'SMTP-Exfil': {
        'severity': 'High', 'type': 'Exfiltration Channel ({source})',
        'target': lambda h, where: f"{h['host']}:{h['port']}",
        'details': lambda h, where: (
            f"SMTP exfil credentials recovered from {where}: "
            f"host={h['host']}:{h['port']} user={h.get('user') or '?'} pass={h['password']}"),
        'mitre': 'T1567 (Exfiltration Over Web Service)',
    },
    'Miner (XMRig-class)': {
        'severity': 'High', 'type': 'Cryptominer Config Recovered ({source})',
        'target': lambda h, where: (h['pools'][0] if h['pools'] else where),
        'details': lambda h, where: (
            f"XMRig-class miner config recovered from {where}: pools={h['pools']} "
            f"algo={h.get('algo') or '?'} wallets={h.get('wallets_cli') or []} "
            f"donate-level={h.get('donate_level')}"),
        'mitre': 'T1496 (Resource Hijacking)',
    },
    'BPFDoor': {
        'severity': 'Critical', 'type': 'BPFDoor Config Artifact ({source})',
        'target': lambda h, where: where,
        'details': lambda h, where: (
            f"BPFDoor-class magic-packet trigger sequence recovered from {where}: "
            f"magic={h.get('magic_sequence')}. {h.get('note', '')}"),
        'mitre': 'T1205.002 (Socket Filters), T1014 (Rootkit)',
    },
    'Mirai/Gafgyt-class': {
        'severity': 'High', 'type': 'Botnet Config Recovered ({source})',
        'target': lambda h, where: (h['c2_candidates'][0] if h.get('c2_candidates') else where),
        'details': lambda h, where: (
            f"Mirai/Gafgyt-class XOR-obfuscated string table recovered from {where}: "
            f"xor_key={h['xor_key']} decoded_tokens={h['decoded_token_count']} "
            f"known_hits={h.get('known_token_hits') or []} c2={h.get('c2_candidates') or []}. "
            f"{h.get('note', '')}"),
        'mitre': 'T1498 (Network DoS), T1071',
    },
}


def to_findings(hits: List[Dict[str, Any]], where: str, mitre_default: str = 'T1071',
                source: str = 'memory') -> List[dict]:
    """Convert extract_all() output into common-schema findings ({Timestamp, Severity,
    Type, Target, Details, MITRE}) consistent with memory_enrich.py's _finding() schema.
    `source` describes WHERE the bytes came from -- "memory" for a carved region
    (memory_enrich.py, the default) or "on-disk" for a live file read (edr_hunt.py's
    structural-config check) -- and is substituted into every Type string that
    describes a location, so a live-host static-pass finding never claims to be a
    memory-carve result it isn't."""
    out = []
    for h in hits:
        fam = h.get('family', 'Unknown')
        spec = _FAMILY_FINDING_SPEC.get(fam)
        if spec:
            out.append({
                'Timestamp': _now(), 'Severity': spec['severity'],
                'Type': spec['type'].format(source=source),
                'Target': spec['target'](h, where), 'Details': spec['details'](h, where),
                'MITRE': spec['mitre'],
            })
            continue
        if fam.startswith('Ebury-class'):
            out.append({
                'Timestamp': _now(), 'Severity': 'Critical',
                'Type': f'SSH Backdoor Artifact ({source})', 'Target': where,
                'Details': (f"Keyutils/network capability-mismatch backdoor recovered from {where}: "
                            f"keyutils_api={h.get('keyutils_api_present') or []} "
                            f"network_imports={h.get('network_imports_present') or []}. "
                            f"{h.get('note', '')}"),
                'MITRE': 'T1556 (Modify Authentication Process), T1554 (Compromise Client Binary)',
            })
            continue
        if fam.startswith('Ransomware'):
            detail_fields = {k: v for k, v in h.items() if k not in ('family', 'note') and v}
            out.append({
                'Timestamp': _now(), 'Severity': 'Critical',
                'Type': f'Ransomware Indicators Recovered ({fam}, {source})', 'Target': where,
                'Details': (f"{fam} structural indicators recovered from {where}: {detail_fields}. "
                            f"{h.get('note', '')}"),
                'MITRE': 'T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)',
            })
            continue
        if fam.startswith('SaaS C2'):
            detail_fields = {k: v for k, v in h.items() if k not in ('family', 'note') and v}
            out.append({
                'Timestamp': _now(), 'Severity': 'High',
                'Type': f'Cloud SaaS C2 Channel Recovered ({fam}, {source})', 'Target': where,
                'Details': f'{fam} channel configuration recovered from {where}: {detail_fields}',
                'MITRE': 'T1102 (Web Service), T1071.001 (Web Protocols)',
            })
            continue
        if fam.startswith('Delivery'):
            detail_fields = {k: v for k, v in h.items() if k not in ('family', 'note') and v}
            out.append({
                'Timestamp': _now(), 'Severity': 'High',
                'Type': f'Delivery Stager Recovered ({fam}, {source})', 'Target': where,
                'Details': f'{fam} stager pattern recovered from {where}: {detail_fields}',
                'MITRE': 'T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer)',
            })
            continue
        if fam.startswith('Anti-Analysis'):
            detail_fields = {k: v for k, v in h.items() if k not in ('family', 'note') and v}
            out.append({
                'Timestamp': _now(), 'Severity': 'Medium',
                'Type': f'Anti-Analysis Technique Recovered ({source})', 'Target': where,
                'Details': f'{fam} recovered from {where}: {detail_fields}. {h.get("note", "")}',
                'MITRE': 'T1622 (Debugger Evasion), T1497 (Virtualization/Sandbox Evasion)',
            })
            continue
        if fam.startswith('DNS Tunnel'):
            detail_fields = {k: v for k, v in h.items() if k not in ('family', 'note') and v}
            out.append({
                'Timestamp': _now(), 'Severity': 'High',
                'Type': f'DNS Tunneling C2 Recovered ({source})', 'Target': where,
                'Details': f'{fam} recovered from {where}: {detail_fields}',
                'MITRE': 'T1071.004 (DNS), T1572 (Protocol Tunneling)',
            })
            continue
        # C2 framework families (Sliver/Mythic/Merlin/Havoc/AdaptixC2/Pupy/unnamed Go):
        # uniform "config recovered" finding.
        detail_fields = {k: v for k, v in h.items() if k != 'family' and v}
        out.append({
            'Timestamp': _now(), 'Severity': 'High',
            'Type': f'C2 Config Recovered ({fam}, {source})', 'Target': where,
            'Details': f'{fam} implant configuration recovered from {where}: {detail_fields}',
            'MITRE': f'{mitre_default} (Application Layer Protocol), T1027 (Obfuscated Files)',
        })
    return out
