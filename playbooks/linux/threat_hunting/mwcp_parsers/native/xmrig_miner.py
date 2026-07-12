"""Cryptominer config (XMRig-class -- Kinsing/kdevtmpfsi-style Linux compromise, the
dominant real-world Linux compromise per WORKFLOW-INVESTIGATION-LINUX.md).

XMRig's config.json / CLI args share these field names verbatim; a JSON blob with a
"pools" array + "user"/"url" keys, or a stratum+tcp CLI invocation, is the structural
signature regardless of the wrapper script hiding it under a masqueraded process name.
memory_enrich.py already catches the stratum:// URL as a bare IOC but not the
structured pool/wallet/algo/donate-level config."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import decode, find_json_objects

_JSON_ANCHOR = re.compile(rb'"(?:donate-level|pools|algo)"\s*:')
_STRATUM_RE = re.compile(rb'stratum\+(?:tcp|ssl)://[A-Za-z0-9\.\-]+:\d{2,5}', re.IGNORECASE)
_WALLET_CLI_RE = re.compile(rb'-[ou]\s+([A-Za-z0-9]{20,106})')
_ALGO_RE = re.compile(rb'"algo"\s*:\s*"([a-z0-9/_\-]{3,40})"', re.IGNORECASE)


def identify(data: bytes) -> bool:
    return bool(_JSON_ANCHOR.search(data) or _STRATUM_RE.search(data))


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _JSON_ANCHOR):
        fields.update(obj)

    pools = set()
    pools_list = fields.get('pools') or []
    if isinstance(pools_list, list):
        for p in pools_list:
            if isinstance(p, dict) and p.get('url'):
                pools.add(str(p['url']))
                if p.get('user'):
                    pools.add(f"user={p['user']}")
    for m in _STRATUM_RE.finditer(data):
        pools.add(decode(m.group(0)))

    algo = fields.get('algo', '')
    if not algo:
        m = _ALGO_RE.search(data)
        if m:
            algo = decode(m.group(1))

    wallets = {decode(m.group(1)) for m in _WALLET_CLI_RE.finditer(data)}

    if not pools:
        return None
    return {
        'family': 'Miner (XMRig-class)', 'pools': sorted(pools)[:10],
        'algo': algo, 'wallets_cli': sorted(wallets)[:5],
        'donate_level': fields.get('donate-level'),
    }
