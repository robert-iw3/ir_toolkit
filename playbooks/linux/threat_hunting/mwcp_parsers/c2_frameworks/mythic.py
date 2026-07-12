"""Mythic (Poseidon/Medusa-type agents are Go/Python -- run on Linux as a first-class
target). Protocol-required field names the Mythic server's agent-comm schema depends on."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import find_json_objects

_REQUIRED_FIELDS = (
    b'PayloadUUID', b'callback_interval', b'c2_profiles',
    b'encrypted_exchange_check', b'AES_PSK', b'tasking_type',
)
_JSON_ANCHOR = re.compile(rb'"?PayloadUUID"?\s*:')


def identify(data: bytes) -> bool:
    return sum(1 for f in _REQUIRED_FIELDS if f in data) >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _JSON_ANCHOR):
        fields.update(obj)

    uuid = fields.get('PayloadUUID') or fields.get('uuid') or fields.get('agent_uuid', '')
    interval = fields.get('callback_interval') or fields.get('sleep_interval')
    servers = set()
    profiles = fields.get('c2_profiles') or []
    if isinstance(profiles, list):
        for p in profiles:
            if isinstance(p, dict):
                for k in ('callback_host', 'server', 'endpoint'):
                    if p.get(k):
                        servers.add(str(p[k]))
    if not (uuid or servers):
        return None
    return {
        'family': 'Mythic', 'payload_uuid': uuid,
        'callback_interval_s': interval, 'c2_servers': sorted(servers)[:10],
    }
