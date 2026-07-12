"""AdaptixC2 (cross-platform JSON-configured agent). agent_id AND callback_url are
both required fields the agent's own config-loader depends on to register with the
server -- neither can be stripped without breaking the agent's own bootstrap."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import find_json_objects

_FIELDS = (b'agent_id', b'callback_url', b'profile')
_JSON_ANCHOR = re.compile(rb'"agent_id"\s*:')


def identify(data: bytes) -> bool:
    return sum(1 for f in _FIELDS if f in data) >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _JSON_ANCHOR):
        fields.update(obj)
    agent_id = fields.get('agent_id', '')
    url = fields.get('callback_url', '')
    profile = fields.get('profile', '')
    if not (agent_id and url):
        return None
    return {'family': 'AdaptixC2', 'agent_id': agent_id, 'callback_url': url, 'profile': profile}
