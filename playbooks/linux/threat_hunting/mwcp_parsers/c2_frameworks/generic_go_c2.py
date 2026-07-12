"""Generic Go C2 beacon heuristic (unnamed/custom Go backdoors -- detect the SHAPE,
not a family name: a Go runtime build marker AND 2+ heartbeat-shaped JSON fields near
an HTTP(S) endpoint). Tuned to Go's build/serialization conventions since Go is the
dominant language for custom Linux implants that don't match a named framework."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import decode, find_json_objects

_GO_BUILD_MARKER_RE = re.compile(rb'Go build ID: "|golang\.org/x/|runtime\.goexit')
_HEARTBEAT_JSON_ANCHOR = re.compile(rb'"(?:hostname|beacon|interval|agent_id|task_id)"\s*:')
_HEARTBEAT_FIELDS = (b'"hostname"', b'"interval"', b'"beacon"', b'"task_id"', b'"agent_id"')
_URL_RE = re.compile(rb'https?://[^\s\x00\'"<>]{4,200}', re.IGNORECASE)


def identify(data: bytes) -> bool:
    if not _GO_BUILD_MARKER_RE.search(data):
        return False
    return sum(1 for f in _HEARTBEAT_FIELDS if f in data) >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _HEARTBEAT_JSON_ANCHOR):
        fields.update(obj)
    urls = sorted({decode(m.group(0)) for m in _URL_RE.finditer(data)})[:10]
    if not (fields or urls):
        return None
    return {
        'family': 'Unnamed Go C2 (structural)', 'heartbeat_fields': sorted(fields.keys()),
        'candidate_urls': urls,
        'note': ('Go runtime marker + heartbeat-shaped JSON (hostname/interval/task_id) near '
                 'HTTP endpoint(s) -- structural match only, no named family.'),
    }
