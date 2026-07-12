"""Sliver (Go, cross-platform -- Linux/BSD implants are common, not a cross-compile
afterthought). Wire-protocol field names required by the Sliver server's JSON
serialization; an operator can strip debug symbols but not rename these without forking
the server. Do NOT check for "sliver"/"BishopFox" -- those strings are stripped."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import decode, find_json_objects

_PROTO_FIELDS = (
    b'"implant_name"', b'"reconnect_interval"', b'"c2s"', b'"dns_c2s"',
    b'"ActiveC2"', b'"PollTimeout"', b'"MaxConnectionErrors"',
    b'mtls://', b'wg://',
)
_JSON_ANCHOR = re.compile(rb'"(?:implant_name|ActiveC2|reconnect_interval)"')
_C2_URL_RE = re.compile(rb'(?:mtls|https|wg|dns|http)://[^\s\x00\'"<>{}\[\]]{4,200}', re.IGNORECASE)
_NAME_RE = re.compile(rb'(?:SliverName|implant_name)\x00{0,8}([A-Za-z0-9_\-]{3,32})', re.IGNORECASE)
_RECONNECT_RE = re.compile(rb'(?:ReconnectInterval|reconnect_interval)\x00{0,8}(\d{1,8})', re.IGNORECASE)


def identify(data: bytes) -> bool:
    return sum(1 for f in _PROTO_FIELDS if f in data) >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _JSON_ANCHOR):
        fields.update(obj)

    urls = set()
    c2_list = fields.get('c2s') or fields.get('C2s') or []
    if isinstance(c2_list, list):
        for entry in c2_list:
            url = entry.get('url', '') if isinstance(entry, dict) else str(entry)
            if url:
                urls.add(url)
    if fields.get('server_url'):
        urls.add(fields['server_url'])
    for m in _C2_URL_RE.finditer(data):
        url = decode(m.group(0)).rstrip('\x00 /').strip()
        if url and len(url) > 8:
            urls.add(url)

    name = fields.get('implant_name', '')
    if not name:
        m = _NAME_RE.search(data)
        if m:
            name = decode(m.group(1)).strip('\x00')

    interval = fields.get('reconnect_interval', 0)
    if not interval:
        m = _RECONNECT_RE.search(data)
        if m:
            interval = int(m.group(1))

    if not (urls or name):
        return None
    return {
        'family': 'Sliver', 'c2_urls': sorted(urls)[:10],
        'implant_name': name, 'reconnect_interval_s': interval or None,
    }
