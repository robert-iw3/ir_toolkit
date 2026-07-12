"""Pupy RAT (Python, explicitly cross-platform -- Linux is a first-class target, not a
cross-compile afterthought). Pupy's transport/config layer uses these module and RPC
names verbatim in its pickled/marshalled config and reflective-loader banner; an
operator can rebuild the payload but these package/RPC names are load-bearing (the
client can't dispatch without them)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import decode, find_json_objects

_MARKERS = (
    b'pupy.pupyimporter', b'PupyCredentials', b'rpyc.core', b'ReverseSlave',
    b'launcher_module', b'pupy_srv.py', b'dnscnc',
)
_CONF_ANCHOR = re.compile(rb'"?(?:launcher_args|transport|server)"?\s*:')
_HOST_RE = re.compile(rb'(?:server|host)["\')\s:=]{1,4}["\']?([a-zA-Z0-9\.\-]{4,100}:\d{2,5})', re.IGNORECASE)


def identify(data: bytes) -> bool:
    return sum(1 for f in _MARKERS if f in data) >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _CONF_ANCHOR):
        fields.update(obj)
    server = fields.get('server', '')
    if not server:
        m = _HOST_RE.search(data)
        if m:
            server = decode(m.group(1))
    transport = fields.get('transport', '')
    dns_cnc = b'dnscnc' in data
    if not (server or dns_cnc):
        return None
    return {'family': 'Pupy', 'server': server, 'transport': transport,
            'dns_cnc': dns_cnc or None}
