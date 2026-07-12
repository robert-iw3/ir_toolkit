"""SMTP exfil credentials (protocol-generic; commodity Linux stealers reuse this
channel the same way Windows RATs do). Requires an SMTP-shaped host, a valid SMTP
port, an email address, AND a labeled credential value all co-occurring in the same
small context window -- any one alone is far too common to mean anything."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .._common import decode

_HOST_RE = re.compile(rb'(?<![a-zA-Z0-9@])(?:smtp|mail)\.[a-zA-Z0-9\.\-]{3,100}', re.IGNORECASE)
_PORTS = {25, 465, 587, 2525, 26, 2526}
_PORT_RE = re.compile(
    rb'(?:\b|[\x00:;,\s])(' + b'|'.join(str(p).encode() for p in sorted(_PORTS)) + rb')(?:\b|[\x00:;,\s])')
_EMAIL_RE = re.compile(rb'[a-zA-Z0-9][a-zA-Z0-9\.\+\-_]{0,63}@[a-zA-Z0-9\.\-]{3,100}\.[a-zA-Z]{2,10}', re.IGNORECASE)
_PASS_LABEL_RE = re.compile(
    rb'(?:password|pass|pwd|secret|key|cred)["\s:=\x00]{0,8}([^\x00\r\n"\'<>\s]{4,64})', re.IGNORECASE)
_CONTEXT_WINDOW = 512


def extract(data: bytes) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for m in _HOST_RE.finditer(data):
        host = decode(m.group(0))
        if not host:
            continue
        lo, hi = max(0, m.start() - _CONTEXT_WINDOW), min(len(data), m.end() + _CONTEXT_WINDOW)
        ctx = data[lo:hi]

        port = '587'
        pm = _PORT_RE.search(ctx)
        if pm:
            try:
                p = int(decode(pm.group(1)))
                if p in _PORTS:
                    port = str(p)
            except ValueError:
                pass

        em = _EMAIL_RE.search(ctx)
        email = decode(em.group(0)) if em else None

        password = None
        passm = _PASS_LABEL_RE.search(ctx)
        if passm:
            val = decode(passm.group(1))
            if val and val.lower() not in ('smtp', 'mail', 'email', 'password', 'pass'):
                password = val

        if not password:
            continue
        key = (host, port, email, password)
        if key in seen:
            continue
        seen.add(key)
        out.append({'family': 'SMTP-Exfil', 'host': host, 'port': port,
                    'user': email, 'password': password})
    return out
