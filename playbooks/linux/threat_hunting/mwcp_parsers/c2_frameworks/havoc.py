"""Havoc (Demon agent -- Linux/macOS builds since Havoc v2). The 0xDEADBEEF config
magic + a plausible size field is the wire-format structure the agent's own config
parser requires to bootstrap; the protocol field names are the fallback signal when
the magic isn't present (e.g. only a decoded/partial config blob was carved)."""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, Optional

from .._common import decode

_MAGIC = b'\xde\xad\xbe\xef'
_PROTO_FIELDS = (b'DemonID', b'SleepTime', b'Injection', b'encrypted_exchange_check')
_SLEEP_RE = re.compile(rb'(?:SleepTime|Sleep)\s*[=:]\s*(\d{1,6})', re.IGNORECASE)
_HOST_RE = re.compile(
    rb'(?:Teamserver|Host)\s*[=:]\s*[\x22\x27]?([a-zA-Z0-9\.\-]{4,100}:\d{2,5})', re.IGNORECASE)


def identify(data: bytes) -> bool:
    if _MAGIC in data:
        pos = data.find(_MAGIC)
        if pos + 8 <= len(data):
            try:
                size = struct.unpack_from('<I', data, pos + 4)[0]
                if 0 < size < 8192:
                    return True
            except struct.error:
                pass
    return sum(1 for f in _PROTO_FIELDS if f in data) >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    sleep, jitter = None, None
    pos = data.find(_MAGIC)
    if pos != -1 and pos + 24 <= len(data):
        try:
            sleep = struct.unpack_from('<I', data, pos + 12)[0]
            jitter = struct.unpack_from('<I', data, pos + 16)[0]
        except struct.error:
            pass
    if sleep is None:
        m = _SLEEP_RE.search(data)
        if m:
            sleep = int(m.group(1))
    host_m = _HOST_RE.search(data)
    host = decode(host_m.group(1)) if host_m else ''
    if sleep is None and not host:
        return None
    return {'family': 'Havoc', 'teamserver': host, 'sleep_s': sleep, 'jitter': jitter}
