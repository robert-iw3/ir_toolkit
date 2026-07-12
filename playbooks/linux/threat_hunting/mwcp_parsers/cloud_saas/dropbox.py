"""Dropbox API as a C2/exfil channel. Requires BOTH the content-upload API endpoint
AND the Dropbox-API-Arg header -- a custom HTTP header the Dropbox API mandates for
every content-endpoint call (it carries the JSON call arguments the REST body can't,
since the body IS the raw file payload). No generic HTTP client emits this header;
it only exists because the Dropbox API protocol requires it."""
from __future__ import annotations

from typing import Any, Dict, Optional

_ENDPOINTS = (b'content.dropboxapi.com/2/files/upload', b'api.dropboxapi.com/2/files/')
_REQUIRED_HEADER = b'Dropbox-API-Arg'


def identify(data: bytes) -> bool:
    return any(e in data for e in _ENDPOINTS) and _REQUIRED_HEADER in data


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    endpoint = next((e.decode() for e in _ENDPOINTS if e in data), None)
    return {
        'family': 'SaaS C2: Dropbox API',
        'endpoint': endpoint,
        'note': ('Dropbox content-API endpoint co-occurring with the Dropbox-API-Arg header '
                 'the protocol requires for every content call -- API-mandated pairing, not an '
                 'artifact string.'),
    }
