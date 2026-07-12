"""Pastebin as a C2/dead-drop channel. Requires the raw-paste fetch URL structure
(pastebin.com/raw/<8-char alphanumeric paste ID> -- Pastebin's own URL-routing format
for a specific paste's raw content) co-occurring with the Pastebin API's own required
POST parameter name (api_dev_key/api_paste_code) for the create/publish side of the
channel, or the API post endpoint itself."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_RAW_URL_RE = re.compile(rb'pastebin\.com/raw/([A-Za-z0-9]{8})\b')
_API_MARKERS = (b'pastebin.com/api/api_post.php', b'api_dev_key', b'api_paste_code')


def identify(data: bytes) -> bool:
    return bool(_RAW_URL_RE.search(data)) and any(m in data for m in _API_MARKERS)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    m = _RAW_URL_RE.search(data)
    return {
        'family': 'SaaS C2: Pastebin',
        'paste_id': m.group(1).decode(),
        'note': ('Pastebin raw-fetch URL (fixed 8-char paste-ID format) co-occurring with the '
                 'Pastebin API\'s own required POST parameter names -- both fetch and publish '
                 'sides of a dead-drop channel.'),
    }
