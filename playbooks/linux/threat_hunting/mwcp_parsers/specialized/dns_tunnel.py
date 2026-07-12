"""DNS tunneling C2 -- data smuggled as DNS TXT-query subdomain labels. Base32 (not
base64) is the standard encoding choice for this technique specifically because DNS
labels are case-insensitive and length-limited to 63 bytes per label; base32's
restricted alphabet survives that constraint safely where base64's mixed case and
length would not, so a long base32-shaped label used AS a DNS subdomain component is a
genuine structural fingerprint of the technique, not an arbitrary string.

Requires that shape to co-occur with the resolver API surface a raw TXT query needs
(res_query/res_search/dn_expand from libresolv, or ares_query/ares_search from c-ares)
-- an ordinary program doing a normal `getaddrinfo()`-style lookup never needs these
lower-level, record-type-explicit resolver functions."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

# A base32-alphabet-only label (40+ chars -- well past any real hostname component,
# consistent with an encoded data chunk) immediately followed by a domain continuation.
_BASE32_LABEL_RE = re.compile(rb'\b[A-Z2-7]{40,63}\.[a-zA-Z0-9\-]{1,63}\.[a-zA-Z]{2,10}\b')
_TXT_RESOLVER_API = (b'res_query', b'res_search', b'dn_expand', b'ares_query', b'ares_search')


def identify(data: bytes) -> bool:
    return bool(_BASE32_LABEL_RE.search(data)) and any(a in data for a in _TXT_RESOLVER_API)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    m = _BASE32_LABEL_RE.search(data)
    api = next((a.decode() for a in _TXT_RESOLVER_API if a in data), None)
    return {
        'family': 'DNS Tunnel: Base32-Label TXT Query',
        'sample_label': m.group(0).decode('utf-8', 'ignore')[:80],
        'resolver_api': api,
        'note': ('Oversized base32-shaped DNS label (base32 specifically, since DNS labels are '
                 'case-insensitive -- base64 would not survive) co-occurring with a low-level '
                 'TXT-capable resolver API an ordinary getaddrinfo()-style lookup never needs.'),
    }
