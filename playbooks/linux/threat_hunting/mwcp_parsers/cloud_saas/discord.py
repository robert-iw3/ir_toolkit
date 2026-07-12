"""Discord webhook as a C2/exfil channel. A Discord webhook URL has an EXACT
API-required shape: a 17-19 digit Snowflake ID followed by a fixed-length opaque
token -- Discord's webhook backend rejects any URL that doesn't match this structure,
so it can't be renamed/reshaped without breaking the channel. Corroborated by the
JSON payload shape the webhook POST body itself requires ("content"/"embeds"/
"username" -- Discord's webhook endpoint rejects a body with none of these)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_WEBHOOK_RE = re.compile(
    rb'discord(?:app)?\.com/api/webhooks/(\d{17,19})/([A-Za-z0-9_\-]{60,90})')
_PAYLOAD_FIELDS = (b'"content"', b'"embeds"', b'"username"', b'"avatar_url"')
_CONTEXT_WINDOW = 2000


def identify(data: bytes) -> bool:
    m = _WEBHOOK_RE.search(data)
    if not m:
        return False
    lo, hi = max(0, m.start() - _CONTEXT_WINDOW), min(len(data), m.end() + _CONTEXT_WINDOW)
    return any(f in data[lo:hi] for f in _PAYLOAD_FIELDS)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    m = _WEBHOOK_RE.search(data)
    return {
        'family': 'SaaS C2: Discord Webhook',
        'webhook_id': m.group(1).decode(),
        'note': ('Discord webhook URL matching the exact Snowflake-ID + fixed-length-token '
                 'shape the Discord API requires, co-occurring with a webhook-POST-body field '
                 '(content/embeds/username) -- both are API requirements, not artifact strings.'),
    }
