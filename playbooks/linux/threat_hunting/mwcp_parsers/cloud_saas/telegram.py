"""Telegram Bot API as a C2/exfil channel. A Telegram bot token has an EXACT wire
format Telegram's own API enforces (numeric bot ID : 35-char secret) -- an operator
cannot use a malformed token and have the bot function at all. Combined with the
API-required endpoint path structure (api.telegram.org/bot<token>/<method>, where
<method> must be a real Bot API method the server recognizes)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_TOKEN_RE = re.compile(rb'(?<!\d)(\d{8,10}):([A-Za-z0-9_\-]{35})\b')
_ENDPOINT_RE = re.compile(
    rb'api\.telegram\.org/bot[\d]{8,10}:[A-Za-z0-9_\-]{35}/(sendMessage|sendDocument|'
    rb'getUpdates|sendPhoto|answerCallbackQuery)', re.IGNORECASE)


def identify(data: bytes) -> bool:
    return bool(_TOKEN_RE.search(data)) and (
        bool(_ENDPOINT_RE.search(data)) or b'api.telegram.org' in data)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    tm = _TOKEN_RE.search(data)
    em = _ENDPOINT_RE.search(data)
    return {
        'family': 'SaaS C2: Telegram Bot API',
        'bot_id': tm.group(1).decode(),
        'endpoint_method': em.group(1).decode() if em else None,
        'note': ('Bot-API-required token format (numeric ID:35-char secret) AND the '
                 'api.telegram.org endpoint co-occurring -- both are protocol requirements, '
                 'not artifact strings an operator chose.'),
    }
