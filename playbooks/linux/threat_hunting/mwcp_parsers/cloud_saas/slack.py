"""Slack as a C2/exfil channel -- two independent Slack-API-required wire formats:
Incoming Webhook URLs (hooks.slack.com/services/<T-team>/<B-bot>/<24-char secret>,
where the T-/B-prefixed segment IDs are Slack's own workspace/app identifier format)
and Bot User OAuth tokens (xoxb-<digits>-<digits>-<alphanumeric>, a format the Slack
API validates server-side)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_WEBHOOK_RE = re.compile(
    rb'hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}')
_BOT_TOKEN_RE = re.compile(rb'xoxb-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,32}')


def identify(data: bytes) -> bool:
    return bool(_WEBHOOK_RE.search(data)) or bool(_BOT_TOKEN_RE.search(data))


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    wm = _WEBHOOK_RE.search(data)
    tm = _BOT_TOKEN_RE.search(data)
    if not (wm or tm):
        return None
    return {
        'family': 'SaaS C2: Slack',
        'incoming_webhook': bool(wm),
        'bot_oauth_token': bool(tm),
        'note': ('Slack Incoming Webhook URL (T-/B-prefixed workspace+app ID segments) or '
                 'Bot OAuth token (xoxb- + two numeric ID segments + secret) -- both are '
                 'formats the Slack API itself validates, not artifact strings.'),
    }
