"""
DiscordExfilConfig -- mwcp parser for Discord webhook / bot token exfil configs.

Discord webhook URLs follow a fixed format mandated by the Discord API:
    https://discord.com/api/webhooks/<server_id>/<token>

Server IDs are Discord Snowflakes (17-19 digits).  Tokens are opaque strings
[A-Za-z0-9_-] that are only valid for that specific server.

This cross-family pattern appears in:
  - Redline / Vidar / Lumma / Raccoon stealers
  - AsyncRAT / VenomRAT variants with Discord notification
  - Custom Python/PS1 stagers using Discord as a dead-drop C2
  - Clipboard hijackers using Discord for screenshot exfil

The webhook URL is DIRECTLY ACTIONABLE:
  curl -H "Content-Type: application/json" -X POST <webhook_url> -d '{"content":"test"}'

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, Password, DecodedString

# Discord webhook: server_id (Snowflake 17-19 digits) + token (60-90 alphanumeric chars)
_WEBHOOK_RE = re.compile(
    rb'https?://(?:discord(?:app)?\.com|ptb\.discord\.com)/api/webhooks/(\d{17,20})/([A-Za-z0-9_\-]{50,90})',
    re.IGNORECASE
)

# Discord bot tokens: three base64url segments separated by dots
# Segment 1: base64(user_id) ~24-26 chars
# Segment 2: timestamp ~6 chars
# Segment 3: HMAC ~27-38 chars
_BOT_TOKEN_RE = re.compile(
    rb'(?<![A-Za-z0-9_\-])([A-Za-z0-9_\-]{24,26}\.[A-Za-z0-9_\-]{5,7}\.[A-Za-z0-9_\-]{27,38})(?![A-Za-z0-9_\-])',
)


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


class DiscordExfilConfig(mwcp.Parser):
    """Extract Discord webhook URLs and bot tokens from any file type."""

    DESCRIPTION = "Discord Webhook/Bot Token C2/Exfil Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        # Run on all file types -- Discord tokens appear in scripts, PEs, and memory
        return True

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen = set()

        # Primary: webhook URLs (most common in commodity malware)
        for m in _WEBHOOK_RE.finditer(data):
            server_id = _clean(m.group(1))
            token     = _clean(m.group(2))
            full_url  = m.group(0).decode('utf-8', 'ignore').strip()

            if full_url in seen:
                continue
            seen.add(full_url)

            self.report.add(C2URL(full_url))
            self.report.add(Password(token))
            self.report.add(DecodedString(
                f'[Discord-Webhook] server_id={server_id} token={token[:16]}... url={full_url}'
            ))
