"""
TelegramC2Config -- mwcp parser for Telegram bot token / chat ID extraction.

Telegram bot tokens follow an exact format imposed by the Telegram BotAPI:
    <bot_id>:<random_token>
where <bot_id> is 8-10 digits and <random_token> is 35 chars [A-Za-z0-9_-].

This cross-family pattern appears in:
  - Redline Stealer
  - Vidar Stealer
  - Agent Tesla
  - Clipboard hijackers
  - Custom Python/PS1/BAT stealers and RATs
  - AsyncRAT variants with Telegram notification

Chat IDs are integers (can be negative for group chats) that often appear
adjacent to the bot token in the binary.

The bot token is DIRECTLY ACTIONABLE:
  https://api.telegram.org/bot<TOKEN>/getMe      -- verify token validity
  https://api.telegram.org/bot<TOKEN>/getUpdates -- read message history

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, Password, DecodedString

# Telegram bot token: 8-10 digit ID, colon, 35 chars of [A-Za-z0-9_-]
_BOT_TOKEN_RE = re.compile(
    rb'(\d{8,10}):([A-Za-z0-9_\-]{35})',
)

# Chat ID: integer, optionally negative, typically 7-15 digits
# Often appears within 256 bytes before or after the bot token
_CHAT_ID_RE = re.compile(
    rb'(?:chat_id|chatid|chat|to|recipient)["\s:=\']*(-?\d{7,15})',
    re.IGNORECASE
)
# Looser: just a long integer (possibly negative) near the token
_CHAT_ID_BARE_RE = re.compile(
    rb'(-\d{9,15}|\d{9,15})'
)

_CONTEXT_WINDOW = 300  # bytes around the token to search for chat ID


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


class TelegramC2Config(mwcp.Parser):
    """Extract Telegram bot tokens and chat IDs from any file type."""

    DESCRIPTION = "Telegram C2/Exfil Bot Token Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        # Run on all file types -- Telegram tokens appear in scripts, PEs, and memory
        return True

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen_tokens = set()
        seen_tags   = set()

        for m in _BOT_TOKEN_RE.finditer(data):
            bot_id    = _clean(m.group(1))
            bot_token = _clean(m.group(2))
            full_token = f'{bot_id}:{bot_token}'

            if full_token in seen_tokens:
                continue
            seen_tokens.add(full_token)

            # Emit the API base URL for direct analyst lookup
            api_url = f'https://api.telegram.org/bot{full_token}/'
            self.report.add(C2URL(api_url))

            # Emit token as Password so it lands in credential output
            self.report.add(Password(full_token))

            # Search context window for chat ID
            token_pos = m.start()
            lo = max(0, token_pos - _CONTEXT_WINDOW)
            hi = min(len(data), token_pos + len(m.group(0)) + _CONTEXT_WINDOW)
            ctx = data[lo:hi]

            chat_id = None
            # Prefer labelled chat_id first
            for cm in _CHAT_ID_RE.finditer(ctx):
                cid = _clean(cm.group(1))
                if cid:
                    chat_id = cid
                    break

            # Fallback: bare long integer (negative = group chat, very diagnostic)
            if not chat_id:
                for cm in _CHAT_ID_BARE_RE.finditer(ctx):
                    cid = _clean(cm.group(1))
                    # Negative chat IDs are highly specific to Telegram groups
                    if cid and cid.startswith('-') and len(cid) >= 10:
                        chat_id = cid
                        break

            # Emit findings as DecodedString for analyst context
            tag_parts = [f'[TelegramC2] bot_id={bot_id}']
            if chat_id:
                tag_parts.append(f'chat_id={chat_id}')
            tag_parts.append(f'token={full_token}')
            tag_parts.append(f'api={api_url}')
            tag = ' | '.join(tag_parts)

            if tag not in seen_tags:
                seen_tags.add(tag)
                self.report.add(DecodedString(tag))

            # Emit chat_id separately as a decoded string for deduplication
            if chat_id:
                cid_tag = f'[TelegramC2-ChatID] {chat_id}'
                if cid_tag not in seen_tags:
                    seen_tags.add(cid_tag)
                    self.report.add(DecodedString(cid_tag))
