"""
RaccoonConfig -- mwcp parser for Raccoon Stealer C2 configuration.

Raccoon v2's loader fetches its real C2 from a Telegram/Telegraph channel
description at runtime -- the embedded fallback is a literal Telegram Bot
API URL (api.telegram.org/bot<token>/...) the sample calls to read that
description. This is a structural requirement of the fetch mechanism
itself (the Telegram Bot API URL format is dictated by Telegram, not by
Raccoon's authors), independent of any Raccoon name string. Earlier v1
builds place a plaintext C2 URL directly in the PE data section instead.

Detection: a Telegram Bot API URL pattern is sufficient on its own for v2
(the bot-ID:token format is specific enough -- see the identify() note
below). For v1, a bare overlay URL is NOT sufficient by itself: an overlay
region with a URL is common in entirely benign installers/self-extracting
archives. v1 detection instead requires the overlay URL TOGETHER WITH a
second, independent mechanism: a browser-credential-database schema query
(the same Chromium `Login Data` / Firefox `moz_logins` schema reference
StealcConfig.py uses) -- Raccoon v1 is documented to be a browser-
credential stealer, so requiring both the C2-delivery primitive AND the
credential-harvesting primitive together is what makes this exclusive to
the stealer TTP rather than "any installer with a URL in its overlay."

References:
  - Public Raccoon Stealer v1/v2 config-delivery writeups; Chromium's own
    `Login Data` SQLite schema is documented directly by the Chromium project

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import struct
import mwcp
from mwcp.metadata import C2URL, DecodedString

_TG_BOT_API_RE = re.compile(rb'(?i)api\.telegram\.org/bot[0-9]{6,10}:[A-Za-z0-9_\-]{20,45}')
_URL_RE = re.compile(rb'(?i)https?://[^\s\x00"\'<>]{6,200}')
_MAX_OVERLAY_SCAN = 4096

# Same Chromium/Firefox credential-store schema reference as StealcConfig.py --
# a genuine second, independent mechanism (credential harvesting) required
# alongside the overlay URL (C2 delivery) for the v1 branch specifically.
_CRED_SCHEMA_RE = re.compile(
    rb'(?i)(?:origin_url[^\x00]{0,40}username_value[^\x00]{0,40}password_value|'
    rb'\bmoz_logins\b)')


def _find_overlay(data: bytes) -> bytes:
    try:
        if data[:2] != b'MZ':
            return b''
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return b''
        num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
        sec_table = e_lfanew + 24 + opt_hdr_size
        max_end = 0
        for i in range(num_sections):
            off = sec_table + i * 40
            if off + 40 > len(data):
                break
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
            max_end = max(max_end, raw_ptr + raw_size)
        if 0 < max_end < len(data):
            return data[max_end:max_end + _MAX_OVERLAY_SCAN]
    except Exception:
        pass
    return b''


class RaccoonConfig(mwcp.Parser):
    """Extract Raccoon Stealer C2 config (v2 Telegram fallback, or v1 overlay URL)."""

    DESCRIPTION = "Raccoon Stealer Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 128:
            return False
        if _TG_BOT_API_RE.search(data):
            return True
        overlay = _find_overlay(data)
        if not overlay or not _URL_RE.search(overlay):
            return False
        return bool(_CRED_SCHEMA_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return

        found = False
        for m in _TG_BOT_API_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore')
            self.report.add(C2URL(f'https://{url}'))
            self.report.add(DecodedString('[Raccoon-Config] v2 Telegram fallback bot API URL'))
            found = True

        overlay = _find_overlay(data)
        if overlay and _CRED_SCHEMA_RE.search(data):
            v1_found = False
            for m in _URL_RE.finditer(overlay):
                url = m.group(0).decode('utf-8', 'ignore').rstrip('"\'<> \x00')
                self.report.add(C2URL(url))
                v1_found = True
            if v1_found:
                self.report.add(DecodedString(
                    '[Raccoon-Config] v1 plaintext C2 URL in overlay, corroborated by a '
                    'browser-credential-schema query in the same file'))
                found = True
