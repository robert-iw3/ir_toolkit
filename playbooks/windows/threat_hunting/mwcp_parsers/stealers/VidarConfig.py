"""
VidarConfig -- mwcp parser for Vidar Stealer C2 profile-ID configuration.

Vidar's loader reads its C2 host and profile ID from the PE OVERLAY --
the bytes immediately following the last section's raw data. This is a
structural requirement of Vidar's own loader code (it seeks to
end-of-sections and reads from there), not an operator-chosen location,
so it cannot be moved without breaking the sample's own config read.
Newer variants deliver the real C2 via a Telegram channel description
fetched at runtime; the embedded fallback is the literal Telegram API
profile-fetch URL pattern.

Detection never checks for a "Vidar" name string. It requires an overlay
region that is present, low-entropy (plaintext-ish, unlike an encrypted
blob), and contains either a URL or a Telegram channel/profile reference.

References:
  - Public Vidar Stealer overlay-config and Telegram-fallback writeups

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import struct
import math
import mwcp
from mwcp.metadata import C2URL, C2Address, DecodedString

_URL_RE = re.compile(rb'(?i)https?://[^\s\x00"\'<>]{6,200}')
_TELEGRAM_RE = re.compile(rb'(?i)(?:t\.me/|telegram\.(?:me|org)/)[A-Za-z0-9_]{3,64}')
_MIN_OVERLAY = 8
_MAX_OVERLAY_SCAN = 4096


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


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


class VidarConfig(mwcp.Parser):
    """Extract Vidar Stealer C2 profile URL / Telegram fallback from the PE overlay."""

    DESCRIPTION = "Vidar Stealer Overlay Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 128:
            return False
        overlay = _find_overlay(data)
        if len(overlay) < _MIN_OVERLAY:
            return False
        if _entropy(overlay) > 6.5:
            return False   # plaintext-ish only -- encrypted overlays belong to other loaders
        return bool(_URL_RE.search(overlay)) or bool(_TELEGRAM_RE.search(overlay))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        overlay = _find_overlay(data)
        if len(overlay) < _MIN_OVERLAY or _entropy(overlay) > 6.5:
            return

        found = False
        for m in _URL_RE.finditer(overlay):
            url = m.group(0).decode('utf-8', 'ignore').rstrip('"\'<> \x00')
            self.report.add(C2URL(url))
            found = True

        for m in _TELEGRAM_RE.finditer(overlay):
            ref = m.group(0).decode('utf-8', 'ignore')
            self.report.add(DecodedString(f'[Vidar-TelegramFallback] {ref}'))
            found = True

        if found:
            self.report.add(DecodedString('[Vidar-Config] C2 profile reference found in PE overlay'))
