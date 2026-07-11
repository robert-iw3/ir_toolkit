"""
LummaConfig -- mwcp parser for Lumma Stealer C2 URL-list configuration.

Lumma embeds a list of candidate C2 URLs, base64-encoded and separated by
NUL bytes, in the PE overlay -- the client tries each in turn until one
responds, a resilience mechanism that structurally requires multiple
distinct encoded URL entries to exist side by side. That multiplicity
(2+ independently-decodable base64 URL entries in one contiguous region)
is the structural signal, not any Lumma name string.

Detection: 2+ NUL-separated base64 tokens in the overlay that each decode
to a URL. A single decodable token is not enough (too easy to coincide
with unrelated base64 data); a decode that doesn't parse as a URL is
discarded.

References:
  - Public Lumma Stealer overlay/base64-URL-list writeups

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import base64
import struct
import mwcp
from mwcp.metadata import C2URL, DecodedString

_MIN_URLS = 2
_MAX_OVERLAY_SCAN = 4096
_B64_TOKEN_RE = re.compile(rb'[A-Za-z0-9+/]{16,300}={0,2}')
_URL_SCHEME_RE = re.compile(r'^https?://[a-zA-Z0-9\.\-]{3,253}(?:/[^\s]*)?$')


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


def _decode_url_list(overlay: bytes) -> list[str]:
    urls = []
    for token_bytes in re.split(rb'\x00+', overlay):
        m = _B64_TOKEN_RE.fullmatch(token_bytes.strip())
        if not m:
            continue
        try:
            decoded = base64.b64decode(token_bytes, validate=True).decode('utf-8', 'ignore')
        except Exception:
            continue
        if _URL_SCHEME_RE.match(decoded):
            urls.append(decoded)
    return urls


class LummaConfig(mwcp.Parser):
    """Extract Lumma Stealer C2 URL list from base64-encoded, NUL-separated
    overlay entries."""

    DESCRIPTION = "Lumma Stealer Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 128:
            return False
        overlay = _find_overlay(data)
        return len(_decode_url_list(overlay)) >= _MIN_URLS

    def run(self):
        data = self.file_object.data
        if not data:
            return
        overlay = _find_overlay(data)
        urls = _decode_url_list(overlay)
        if len(urls) < _MIN_URLS:
            return
        for url in urls:
            self.report.add(C2URL(url))
        self.report.add(DecodedString(
            f'[Lumma-Config] {len(urls)} base64-encoded C2 URL(s) in overlay'))
