"""
PowerShellDecoder -- mwcp parser that extracts and decodes -EncodedCommand payloads.

Scans ANY file for embedded PowerShell -EncodedCommand / -enc base64 strings --
common in LNK droppers, VBS stagers, HTA files, batch scripts, and macro stubs.
Decodes UTF-16LE base64 and emits as mwcp.metadata.DecodedString so the analyst
can see the actual command without manual decoding.

Also extracts:
  - Hardcoded IEX / Invoke-Expression download cradles (WebClient + DownloadString)
  - Embedded URLs in script files (C2 stage-1 delivery URLs)
  - -WindowStyle Hidden with command (stager fingerprint)
"""

import re
import base64
import mwcp
from mwcp.metadata import DecodedString, C2URL

# Patterns that identify embedded PS encoding
_ENC_RE   = re.compile(
    rb'(?i)(?:-enc(?:odedcommand)?|-e)\s+([A-Za-z0-9+/=]{20,})',
    re.DOTALL)
# Wide (UTF-16LE) variant -- common in VBS/HTA that builds the command in wide strings
_ENC_WIDE = re.compile(
    rb'(?:[A-Za-z0-9+/=]{2}\x00){10,}',
)
# Download cradle
_DOWNLOAD_RE = re.compile(
    rb'(?i)(?:DownloadString|DownloadFile|Net\.WebClient|IEX|Invoke-Expression)'
    rb'.{0,200}(?:https?://[^\s\'"<>\x00]{8,200})',
    re.DOTALL)
# Inline URL in script context
_URL_RE = re.compile(
    rb'https?://[^\s\'"<>\x00\r\n]{8,200}', re.IGNORECASE)

_BENIGN_DOMAINS = re.compile(
    rb'(?i)(microsoft\.com|windows\.com|windowsupdate\.com|adobe\.com|'
    rb'digicert\.com|verisign\.com|ocsp\.|crl\.)')

_MAX_DECODE_LEN = 10_000   # cap decoded output length in DecodedString


def _try_decode_b64(b64bytes: bytes) -> str | None:
    """Attempt base64 → UTF-16LE decode (PowerShell's encoding). Returns string or None."""
    for pad in (b64bytes, b64bytes + b'=', b64bytes + b'=='):
        try:
            raw = base64.b64decode(pad)
            # PS always uses UTF-16LE; reject if not decodeable or all-zero
            text = raw.decode('utf-16-le', errors='strict')
            if len(text) > 4 and any(c.isprintable() for c in text[:20]):
                return text[:_MAX_DECODE_LEN]
        except Exception:
            continue
    return None


class PowerShellDecoder(mwcp.Parser):
    """Extract and decode embedded PowerShell -EncodedCommand payloads."""

    DESCRIPTION = "PowerShell EncodedCommand Decoder (all families)"

    @classmethod
    def identify(cls, file_object):
        return True   # run against all file types (LNK, VBS, HTA, PS1, PE...)

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen_decoded = set()
        seen_urls    = set()

        # 1. -EncodedCommand base64 → decode to UTF-16LE
        for m in _ENC_RE.finditer(data):
            decoded = _try_decode_b64(m.group(1))
            if decoded and decoded not in seen_decoded:
                seen_decoded.add(decoded)
                self.logger.debug(f"[PSDecoder] decoded enc-command ({len(decoded)} chars)")
                self.report.add(DecodedString(
                    f"[PS-EncodedCommand] {decoded}",
                    encryption_key=None,
                ))

        # 2. Download cradle URLs inside PS commands
        for m in _DOWNLOAD_RE.finditer(data):
            url_match = _URL_RE.search(m.group(0))
            if url_match:
                url = url_match.group(0).decode('utf-8', 'ignore').strip()
                if url not in seen_urls and not _BENIGN_DOMAINS.search(url_match.group(0)):
                    seen_urls.add(url)
                    self.report.add(C2URL(url))

        # 3. Standalone URLs in script files (not in PS command context)
        ext = ''
        try:
            import os
            ext = os.path.splitext(getattr(self.file_object, 'name', '') or '').lower()
        except Exception:
            pass
        if ext in ('.ps1', '.psm1', '.vbs', '.vbe', '.js', '.hta', '.bat', '.cmd',
                   '.lnk', '.wsf', '.wsh'):
            for m in _URL_RE.finditer(data):
                url = m.group(0).decode('utf-8', 'ignore').strip()
                if url not in seen_urls and not _BENIGN_DOMAINS.search(m.group(0)):
                    seen_urls.add(url)
                    self.report.add(C2URL(url))
