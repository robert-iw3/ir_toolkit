"""
PoshC2Config -- mwcp parser for PoshC2 PowerShell C2 stager configs.

PoshC2 stagers are PS1 files with plaintext config variables embedded directly
in the script. Key fields: $server / $URLS, $Payload, $kill_date, $proxy_url.
The server list is either a single URL or comma-separated.

Also handles PoshC2 dropper implants that embed the PS1 stager as a string.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_SERVER_RE  = re.compile(rb'(?i)\$(?:server|URLS?)\s*=\s*["\']([^"\']{10,})["\']')
_PAYLOAD_RE = re.compile(rb'(?i)\$Payload\s*=\s*["\']([^"\']{10,})["\']')
_KILLDATE_RE= re.compile(rb'(?i)\$kill_?date\s*=\s*["\']([^"\']{4,20})["\']')
_PROXY_RE   = re.compile(rb'(?i)\$proxy_?url\s*=\s*["\']([^"\']{5,200})["\']')
_URL_RE     = re.compile(rb'https?://[^\s\'"<>\x00\r\n]{8,200}', re.IGNORECASE)

_POSH_MARKERS = [
    b'$URLS', b'$server', b'PoshC2', b'Invoke-PoshC2',
    b'Start-Portscan', b'ImplantType', b'$kill_date',
]


class PoshC2Config(mwcp.Parser):
    """Extract PoshC2 stager configuration variables."""

    DESCRIPTION = "PoshC2 C2 Framework Config Extractor"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''
        # Must have at least 2 PoshC2 markers to avoid FP
        hits = sum(1 for m in _POSH_MARKERS if m.lower() in data.lower())
        return hits >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen = set()

        # Server / URL list
        for m in _SERVER_RE.finditer(data):
            raw = m.group(1).decode('utf-8', 'ignore').strip()
            for url in raw.split(','):
                url = url.strip().strip("'\"")
                if url and url not in seen and url.startswith('http'):
                    seen.add(url)
                    self.report.add(C2URL(url))

        # Payload (drop URL)
        for m in _PAYLOAD_RE.finditer(data):
            val = m.group(1).decode('utf-8', 'ignore').strip()
            if val and val not in seen:
                seen.add(val)
                self.report.add(DecodedString(f'[PoshC2-Payload] {val}'))

        # Kill date
        for m in _KILLDATE_RE.finditer(data):
            val = m.group(1).decode('utf-8', 'ignore').strip()
            self.report.add(DecodedString(f'[PoshC2-KillDate] {val}'))

        # Proxy
        for m in _PROXY_RE.finditer(data):
            val = m.group(1).decode('utf-8', 'ignore').strip()
            if val and val.startswith('http'):
                self.report.add(C2URL(val))
                self.report.add(DecodedString(f'[PoshC2-Proxy] {val}'))

        # Fallback: any URLs in PS1 context
        ext = ''
        try:
            import os
            ext = os.path.splitext(getattr(self.file_object, 'name', '') or '')[1].lower()
        except Exception:
            pass
        if ext in ('.ps1', '.psm1') or b'PoshC2' in data:
            for m in _URL_RE.finditer(data):
                url = m.group(0).decode('utf-8', 'ignore').strip()
                if url not in seen:
                    seen.add(url)
                    self.report.add(C2URL(url))
