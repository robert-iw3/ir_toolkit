"""
PowGratConfig -- mwcp parser for PowGrat PowerShell C2 stager configuration.

PowGrat is a minimalist PS1-based C2 stager where the server-side framework
requires these exact PowerShell variable names in the dropper:
    $C2Server  -- full URL of the C2 listener
    $C2Port    -- port number (string)
    $Password  -- stager pre-shared password for session authentication

These names are part of PowGrat's module API contract -- the server-side
handler checks for these exact identifiers.  An operator cannot rename them
without forking both the stager and the server.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, C2Address, Password, DecodedString

# PowGrat server-required variable names (case-insensitive; operators use default casing)
_C2SERVER_RE = re.compile(
    rb'\$C2Server\s*=\s*["\']?(https?://[^\s"\']{4,200})["\']?',
    re.IGNORECASE
)
_C2PORT_RE = re.compile(
    rb'\$C2Port\s*=\s*["\']?(\d{2,5})["\']?',
    re.IGNORECASE
)
_PASSWORD_RE = re.compile(
    rb'\$Password\s*=\s*["\']([^"\']{4,128})["\']',
    re.IGNORECASE
)

# Identification marker set: need all three to avoid PS1 false positives
_MARKER_RE = re.compile(rb'\$C2(?:Server|Port)', re.IGNORECASE)


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


class PowGratConfig(mwcp.Parser):
    """Extract PowGrat C2 stager configuration from PowerShell scripts."""

    DESCRIPTION = "PowGrat PS1 Stager Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        # Require both $C2Server and $C2Port -- $Password alone is too broad
        markers = set(m.group(0).lower() for m in _MARKER_RE.finditer(data))
        return b'$c2server' in markers and b'$c2port' in markers

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen = set()
        server_url = None
        port = None

        for m in _C2SERVER_RE.finditer(data):
            url = _clean(m.group(1))
            if url and url not in seen:
                seen.add(url)
                server_url = url
                self.report.add(C2URL(url))

        for m in _C2PORT_RE.finditer(data):
            p = _clean(m.group(1))
            if p and p not in seen:
                seen.add(p)
                port = p

        for m in _PASSWORD_RE.finditer(data):
            pw = _clean(m.group(1))
            if pw and pw not in seen:
                seen.add(pw)
                self.report.add(Password(pw))

        parts = ['[PowGrat-Config]']
        if server_url:
            parts.append(f'server={server_url}')
        if port:
            parts.append(f'port={port}')
        if server_url or port:
            self.report.add(DecodedString(' '.join(parts)))
