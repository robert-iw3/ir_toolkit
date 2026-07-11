"""
DropboxC2Config -- mwcp parser for Dropbox-as-C2: a malware sample using
Dropbox's file-content API as a covert C2/exfil channel (config pull /
result exfil via a Dropbox app folder instead of a bespoke C2 protocol).

Two independent mechanisms, both required:
  1. A Dropbox content API endpoint: `content.dropboxapi.com/2/files/
     upload` or `/2/files/download` -- Dropbox's own fixed REST API
     path, not operator-chosen.
  2. The `Dropbox-API-Arg` HTTP header name -- Dropbox's own
     protocol-required custom header that MUST accompany every content
     API call (it carries the JSON call arguments Dropbox's API spec
     demands go in a header rather than the body for these endpoints).
     No other reasonable use of this exact header name exists.

A Dropbox API endpoint alone is an ordinary, widely-used cloud storage
service. Only the endpoint paired with the exact header its own API
protocol requires, in the same file, is the Dropbox-as-C2-channel shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_DROPBOX_API_RE = re.compile(
    rb'(?i)https?://content\.dropboxapi\.com/2/files/(?:upload|download)\b')
_DROPBOX_HEADER_RE = re.compile(rb'(?i)Dropbox-API-Arg["\']?\s*[:=]')


class DropboxC2Config(mwcp.Parser):
    """Detect Dropbox-as-C2: content API endpoint + Dropbox-API-Arg header."""

    DESCRIPTION = "Dropbox API C2 Channel Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_DROPBOX_API_RE.search(data)) and bool(_DROPBOX_HEADER_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        api_m = _DROPBOX_API_RE.search(data)
        hdr_m = _DROPBOX_HEADER_RE.search(data)
        if not (api_m and hdr_m):
            return

        url = api_m.group(0).decode('utf-8', 'ignore')
        self.report.add(C2URL(url))
        self.report.add(DecodedString(
            f'[Dropbox-C2] content API endpoint + Dropbox-API-Arg header -- '
            f'Dropbox-as-C2-channel shape'))
