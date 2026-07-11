"""
GoogleSheetC2Config -- mwcp parser for Google Sheets-as-C2: a malware
sample reading/writing a Google Sheet through Google's own Sheets API
as a covert C2 channel (a documented technique in loaders like
"More_eggs" and various Sheets-backed stealer panels).

Two independent mechanisms, both required:
  1. A Google Sheets API endpoint: `sheets.googleapis.com/v4/spreadsheets/`
     -- Google's own fixed REST API path, not operator-chosen.
  2. A Google API key in Google's own fixed format: `AIza` followed by
     35 URL-safe base64 characters -- the exact prefix/length Google
     Cloud issues every API key with, dictated by Google, not the
     malware author.

A Sheets API endpoint alone is an ordinary, widely-used Google service.
A string matching the AIza-prefixed key shape alone could be a
credential-scanner false positive from unrelated Google Cloud config.
Only the API endpoint AND a Google API key together, in the same file,
is the Sheets-as-C2-channel shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, Credential, DecodedString

_SHEETS_API_RE = re.compile(
    rb'(?i)https?://sheets\.googleapis\.com/v4/spreadsheets/[A-Za-z0-9_-]{10,80}')
_GOOGLE_API_KEY_RE = re.compile(rb'AIza[0-9A-Za-z_-]{35}')


class GoogleSheetC2Config(mwcp.Parser):
    """Detect Google Sheets-as-C2: Sheets API endpoint + Google API key."""

    DESCRIPTION = "Google Sheets API C2 Channel Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_SHEETS_API_RE.search(data)) and bool(_GOOGLE_API_KEY_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        api_m = _SHEETS_API_RE.search(data)
        key_m = _GOOGLE_API_KEY_RE.search(data)
        if not (api_m and key_m):
            return

        url = api_m.group(0).decode('utf-8', 'ignore')
        self.report.add(C2URL(url))
        key = key_m.group(0).decode('utf-8', 'ignore')
        self.report.add(Credential(password=key).add_tag('google_api_key'))
        self.report.add(DecodedString(
            f'[GoogleSheets-C2] Sheets API endpoint + Google API key ({key[:8]}...) -- '
            f'Sheets-as-C2-channel shape'))
