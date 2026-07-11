"""
StealcConfig -- mwcp parser for Stealc Stealer C2 configuration.

"Content-Type: application/x-www-form-urlencoded" is an HTTP protocol
requirement, not a malware-chosen string -- but it is also extremely
common in entirely benign software (any HTTP client, telemetry, license
check). A header string plus a nearby URL is NOT sufficient evidence on
its own; that combination is common enough in legitimate binaries that it
is not exclusive to an exfiltration TTP.

Detection therefore requires TWO independent mechanisms together, not one
check repeated:
  1. The exfil primitive: the Content-Type header value with a C2 URL
     within close proximity (the POST target).
  2. The credential-harvesting primitive: the exact SQL query stealers use
     to read Chromium's "Login Data" SQLite table --
     "SELECT origin_url, username_value, password_value FROM logins" (or
     the equivalent Firefox `moz_logins` schema reference) -- because this
     precise column/table naming is a requirement of Chromium's OWN
     database schema, not something the malware author invented, an
     operator cannot alter it without querying the wrong columns and
     getting no data back.

Only a sample exhibiting BOTH the network-exfil shape AND the browser-
credential-schema query is reported -- a benign HTTP client has no reason
to also embed Chromium's internal logins-table schema, and a benign
password manager reading that schema has no reason to also build a bare
POST request to an external URL.

References:
  - Public Stealc config-layout writeups; Chromium's own `Login Data`
    SQLite schema (`logins` table, `origin_url`/`username_value`/
    `password_value` columns) is documented directly by the Chromium project

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_CONTENT_TYPE = b'Content-Type: application/x-www-form-urlencoded'
_URL_RE = re.compile(rb'(?i)https?://[^\s\x00"\'<>]{6,200}')
_PROXIMITY = 256

# Chromium's own SQLite schema for the "Login Data" file -- these exact
# column/table names are a requirement of Chromium's own database, not
# operator-chosen. Firefox's equivalent `moz_logins` table name is included
# as an alternate credential-store schema reference.
_CRED_SCHEMA_RE = re.compile(
    rb'(?i)(?:origin_url[^\x00]{0,40}username_value[^\x00]{0,40}password_value|'
    rb'\bmoz_logins\b)')


class StealcConfig(mwcp.Parser):
    """Extract Stealc Stealer C2 URL -- only when both the exfil POST shape
    AND a browser-credential-schema query are present together."""

    DESCRIPTION = "Stealc Stealer Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64 or _CONTENT_TYPE not in data:
            return False
        if not _CRED_SCHEMA_RE.search(data):
            return False
        idx = data.find(_CONTENT_TYPE)
        window = data[max(0, idx - _PROXIMITY): idx + len(_CONTENT_TYPE) + _PROXIMITY]
        return bool(_URL_RE.search(window))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        if not _CRED_SCHEMA_RE.search(data):
            return
        pos = 0
        found = False
        while True:
            idx = data.find(_CONTENT_TYPE, pos)
            if idx == -1:
                break
            window = data[max(0, idx - _PROXIMITY): idx + len(_CONTENT_TYPE) + _PROXIMITY]
            for m in _URL_RE.finditer(window):
                url = m.group(0).decode('utf-8', 'ignore').rstrip('"\'<> \x00')
                self.report.add(C2URL(url))
                found = True
            pos = idx + len(_CONTENT_TYPE)
        if found:
            self.report.add(DecodedString(
                '[Stealc-Config] C2 URL adjacent to POST Content-Type header, '
                'corroborated by a browser-credential-schema query in the same file'))
