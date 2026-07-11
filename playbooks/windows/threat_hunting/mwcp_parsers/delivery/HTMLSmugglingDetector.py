"""
HTMLSmugglingDetector -- mwcp parser for HTML smuggling: a Blob-construction
JS API call combined with a large base64-encoded data payload, used to
assemble/decode a malicious file client-side and evade network-layer
inspection of the file itself (Nobelium/APT29, IcedID, and many
downstream loader campaigns).

Two independent mechanisms, both required:
  1. A Blob-construction API call: `msSaveOrOpenBlob`/`msSaveBlob` (legacy
     IE/Edge) or `new Blob([...` -- the exact JS API surface a script must
     call to turn a decoded byte array into a downloadable file, not
     operator-chosen.
  2. A base64 payload of at least 4KB inline in the page -- large enough to
     be an embedded executable/archive rather than a small inline image or
     icon (the common, benign use of small base64 data URIs in legitimate
     pages).

A Blob API call alone is used by countless legitimate web apps (export-
to-file features). A base64 blob alone is extremely common (embedded
images/fonts). Only the co-occurrence of a Blob-construction call AND a
payload-sized base64 blob in the same page is the smuggling shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

# Matched against data.lower() -- (?i) case-folding across a multi-MB
# buffer combined with variable-whitespace (\s*) alternation was the
# dominant identify() cost against large carved regions; lower()-once +
# case-sensitive match is equivalent and the lower() step runs at C speed.
_BLOB_API_RE = re.compile(
    rb'(msSaveOrOpenBlob|msSaveBlob|new\s+Blob\s*\(\s*\[)'.lower())

# Possessive quantifier ({1000,}+, Python 3.11+) -- this repeated fixed-width
# group is catastrophic-backtracking-prone against dense base64-like runs in
# large carved regions; possessive matching (no backtracking into the
# repetition once matched) is safe here since a base64 blob has no
# alternative parse we'd need to backtrack for.
_B64_BLOB_RE = re.compile(rb'(?:[A-Za-z0-9+/]{4}){1000,}+={0,2}')

_MIN_B64_LEN = 4096


class HTMLSmugglingDetector(mwcp.Parser):
    """Detect HTML smuggling: Blob-construction API + large inline base64
    payload."""

    DESCRIPTION = "HTML Smuggling Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64 or not _BLOB_API_RE.search(data.lower()):
            return False
        return any(len(m.group(0)) >= _MIN_B64_LEN for m in _B64_BLOB_RE.finditer(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        blob_m = _BLOB_API_RE.search(data.lower())
        if not blob_m:
            return
        best = None
        for m in _B64_BLOB_RE.finditer(data):
            if len(m.group(0)) >= _MIN_B64_LEN:
                if best is None or len(m.group(0)) > len(best.group(0)):
                    best = m
        if best is None:
            return

        self.report.add(DecodedString(
            f'[HTML-Smuggling] Blob API ({blob_m.group(0).decode("utf-8","ignore")}) '
            f'+ inline base64 payload of {len(best.group(0))} bytes -- '
            f'client-side file assembly/decode shape'))
