"""
PastebinC2Config -- mwcp parser for Pastebin-as-C2: a malware sample
fetching its config/command list from a raw Pastebin paste (a
long-documented, low-cost dead-drop technique -- the malware embeds a
fixed paste ID and reads whatever the operator currently has posted
there, letting them rotate infrastructure without recompiling).

Two independent mechanisms, both required:
  1. A Pastebin raw-paste URL: `pastebin.com/raw/` followed by
     Pastebin's own fixed 8-character alphanumeric paste-ID format --
     the exact URL structure Pastebin's site issues, not
     operator-chosen.
  2. An HTTP fetch-and-consume primitive in the same file: .NET
     `WebClient.DownloadString`/`DownloadData`, PowerShell
     `Invoke-WebRequest`/`Invoke-RestMethod`, or a `Msxml2.XMLHTTP` /
     `URLDownloadToFile` COM/API call -- the actual mechanism that
     turns the URL into consumed data.

A bare `pastebin.com/raw/...` URL alone is not evidence -- Pastebin is
a legitimate public service referenced constantly in benign scripts,
documentation, and tooling (installer one-liners, gist mirrors). Only
the URL paired with a fetch primitive that actually reads it, in the
same file, is the dead-drop-C2 shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_PASTEBIN_RAW_RE = re.compile(rb'(?i)https?://pastebin\.com/raw/[A-Za-z0-9]{8}\b')
_FETCH_PRIMITIVE_RE = re.compile(
    rb'(?i)(WebClient\s*\(\s*\)\s*\.\s*Download(?:String|Data|File)|'
    rb'Invoke-(?:WebRequest|RestMethod)|'
    rb'Msxml2\.(?:Server)?XMLHTTP|'
    rb'URLDownloadToFile[AW]?)')


class PastebinC2Config(mwcp.Parser):
    """Detect Pastebin-as-C2: raw-paste URL + HTTP fetch primitive."""

    DESCRIPTION = "Pastebin Dead-Drop C2 Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_PASTEBIN_RAW_RE.search(data)) and bool(_FETCH_PRIMITIVE_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        url_m = _PASTEBIN_RAW_RE.search(data)
        fetch_m = _FETCH_PRIMITIVE_RE.search(data)
        if not (url_m and fetch_m):
            return

        url = url_m.group(0).decode('utf-8', 'ignore')
        self.report.add(C2URL(url))
        self.report.add(DecodedString(
            f'[Pastebin-C2] raw paste URL + fetch primitive '
            f'({fetch_m.group(0)[:40].decode("utf-8","ignore")}) -- dead-drop C2 shape'))
