"""
MSHTAConfig -- mwcp parser for a malicious HTA (HTML Application): an
inline VBScript/JScript block that instantiates an HTTP-capable COM
object and references a URL, the standard mshta.exe C2/download-cradle
shape.

Two independent mechanisms, both required:
  1. Instantiation of a network-capable COM ProgID: `Msxml2.XMLHTTP`,
     `Microsoft.XMLHTTP`, or `Msxml2.ServerXMLHTTP` -- an HTA script
     cannot issue an HTTP request without naming one of these exact,
     spec-fixed COM ProgIDs (Rule 3 exception: the ProgID string IS the
     mechanism, a script has no other way to reach the network).
  2. A URL literal in the same file.

An HTA containing a URL alone is not evidence (URLs appear in legitimate
help/about text). A `Msxml2.XMLHTTP` ProgID alone could appear in
benign internal tooling. Only the co-occurrence of the network COM
object instantiation AND a URL is the download-cradle shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_XHR_COM_RE = re.compile(
    rb'(?i)CreateObject\s*\(\s*["\'](Msxml2\.(?:Server)?XMLHTTP(?:\.\d\.\d)?|'
    rb'Microsoft\.XMLHTTP)["\']')

_URL_RE = re.compile(rb'(?i)https?://[^\s"\'<>\x00]{6,200}')

_HTA_TAG_RE = re.compile(rb'(?i)<(?:hta:application|script)\b')


class MSHTAConfig(mwcp.Parser):
    """Detect an HTA download cradle: network COM ProgID + URL."""

    DESCRIPTION = "MSHTA Download-Cradle Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32 or not _HTA_TAG_RE.search(data):
            return False
        return bool(_XHR_COM_RE.search(data)) and bool(_URL_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        com_m = _XHR_COM_RE.search(data)
        if not com_m:
            return

        found_url = False
        for m in _URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').rstrip('"\'<> \x00')
            self.report.add(C2URL(url))
            found_url = True
        if not found_url:
            return

        self.report.add(DecodedString(
            f'[MSHTA-Cradle] network COM ProgID {com_m.group(1).decode("utf-8","ignore")} '
            f'+ embedded URL -- download-cradle shape'))
