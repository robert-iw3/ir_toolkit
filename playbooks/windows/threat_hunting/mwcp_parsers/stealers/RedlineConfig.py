"""
RedlineConfig -- mwcp parser for Redline Stealer .NET resource configuration.

Redline stores its config as a base64-encoded XML blob inside a .NET
resource. The XML schema (root element with C2 host/port/key child
elements) is what Redline's own deserializer requires to reconstruct the
settings object -- the base64+XML SHAPE is the structural signal, not any
Redline name string.

Detection: locate base64 candidate blobs of plausible size, decode, and
only accept a candidate whose decoded bytes are well-formed XML containing
2+ child elements and an embedded IP:port or URL -- a decode that isn't
valid XML with an embedded address is discarded, never guessed.

References:
  - Public Redline Stealer .NET resource / XML-config writeups

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import base64
import xml.etree.ElementTree as ET
import mwcp
from mwcp.metadata import C2Address, C2URL, DecodedString

_B64_RE = re.compile(rb'[A-Za-z0-9+/]{40,4000}={0,2}')
_ADDR_RE = re.compile(r'((?:\d{1,3}\.){3}\d{1,3}:\d{1,5}|https?://[^\s<>"\']{6,200})')


def _try_decode_xml_config(candidate: bytes) -> tuple[str, list[str]] | None:
    try:
        raw = base64.b64decode(candidate, validate=True)
    except Exception:
        return None
    if not raw.startswith(b'<') or len(raw) < 20:
        return None
    try:
        text = raw.decode('utf-8', 'ignore')
        root = ET.fromstring(text)
    except Exception:
        return None
    if len(list(root)) < 2:
        return None
    addrs = _ADDR_RE.findall(text)
    if not addrs:
        return None
    return text, addrs


class RedlineConfig(mwcp.Parser):
    """Extract Redline Stealer configuration from a base64-encoded XML .NET resource."""

    DESCRIPTION = "Redline Stealer Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 128:
            return False
        for m in _B64_RE.finditer(data):
            if _try_decode_xml_config(m.group(0)):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        for m in _B64_RE.finditer(data):
            result = _try_decode_xml_config(m.group(0))
            if not result:
                continue
            text, addrs = result
            for addr in addrs:
                if addr.startswith('http'):
                    self.report.add(C2URL(addr))
                else:
                    self.report.add(C2Address(addr))
            self.report.add(DecodedString(f'[Redline-Config] {text[:400]}'))
            return
