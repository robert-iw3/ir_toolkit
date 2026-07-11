"""
GenericC2 -- mwcp parser extracting C2 infrastructure from ANY binary.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP into tools/mwcp/lib/mwcp/parsers/.
Runs against every carved region in memory_enrich.py alongside capa and FLOSS.

NOTE: memory_enrich.py already runs an IOC sweep over all private committed regions.
Results from this mwcp parser are MERGED (deduplicated) with the existing sweep in
memory_enrich.run_mwcp() before any output is written -- no double-counting occurs.
"""

import re
import mwcp
from mwcp.metadata import C2Address, C2URL, Registry

_IP_PORT_RE  = re.compile(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\x00](\d{2,5})')
_URL_RE      = re.compile(rb'https?://[^\x00\s"\'<>]{8,200}', re.IGNORECASE)
_DOMAIN_RE   = re.compile(
    rb'(?:[a-z0-9\-]{2,63}\.){1,5}(?:com|net|org|ru|cn|io|co|tk|top|xyz|pw|cc|biz|info|onion)\b',
    re.IGNORECASE)
_REG_PATH_RE = re.compile(
    rb'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[\\\\/][^\x00\r\n]{8,200}',
    re.IGNORECASE)

_PRIVATE_RE = re.compile(
    r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)'
)
_BENIGN_DOMAIN = re.compile(
    r'(?i)(microsoft\.com|windows\.com|windowsupdate\.com|adobe\.com|'
    r'digicert\.com|verisign\.com|entrust\.net|ocsp\.|crl\.|w3\.org|'
    r'openxmlformats\.org|iptc\.org|purl\.org|youtube\.com|github\.com)'
)


def _decode(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


class GenericC2(mwcp.Parser):
    DESCRIPTION = "Generic C2 / Infrastructure Extractor (all families)"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        data = self.file_object.data
        if not data:
            return
        seen = set()

        for m in _IP_PORT_RE.finditer(data):
            ip, port = _decode(m.group(1)), _decode(m.group(2))
            if _PRIVATE_RE.match(ip):
                continue
            try:
                p = int(port)
                if not (1 <= p <= 65535):
                    continue
            except ValueError:
                continue
            addr = f"{ip}:{port}"
            if addr not in seen:
                seen.add(addr)
                self.report.add(C2Address(addr))

        for m in _URL_RE.finditer(data):
            url = _decode(m.group(0))
            if url and url not in seen and not _BENIGN_DOMAIN.search(url):
                seen.add(url)
                self.report.add(C2URL(url))

        for m in _DOMAIN_RE.finditer(data):
            dom = _decode(m.group(0))
            if dom and len(dom) > 4 and dom not in seen and not _BENIGN_DOMAIN.search(dom):
                seen.add(dom)
                self.report.add(C2Address(dom))

        for m in _REG_PATH_RE.finditer(data):
            path = _decode(m.group(0))
            if path and path not in seen:
                seen.add(path)
                self.report.add(Registry(path))
