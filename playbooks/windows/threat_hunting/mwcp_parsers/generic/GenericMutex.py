"""
GenericMutex -- mwcp parser that extracts mutex candidate strings from ANY binary.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP into tools/mwcp/lib/mwcp/parsers/.
Runs against every carved shellcode/PE region in memory_enrich.py alongside capa and FLOSS.

Approach:
- Scan for CreateMutex / OpenMutex API references and extract strings near those calls
- Apply the same heuristic used by memory_enrich.is_suspicious_object_name()
- Emit confirmed candidates as mwcp.metadata.Mutex (flows into IOCs.json + Memory_Enrichment.md)

Generic coverage: works against ALL malware families, not just ones with family-specific parsers.
"""

import re
import mwcp
from mwcp.metadata import Mutex

_MUTEX_APIS = (
    b'CreateMutexA', b'CreateMutexW',
    b'CreateMutexExA', b'CreateMutexExW',
    b'OpenMutexA', b'OpenMutexW',
)

_MIN_LEN = 4
_MAX_LEN = 260

_BENIGN_PREFIX = re.compile(
    r'(?i)^(Local\\|Global\\|Session\\|__|Microsoft|Windows|WilError|SmartScreen|'
    r'DBWin|MSCTF|RotHint|UrlZones|\{|OLE|\[)'
)
_HEX_TOKEN = re.compile(r'^[0-9A-Fa-f]{6,}$')
_SM0_RE    = re.compile(r'^SM0:\d+:\d+:(.+)$', re.IGNORECASE)
_SM0_BENIGN = re.compile(r'^WilError_\d+$', re.IGNORECASE)
_ASCII_RE  = re.compile(rb'[\x20-\x7e]{4,}')
_WIDE_RE   = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')


def _is_mutex_candidate(name: str) -> bool:
    if not name or len(name) < _MIN_LEN or len(name) > _MAX_LEN:
        return False
    sm0 = _SM0_RE.match(name)
    if sm0:
        return not bool(_SM0_BENIGN.match(sm0.group(1)))
    if _BENIGN_PREFIX.search(name):
        return False
    if _HEX_TOKEN.match(name):
        return True
    if (len(name) >= 6 and ':' not in name and '\\' not in name
            and '-' not in name and ' ' not in name
            and not name.isdigit()):
        return True
    return False


def _strings_near_apis(data: bytes, window: int = 512) -> list:
    offsets = set()
    for api in _MUTEX_APIS:
        for m in re.finditer(re.escape(api), data):
            start = max(0, m.start() - window)
            end   = min(len(data), m.end() + window)
            offsets.add((start, end))
    out = []
    for start, end in offsets:
        chunk = data[start:end]
        for s in _ASCII_RE.findall(chunk):
            try:
                out.append(s.decode('ascii', 'ignore'))
            except Exception:
                pass
        for s in _WIDE_RE.findall(chunk):
            try:
                txt = s.decode('utf-16-le', 'ignore').rstrip('\x00')
                if txt:
                    out.append(txt)
            except Exception:
                pass
    return out


def _all_strings(data: bytes) -> list:
    out = []
    for s in _ASCII_RE.findall(data):
        try:
            out.append(s.decode('ascii', 'ignore'))
        except Exception:
            pass
    for s in _WIDE_RE.findall(data):
        try:
            txt = s.decode('utf-16-le', 'ignore').rstrip('\x00')
            if txt:
                out.append(txt)
        except Exception:
            pass
    return out


class GenericMutex(mwcp.Parser):
    DESCRIPTION = "Generic Mutex Extractor (all families)"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        data = self.file_object.data
        if not data:
            return
        seen = set()
        for name in _strings_near_apis(data):
            name = name.strip()
            if name in seen or not _is_mutex_candidate(name):
                continue
            seen.add(name)
            self.report.add(Mutex(name))
        for name in _all_strings(data):
            name = name.strip()
            if name in seen:
                continue
            if _HEX_TOKEN.match(name) and _MIN_LEN <= len(name) <= 20:
                seen.add(name)
                self.report.add(Mutex(name))
