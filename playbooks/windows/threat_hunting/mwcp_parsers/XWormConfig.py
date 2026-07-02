"""
XWormConfig -- mwcp parser for XWorm RAT configuration.

XWorm is a commodity .NET RAT that is similar to AsyncRAT but uses distinct
field names in its config resource section:
    XWorm      -- version banner (e.g. "XWorm V5.6") -- family label
    Ver        -- version string (distinct from AsyncRAT's "Version")
    BSOD       -- crash/kill switch flag (AsyncRAT uses "BDOS")
    Hwid       -- hardware ID field (not in AsyncRAT)

The Hosts/Ports/Mutex structure is shared with AsyncRAT.  The presence of
"XWorm" + "Ver" (not "Version") + "BSOD" (not "BDOS") collectively identify
XWorm configs.  An operator cannot rename them without breaking server-side
XWorm panel parsing.

Detection: "XWorm" string + key cluster with >=3 XWorm-specific keys.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Mutex, DecodedString

# XWorm-specific markers (all absent from vanilla AsyncRAT)
_XWORM_MARKER_RE = re.compile(rb'[Xx][Ww]orm', re.IGNORECASE)

_CLUSTER_RE = re.compile(
    rb'(?:Hosts|Ports|Ver(?!sion)|Mutex|BSOD|Hwid|Group|Delay|Pastebin|XWorm)',
    re.IGNORECASE
)
_MIN_KEY_HITS = 3
_WINDOW_SIZE  = 4096

_HOSTS_RE   = re.compile(
    rb'(?:H\x00o\x00s\x00t\x00s\x00|Hosts)[\x00-\x08]{0,8}([a-zA-Z0-9\.\-]{3,253}(?:,[a-zA-Z0-9\.\-]{3,253})*)',
    re.IGNORECASE
)
_PORTS_RE   = re.compile(
    rb'(?:P\x00o\x00r\x00t\x00s\x00|Ports)[\x00-\x08]{0,8}(\d{2,5}(?:,\d{2,5})*)',
    re.IGNORECASE
)
_MUTEX_RE   = re.compile(
    rb'(?:M\x00u\x00t\x00e\x00x\x00|Mutex)[\x00-\x08]{0,8}([A-Za-z0-9_\-\{\}]{4,80})',
    re.IGNORECASE
)
_VER_RE     = re.compile(
    rb'Ver(?!sion)[\x00-\x08]{0,8}(\d+\.\d+(?:\.\d+)?)',
    re.IGNORECASE
)
_GROUP_RE   = re.compile(
    rb'(?:G\x00r\x00o\x00u\x00p\x00|Group)[\x00-\x08]{0,8}([A-Za-z0-9_\-\.]{1,60})',
    re.IGNORECASE
)


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _key_density(data: bytes) -> bool:
    hits = [m.start() for m in _CLUSTER_RE.finditer(data)]
    if len(hits) < _MIN_KEY_HITS:
        return False
    for i in range(len(hits)):
        end = hits[i] + _WINDOW_SIZE
        if sum(1 for h in hits if hits[i] <= h <= end) >= _MIN_KEY_HITS:
            return True
    return False


class XWormConfig(mwcp.Parser):
    """Extract XWorm RAT configuration from PE or memory regions."""

    DESCRIPTION = "XWorm RAT Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        # Require "XWorm" marker AND the key cluster
        return bool(_XWORM_MARKER_RE.search(data)) and _key_density(data)

    def run(self):
        data = self.file_object.data
        if not data:
            return

        if not _key_density(data):
            return

        seen  = set()
        hosts = []
        ports = []

        for m in _HOSTS_RE.finditer(data):
            for h in _clean(m.group(1)).split(','):
                h = h.strip()
                if h and h not in hosts:
                    hosts.append(h)

        for m in _PORTS_RE.finditer(data):
            for p in _clean(m.group(1)).split(','):
                p = p.strip()
                if p and p not in ports:
                    ports.append(p)

        for host in hosts:
            for port in ports:
                try:
                    p = int(port)
                    if not (1 <= p <= 65535):
                        continue
                except ValueError:
                    continue
                c2 = f'{host}:{port}'
                if c2 not in seen:
                    seen.add(c2)
                    self.report.add(C2Address(c2))

        if hosts and not ports:
            for host in hosts:
                if host not in seen:
                    seen.add(host)
                    self.report.add(C2Address(host))

        for m in _MUTEX_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen:
                seen.add(val)
                self.report.add(Mutex(val))

        ver = None
        for m in _VER_RE.finditer(data):
            ver = _clean(m.group(1))
            break

        for m in _GROUP_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen and val not in ('Group', 'BSOD', 'False', 'True', 'XWorm'):
                seen.add(val)
                self.report.add(DecodedString(f'[XWorm-Group] {val}'))

        label = f'[XWorm-Config] hosts={hosts} ports={ports}'
        if ver:
            label += f' ver={ver}'
        self.report.add(DecodedString(label))
