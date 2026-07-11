"""
DcRATConfig -- mwcp parser for DcRAT (Dark Crystal RAT) configuration.

DcRAT is a publicly released .NET RAT that is a fork of AsyncRAT.  It uses
the same Hosts/Ports/Mutex .NET resource string structure but adds two
protocol-required fields that are absent from vanilla AsyncRAT:
    HVNC            -- Hidden VNC module capability flag (True/False)
    Serversignature -- RSA server certificate fingerprint for mutual auth

These two fields uniquely identify DcRAT vs AsyncRAT builds:
  - An operator cannot rename them without breaking the DcRAT server's
    certificate verification and HVNC dispatch logic.
  - VenomRAT (another DcRAT fork) also has HVNC, so this parser covers both.

Extraction: same host/port/mutex logic as AsyncRAT + DcRAT-specific fields.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Mutex, DecodedString, Password

# DcRAT-unique markers (both absent from vanilla AsyncRAT)
_DCRAT_MARKER_RE = re.compile(rb'HVNC|Serversignature', re.IGNORECASE)

# Core key cluster (same as AsyncRAT)
_CLUSTER_RE = re.compile(
    rb'(?:Hosts|Ports|Version|Mutex|Certificate|HVNC|Serversignature|Group|Delay|Install)',
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
_VERSION_RE = re.compile(
    rb'(?:V\x00e\x00r\x00s\x00i\x00o\x00n\x00|Version)[\x00-\x08]{0,8}(\d+\.\d+(?:\.\d+)?)',
    re.IGNORECASE
)
_GROUP_RE   = re.compile(
    rb'(?:G\x00r\x00o\x00u\x00p\x00|Group)[\x00-\x08]{0,8}([A-Za-z0-9_\-\.]{1,60})',
    re.IGNORECASE
)
_SERVERSIG_RE = re.compile(
    rb'Serversignature[\x00-\x08]{0,8}([A-Za-z0-9+/=]{8,128})',
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


class DcRATConfig(mwcp.Parser):
    """Extract DcRAT / VenomRAT configuration from PE or memory regions."""

    DESCRIPTION = "DcRAT/VenomRAT Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        # Require at least one DcRAT-specific marker AND the key cluster
        has_marker = bool(_DCRAT_MARKER_RE.search(data))
        return has_marker and (data[:2] == b'MZ' or _key_density(data))

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

        for m in _VERSION_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen:
                seen.add(val)
                self.report.add(DecodedString(f'[DcRAT-Version] {val}'))

        for m in _GROUP_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen and val not in ('Group', 'HVNC', 'False', 'True'):
                seen.add(val)
                self.report.add(DecodedString(f'[DcRAT-Group] {val}'))

        for m in _SERVERSIG_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen:
                seen.add(val)
                self.report.add(Password(val))
                self.report.add(DecodedString(f'[DcRAT-Serversignature] {val[:32]}...'))

        # Emit family label for triage
        hvnc = b'HVNC' in data
        self.report.add(DecodedString(f'[DcRAT-Config] hosts={hosts} ports={ports} hvnc={hvnc}'))
