"""
QuasarRATConfig -- mwcp parser for Quasar RAT configuration.

Quasar is an open-source .NET RAT.  It stores its configuration as .NET
resource strings.  The key differentiators from AsyncRAT are:
    Port        -- SINGULAR (not "Ports" like AsyncRAT)
    Password    -- AES-128 key seed (distinct from AsyncRAT's crypto approach)
    Tag         -- campaign tag / victim grouping label
    ShowConsole -- console visibility flag (not in AsyncRAT)

These field names are part of Quasar's resource schema -- the server reads
them by name.  The combination of Port (singular) + Password + Tag uniquely
identifies Quasar vs AsyncRAT / DcRAT.

Extracts: C2 host:port, mutex (GUID format), AES key seed (Password), campaign
tag, version string.

References:
    https://github.com/quasar/Quasar (public)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Mutex, Password, DecodedString

# Cluster of Quasar-specific resource key names. \b word boundaries are
# load-bearing -- without them these substrings match inside unrelated
# Windows API export names ("Mutex" inside "CreateMutexA"/"OpenMutexA"),
# which are present in virtually every process's mapped kernelbase.dll/
# ntdll.dll strings and produced a wall of false positives against real
# memory captures.
_CLUSTER_RE = re.compile(
    rb'\b(?:Hosts|Port(?!s)|Password|Mutex|Tag|ShowConsole|LogDirectoryName|Version|InstallName)\b',
    re.IGNORECASE
)
_MIN_KEY_HITS = 3
_WINDOW_SIZE  = 4096

# Port (singular only -- word-boundary via negative lookahead for 's')
_HOSTS_RE   = re.compile(
    rb'\bHosts\b[\x00-\x08]{0,8}([a-zA-Z0-9\.\-]{3,253}(?:;[a-zA-Z0-9\.\-]{3,253})*)',
    re.IGNORECASE
)
_PORT_RE    = re.compile(
    rb'\bPort(?!s)\b[\x00-\x08]{0,8}(\d{2,5})',
    re.IGNORECASE
)
_MUTEX_RE   = re.compile(
    rb'\bMutex\b[\x00-\x08]{0,8}([A-Za-z0-9_\-\{\}]{4,80})',
    re.IGNORECASE
)
_PASSWORD_RE = re.compile(
    rb'\bPassword\b[\x00-\x08]{0,8}([A-Za-z0-9!@#\$%^&\*\-_\.]{6,64})',
    re.IGNORECASE
)
_TAG_RE     = re.compile(
    rb'\b(?:Tag|LogDirectoryName)\b[\x00-\x08]{0,8}([A-Za-z0-9_\-\.]{1,64})',
    re.IGNORECASE
)
_VERSION_RE = re.compile(
    rb'\bVersion\b[\x00-\x08]{0,8}(\d+\.\d+\.\d+\.\d+)',
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


class QuasarRATConfig(mwcp.Parser):
    """Extract Quasar RAT configuration from PE or memory regions."""

    DESCRIPTION = "Quasar RAT Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        # Require Port (singular) AND Password AND key cluster density
        has_port = bool(re.search(rb'Port(?!s)[\x00-\x08]', data, re.IGNORECASE))
        has_password = b'Password' in data
        return has_port and has_password and _key_density(data)

    def run(self):
        data = self.file_object.data
        if not data:
            return

        if not _key_density(data):
            return

        seen  = set()
        hosts = []
        port  = None

        for m in _HOSTS_RE.finditer(data):
            for h in _clean(m.group(1)).split(';'):
                h = h.strip()
                if h and h not in hosts:
                    hosts.append(h)

        for m in _PORT_RE.finditer(data):
            port = _clean(m.group(1))
            break

        for host in hosts:
            if port:
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
            else:
                if host not in seen:
                    seen.add(host)
                    self.report.add(C2Address(host))

        for m in _MUTEX_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen:
                seen.add(val)
                self.report.add(Mutex(val))

        for m in _PASSWORD_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen and val not in ('Password', 'False', 'True'):
                seen.add(val)
                self.report.add(Password(val))
                self.report.add(DecodedString(f'[Quasar-AESKey] {val}'))
                break

        tag = None
        for m in _TAG_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen and val not in ('Tag', 'Logs', 'Password'):
                seen.add(val)
                tag = val
                self.report.add(DecodedString(f'[Quasar-Tag] {val}'))
                break

        ver = None
        for m in _VERSION_RE.finditer(data):
            ver = _clean(m.group(1))
            break

        label = f'[Quasar-Config] hosts={hosts}'
        if port:
            label += f' port={port}'
        if ver:
            label += f' ver={ver}'
        if tag:
            label += f' tag={tag}'
        self.report.add(DecodedString(label))
