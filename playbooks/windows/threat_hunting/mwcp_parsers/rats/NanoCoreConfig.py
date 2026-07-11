"""
NanoCoreConfig -- mwcp parser for NanoCore RAT configuration.

NanoCore is a .NET RAT that stores its settings as a serialized object
graph inside a .NET resource. The client's deserializer requires a fixed
set of field/property names to reconstruct the settings object -- these
names are embedded in the .NET metadata strings heap regardless of build
obfuscation of the surrounding code, because .NET reflection-based
deserialization resolves members by name at runtime. A cluster of these
names appearing together is the structural signal; no NanoCore name
string is checked.

Field cluster (from NanoCore's public plugin/settings schema):
    BuildTime, Mutex, Group, RunOnStartup, RequestElevation,
    ConnectionPort, PrimaryConnectionHost, KeepAliveTimeout

Detection: 4+ of these field names within a 4KB window in a .NET PE.

References:
  - malwareconfig.com / public NanoCore settings-schema documentation

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Mutex, DecodedString

# \b word boundaries are load-bearing -- without them "Mutex"/"Group" match
# inside unrelated Windows API export names ("CreateMutexA", "OpenMutexA",
# "TpReleaseCleanupGroup"), which are present in virtually every process's
# mapped kernelbase.dll/ntdll.dll strings and produced a wall of false
# positives against real memory captures.
_CLUSTER_RE = re.compile(
    rb'\b(?:BuildTime|Mutex|Group|RunOnStartup|RequestElevation|'
    rb'ConnectionPort|PrimaryConnectionHost|KeepAliveTimeout)\b')
_MIN_KEY_HITS = 4
_WINDOW_SIZE = 4096

_HOST_RE  = re.compile(
    rb'\bPrimaryConnectionHost\b[\x00-\x08]{0,8}([a-zA-Z0-9\.\-]{3,253})', re.IGNORECASE)
_PORT_RE  = re.compile(rb'\bConnectionPort\b[\x00-\x08]{0,8}(\d{2,5})', re.IGNORECASE)
_MUTEX_RE = re.compile(
    rb'\bMutex\b[\x00-\x08]{0,8}([A-Za-z0-9_\-]{4,64})', re.IGNORECASE)
_GROUP_RE = re.compile(
    rb'\bGroup\b[\x00-\x08]{0,8}([A-Za-z0-9_\-\.]{1,60})', re.IGNORECASE)


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


class NanoCoreConfig(mwcp.Parser):
    """Extract NanoCore RAT configuration field cluster from a .NET PE."""

    DESCRIPTION = "NanoCore RAT Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        return _key_density(data)

    def run(self):
        data = self.file_object.data
        if not data or not _key_density(data):
            return

        host = ''
        m = _HOST_RE.search(data)
        if m:
            host = _clean(m.group(1))

        port = ''
        m = _PORT_RE.search(data)
        if m:
            port = _clean(m.group(1))

        if host:
            addr = f'{host}:{port}' if port else host
            self.report.add(C2Address(addr))

        for m in _MUTEX_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val.lower() not in ('mutex',):
                self.report.add(Mutex(val))
                break

        group = ''
        m = _GROUP_RE.search(data)
        if m:
            group = _clean(m.group(1))
            if group.lower() not in ('group',):
                self.report.add(DecodedString(f'[NanoCore-Group] {group}'))

        if host or port or group:
            self.report.add(DecodedString(
                f'[NanoCore-Config] host={host} port={port} group={group}'))
