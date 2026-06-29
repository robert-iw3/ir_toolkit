"""
AsyncRATConfig -- mwcp parser for AsyncRAT .NET RAT configuration.

AsyncRAT stores its configuration as .NET resource strings. Key config strings
appear as a cluster near each other: "Hosts", "Ports", "Version", "Mutex",
"Certificate", "Pastebin", "BDOS", "Group", "Delay", "Install".

Two storage variants:
  1. Plaintext strings in .NET resources (older builds)
  2. AES-encrypted strings, but the key/IV are also stored as resources -- the
     decrypted form sometimes appears in memory dumps.

This parser takes a string-proximity approach: find "Hosts" and "Ports" keys
and extract the values that follow them. It also scans for base64 strings that
decode to XML (the encrypted resource variant), emitting the base64 blob as a
DecodedString for further analyst processing.

AsyncRAT codebase is also the ancestor of DcRAT, VenomRAT, and several other
commodity RATs -- this parser provides baseline coverage for all of them.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import base64
import mwcp
from mwcp.metadata import C2Address, Mutex, DecodedString

# .NET string header pattern: wide-char or UTF-8 key followed by value.
# In memory / PE, .NET strings often appear as UTF-16LE or UTF-8.
# We scan for the ASCII/UTF-8 key cluster first, then for UTF-16LE.

# Key names that appear in AsyncRAT resource sections
_ASYNCRAT_KEYS = [b'Hosts', b'Ports', b'Version', b'Mutex', b'Certificate',
                  b'Pastebin', b'BDOS', b'Group', b'Delay', b'Install', b'Anti']

# Pattern: "Hosts" near a hostname/IP value, then "Ports" near a port number.
# Both UTF-8 and UTF-16LE variants.
_STR_CLUSTER_RE = re.compile(
    rb'(?:Hosts|Ports|Version|Mutex|Certificate|Pastebin|BDOS|Group|Delay|Install)',
    re.IGNORECASE
)

# Extract value after "Hosts" key (typically follows within 0-200 bytes)
# AsyncRAT separates keys and values with null bytes or length-prefixed .NET strings
_HOSTS_AFTER_RE = re.compile(
    rb'(?:H\x00o\x00s\x00t\x00s\x00|Hosts)[\x00-\x08]{0,8}([a-zA-Z0-9\.\-]{3,253}(?:,[a-zA-Z0-9\.\-]{3,253})*)',
    re.IGNORECASE
)
_PORTS_AFTER_RE = re.compile(
    rb'(?:P\x00o\x00r\x00t\x00s\x00|Ports)[\x00-\x08]{0,8}(\d{2,5}(?:,\d{2,5})*)',
    re.IGNORECASE
)
_MUTEX_AFTER_RE = re.compile(
    rb'(?:M\x00u\x00t\x00e\x00x\x00|Mutex)[\x00-\x08]{0,8}([A-Za-z0-9_\-\{\}]{4,80})',
    re.IGNORECASE
)
_VERSION_AFTER_RE = re.compile(
    rb'(?:V\x00e\x00r\x00s\x00i\x00o\x00n\x00|Version)[\x00-\x08]{0,8}(\d+\.\d+(?:\.\d+)?)',
    re.IGNORECASE
)
_GROUP_AFTER_RE = re.compile(
    rb'(?:G\x00r\x00o\x00u\x00p\x00|Group)[\x00-\x08]{0,8}([A-Za-z0-9_\-\.]{1,60})',
    re.IGNORECASE
)

# Base64 strings >= 64 chars that decode to XML (encrypted config blobs)
_B64_RE = re.compile(rb'[A-Za-z0-9+/]{64,}={0,2}')

# Minimum key cluster density: require at least 3 known keys in a 4KB window
_MIN_KEY_HITS = 3
_WINDOW_SIZE  = 4096


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _check_key_density(data: bytes) -> bool:
    """Return True if data contains at least _MIN_KEY_HITS AsyncRAT key strings in any 4KB window."""
    hits = [m.start() for m in _STR_CLUSTER_RE.finditer(data)]
    if len(hits) < _MIN_KEY_HITS:
        return False
    # Sliding window check
    for i in range(len(hits)):
        window_end = hits[i] + _WINDOW_SIZE
        count = sum(1 for h in hits if hits[i] <= h <= window_end)
        if count >= _MIN_KEY_HITS:
            return True
    return False


class AsyncRATConfig(mwcp.Parser):
    """Extract AsyncRAT (and DcRAT/VenomRAT variant) configuration from PE or memory regions."""

    DESCRIPTION = "AsyncRAT/DcRAT Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        # Quick pre-filter: must be a PE (.NET) or contain the key cluster
        is_pe = data[:2] == b'MZ'
        has_cluster = _check_key_density(data)
        return is_pe or has_cluster

    def run(self):
        data = self.file_object.data
        if not data:
            return

        # Only proceed if we have enough key density to be confident
        if not _check_key_density(data):
            return

        seen = set()
        hosts = []
        ports = []

        # Extract Hosts
        for m in _HOSTS_AFTER_RE.finditer(data):
            raw = _clean(m.group(1))
            for h in raw.split(','):
                h = h.strip()
                if h and h not in hosts:
                    hosts.append(h)

        # Extract Ports
        for m in _PORTS_AFTER_RE.finditer(data):
            raw = _clean(m.group(1))
            for p in raw.split(','):
                p = p.strip()
                if p and p not in ports:
                    ports.append(p)

        # Emit C2Address for each host:port combination
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

        # If we have hosts but no explicit ports, emit hosts alone
        if hosts and not ports:
            for host in hosts:
                if host not in seen:
                    seen.add(host)
                    self.report.add(C2Address(host))

        # Extract Mutex
        for m in _MUTEX_AFTER_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen:
                seen.add(val)
                self.report.add(Mutex(val))

        # Extract Version
        for m in _VERSION_AFTER_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen:
                seen.add(val)
                self.report.add(DecodedString(f'[AsyncRAT-Version] {val}'))

        # Extract Group (campaign tag)
        for m in _GROUP_AFTER_RE.finditer(data):
            val = _clean(m.group(1))
            if val and val not in seen and val not in ('Group', 'BDOS', 'False', 'True'):
                seen.add(val)
                self.report.add(DecodedString(f'[AsyncRAT-Group] {val}'))

        # Scan for base64 blobs that look like encrypted XML config
        for m in _B64_RE.finditer(data):
            b64_bytes = m.group(0)
            try:
                decoded = base64.b64decode(b64_bytes)
                # Check for XML or encrypted blob indicators
                if decoded[:5] in (b'<?xml', b'<Conf') or (
                        len(decoded) > 32 and decoded[:2] in (b'\x1f\x8b', b'\x50\x4b')):
                    tag = f'[AsyncRAT-B64Config] {b64_bytes[:64].decode("ascii", "ignore")}...'
                    if tag not in seen:
                        seen.add(tag)
                        self.report.add(DecodedString(tag))
            except Exception:
                continue
