"""
EmotedConfig -- mwcp parser for Emotet C2 IP-list configuration.

Emotet embeds a static fallback C2 list as an XOR-encoded, count-prefixed
array of fixed-size records: [4-byte IPv4][2-byte port][2-byte flags].
Like QakBot's offline list (see QakBotConfig.py, same record shape,
independently documented by public Emotet trackers), the decoded record
layout is dictated by Emotet's own connection-attempt loop -- it cannot
dial a fallback C2 without a valid routable IPv4+port pair in this exact
shape. Emotet's static lists are typically much larger than QakBot's
(15-60+ entries), which is itself part of the structural signal.

Detection never checks for an "Emotet"/"Heodo" name string -- only the
count and internal consistency of the decoded record array (every record
must independently parse as a routable IPv4 + a port drawn from the small
set of ports actually used for C2/service traffic -- see QakBotConfig.py's
docstring for why the port check specifically, not "any 1-65535", is what
keeps this evidentiary rather than coincidental across a 512x256 brute-
force search space; a decode that produces even one implausible record is
discarded entirely, never partially reported).

This covers the single-byte-XOR-encoded static list variant. Emotet builds
that protect the list with a per-sample RC4/AES key with no adjacent key
material in the binary are out of scope for a static/file-only parser --
honestly unextractable without the network-delivered key, not guessed.

References:
  - Binary Defense "Emotet C2 tracker", Unit42 Emotet config-format writeups

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import struct
import mwcp
from mwcp.metadata import C2Address, DecodedString

_RECORD_SIZE  = 8
_MIN_RECORDS  = 8      # Emotet lists run much larger than QakBot's -- part of the signal
_MAX_RECORDS  = 300
_SCAN_WINDOW  = 16384
_SCAN_OFFSETS = 512

_PRIVATE_FIRST_OCTET = (0, 10, 127)
_PRIVATE_172 = range(16, 32)

_PLAUSIBLE_PORTS = frozenset({
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    2222, 3389, 4443, 5900, 7080, 8000, 8080, 8443, 9001, 50000, 65400,
})


def _is_routable_ipv4(b: bytes) -> bool:
    o1, o2, o3, o4 = b
    if o1 in _PRIVATE_FIRST_OCTET or o1 == 255:
        return False
    if o1 == 172 and o2 in _PRIVATE_172:
        return False
    if o1 == 192 and o2 == 168:
        return False
    if o1 == 169 and o2 == 254:
        return False
    return True


_XOR_TABLES = [bytes(b ^ key for b in range(256)) for key in range(256)]


def _parse_records(chunk: bytes) -> list[tuple[str, int]]:
    n_records = min(len(chunk) // _RECORD_SIZE, _MAX_RECORDS)
    if n_records < _MIN_RECORDS:
        return []
    out = []
    for i in range(n_records):
        rec = chunk[i * _RECORD_SIZE:(i + 1) * _RECORD_SIZE]
        if len(rec) < _RECORD_SIZE:
            break
        ip_bytes = rec[0:4]
        if not _is_routable_ipv4(ip_bytes):
            return []
        port = struct.unpack('<H', rec[4:6])[0]
        if port not in _PLAUSIBLE_PORTS:
            return []
        out.append(('.'.join(str(b) for b in ip_bytes), port))
    return out if len(out) >= _MIN_RECORDS else []


def _find_c2_list(data: bytes) -> list[tuple[str, int]]:
    """Brute-force the single-byte XOR key space over a bounded window.
    Decodes the WHOLE window once per key via bytes.translate() (C-speed)
    instead of re-XORing per-offset with a Python generator -- the latter
    (512x256 repeated per-byte XOR generators) is what made this
    pathological against multi-MB carved regions."""
    window = data[:_SCAN_WINDOW]
    if len(window) < _RECORD_SIZE * _MIN_RECORDS:
        return []
    for key in range(256):
        decoded = window.translate(_XOR_TABLES[key]) if key else window
        for offset in range(0, min(len(decoded), _SCAN_OFFSETS)):
            chunk = decoded[offset:offset + _RECORD_SIZE * _MAX_RECORDS]
            if len(chunk) < _RECORD_SIZE * _MIN_RECORDS:
                break
            records = _parse_records(chunk)
            if records:
                return records
    return []


class EmotedConfig(mwcp.Parser):
    """Extract Emotet static fallback C2 IP:port list from a PE or carved
    memory region (XOR-encoded record-list variant only)."""

    DESCRIPTION = "Emotet C2 IP-List Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < _RECORD_SIZE * _MIN_RECORDS:
            return False
        return bool(_find_c2_list(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        records = _find_c2_list(data)
        if not records:
            return
        for ip, port in records:
            self.report.add(C2Address(f'{ip}:{port}'))
        self.report.add(DecodedString(
            f'[Emotet-Config] {len(records)} C2 IP:port record(s) decoded from '
            f'XOR-encoded fixed-record fallback list'))
