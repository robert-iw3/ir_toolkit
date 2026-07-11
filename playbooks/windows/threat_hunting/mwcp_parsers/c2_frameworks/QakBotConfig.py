"""
QakBotConfig -- mwcp parser for QakBot (Qbot) C2 IP-list configuration.

QakBot embeds its offline C2 list as an XOR-encoded, count-prefixed array of
fixed-size records: [4-byte IPv4][2-byte port][2-byte flags]. The record
layout is a wire-format requirement of QakBot's own connection-attempt loop
-- the binary cannot dial a C2 host without a valid IPv4+port pair in this
exact shape, so no amount of build obfuscation changes the DECODED record
structure, only the XOR key protecting it in the file.

Detection never checks for a "QakBot"/"Qbot" name string. It brute-forces
the single-byte XOR key space (identical strategy to CobaltStrikeConfig.py's
key search) over a length-prefixed region and only accepts a key/offset
when the decoded bytes form >=6 repeating 8-byte records that each parse
as a valid, non-private, non-loopback IPv4 address AND a port drawn from
the small set of ports actually used for C2/service traffic. The port
restriction is load-bearing, not cosmetic: "any value 1-65535 is a valid
port" passes ~99.998% of random 2-byte values, which is not selective
enough across a 512-offset x 256-key brute-force search space -- the
realistic C2/service port set is what actually keeps this evidentiary,
not the record count.

References:
  - Zscaler ThreatLabz / Deep Instinct / VMware Carbon Black QakBot config trackers

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import struct
import mwcp
from mwcp.metadata import C2Address, DecodedString

_RECORD_SIZE = 8       # 4-byte IP + 2-byte port + 2-byte flags
_MIN_RECORDS = 6
_MAX_RECORDS = 200
_SCAN_WINDOW = 8192     # bound the brute-force search to a reasonable region

_PRIVATE_FIRST_OCTET = (0, 10, 127)
_PRIVATE_172 = range(16, 32)

# Realistic C2/service ports observed across QakBot builds and generic C2
# infrastructure. This is the actual filter (see module docstring) -- "any
# 1-65535" is not selective enough to survive a 512x256 brute-force search.
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
    """Parse an ALREADY-DECODED chunk as a contiguous array of
    [ip4][port2][flags2] records. Returns [] unless the WHOLE window is
    consistent (every record must be a routable IP and a plausible port)
    -- partial/coincidental matches are rejected."""
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
            return []   # one bad record invalidates this key/offset entirely
        port = struct.unpack('<H', rec[4:6])[0]
        if port not in _PLAUSIBLE_PORTS:
            return []
        out.append(('.'.join(str(b) for b in ip_bytes), port))
    return out if len(out) >= _MIN_RECORDS else []


def _find_c2_list(data: bytes) -> list[tuple[str, int]]:
    """Brute-force the single-byte XOR key space over a bounded window.
    The XOR-decode itself uses bytes.translate() (C-speed, O(window) per
    key) instead of a per-byte Python generator -- decoding the WHOLE
    window once per key, then scanning offsets on the pre-decoded bytes,
    avoids re-XORing the same bytes across all 512 candidate offsets
    (512x256 repeated per-byte XOR generators is what made this pathological
    against multi-MB carved regions)."""
    window = data[:_SCAN_WINDOW]
    if len(window) < _RECORD_SIZE * _MIN_RECORDS:
        return []
    for key in range(256):
        decoded = window.translate(_XOR_TABLES[key]) if key else window
        for offset in range(0, min(len(decoded), 512)):
            chunk = decoded[offset:offset + _RECORD_SIZE * _MAX_RECORDS]
            if len(chunk) < _RECORD_SIZE * _MIN_RECORDS:
                break
            records = _parse_records(chunk)
            if records:
                return records
    return []


class QakBotConfig(mwcp.Parser):
    """Extract QakBot (Qbot) C2 IP:port list from a PE or carved memory region."""

    DESCRIPTION = "QakBot (Qbot) C2 IP-List Config Extractor"

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
            f'[QakBot-Config] {len(records)} C2 IP:port record(s) decoded from '
            f'XOR-encoded fixed-record list'))
