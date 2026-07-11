"""
MetasploitPayload -- mwcp parser for a reverse-TCP shellcode stager
(Metasploit-generated and metasm-derived stagers use this exact shape;
other custom shellcode using the same position-independent-code idiom
can also match -- this detects the STAGER SHAPE, not a tool-name string).

Two independent mechanisms, both required:
  1. A GetPC-stub-into-PEB-walk prologue: `\\xfc\\xe8` (cld; call $+N,
     the position-independent "get my own address" idiom) followed
     within the call target by `\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b`
     (pushad; mov ebp,esp; xor edx,edx; mov eXX,fs:[...] -- the PEB
     access used to walk InMemoryOrderModuleList for API resolution
     without import table entries). This exact instruction sequence is
     how position-independent x86 Windows shellcode resolves API
     addresses at runtime; it is not a string an operator can strip
     without rewriting the stager's actual mechanism.
  2. An embedded `sockaddr_in` structure: `\\x02\\x00` (AF_INET, as
     `connect()` expects it packed in the structure) followed by a
     2-byte big-endian port and a plausible 4-byte IPv4 address --
     reverse_tcp shellcode passes this raw structure directly to
     `connect()`, so LHOST/LPORT are necessarily embedded in exactly
     this binary shape for the stager to function at all.

The PEB-walk prologue alone is a general position-independent-shellcode
idiom (used by many shellcode generators, not exclusively Metasploit).
A `\\x02\\x00`-prefixed byte run alone is common coincidental binary
noise. Only the PEB-walk stager prologue paired with a plausible
embedded sockaddr_in structure, in the same buffer, is the
reverse-TCP-stager shape worth surfacing.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import struct
import mwcp
from mwcp.metadata import C2URL, DecodedString

_GETPC_PEBWALK_RE = re.compile(
    rb'\xfc\xe8[\x00-\xff]{2}\x00\x00\x60\x89\xe5\x31\xd2\x64[\x8a\x8b]')

_SOCKADDR_IN_RE = re.compile(rb'\x02\x00([\x00-\xff]{2})([\x00-\xff]{4})')


def _plausible_port(port_bytes: bytes) -> bool:
    return struct.unpack('>H', port_bytes)[0] != 0


def _plausible_ipv4(ip_bytes: bytes) -> bool:
    if ip_bytes[0] in (0, 127, 255):
        return False
    return ip_bytes != b'\xff\xff\xff\xff'


class MetasploitPayload(mwcp.Parser):
    """Detect a reverse-TCP shellcode stager: PEB-walk prologue + embedded
    sockaddr_in (LHOST/LPORT)."""

    DESCRIPTION = "Reverse-TCP Shellcode Stager (LHOST/LPORT) Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64 or not _GETPC_PEBWALK_RE.search(data):
            return False
        for m in _SOCKADDR_IN_RE.finditer(data):
            if _plausible_port(m.group(1)) and _plausible_ipv4(m.group(2)):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        prologue_m = _GETPC_PEBWALK_RE.search(data)
        if not prologue_m:
            return

        found = False
        for m in _SOCKADDR_IN_RE.finditer(data):
            port_bytes, ip_bytes = m.group(1), m.group(2)
            if not (_plausible_port(port_bytes) and _plausible_ipv4(ip_bytes)):
                continue
            port = struct.unpack('>H', port_bytes)[0]
            lhost = '.'.join(str(b) for b in ip_bytes)
            self.report.add(C2URL(f'tcp://{lhost}:{port}'))
            self.report.add(DecodedString(
                f'[Metasploit-Stager] PEB-walk GetPC prologue + embedded sockaddr_in '
                f'LHOST={lhost} LPORT={port} -- reverse-TCP shellcode stager shape'))
            found = True
        if not found:
            return
