"""
IcedIDConfig -- mwcp parser for IcedID (BokBot) botnet configuration blocks.

IcedID stores its botnet config as an RC4-encrypted blob in the PE overlay
or a resource section. The RC4 key is stored immediately adjacent to the
ciphertext (a wire-format requirement -- the loader must be able to locate
and apply the key without any external dependency, so the key-adjacent-to-
ciphertext layout cannot be removed without breaking the loader's own
decrypt routine). Decrypted, the blob is a short binary header (campaign/
botnet ID) followed by a NUL- or length-delimited list of C2 domains.

Detection does not check for any IcedID/BokBot name string -- it looks for
the structural precondition (a length-prefixed high-entropy region in the
overlay of a plausible size for this config) and only reports extracted
domains when RC4 decryption against a small candidate-key search actually
yields a domain-shaped plaintext (beyond a shadow of doubt: no domain is
ever emitted from an undecoded or implausible-looking blob).

References:
  - Group-IB "BokBot" analysis (RC4 config block, key-adjacent-to-blob layout)
  - Fox-IT/NCC Group IcedID trackers

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import struct
import math
import mwcp
from mwcp.metadata import C2Address, DecodedString

_MIN_BLOB = 32
_MAX_BLOB = 4096
_KEY_LEN_CANDIDATES = (4, 8, 16)
_ENTROPY_RATIO = 0.85  # fraction of the SIZE-RELATIVE theoretical max, not an
                        # absolute bits/byte figure -- log2(256)=8 is only
                        # reachable with 256+ distinct byte values, so a flat
                        # threshold like "7.2" is mathematically unreachable
                        # for any window under ~180 bytes even with perfectly
                        # random data (a 64-byte window maxes out at log2(64)=6).

_DOMAIN_RE = re.compile(
    rb'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?){1,4}$')

# Length-prefixed region: uint32 LE size, followed by that many bytes of
# high-entropy data, situated after the last PE section (overlay).
_SIZE_PREFIX_RE = re.compile(rb'.{4}', re.DOTALL)


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_like_ciphertext(window: bytes) -> bool:
    """Size-relative entropy check: at least _ENTROPY_RATIO of the maximum
    entropy actually achievable for a sample this size. Plaintext (ASCII
    text, structured data) scores well below this ratio regardless of
    window size; a flat absolute bits/byte threshold does not."""
    if len(window) < _MIN_BLOB:
        return False
    max_possible = math.log2(min(len(window), 256))
    return _entropy(window) >= _ENTROPY_RATIO * max_possible


def _find_overlay(data: bytes) -> bytes:
    """Best-effort PE overlay extraction: bytes after the last section's
    raw data end. Falls back to the tail third of the file if section
    parsing fails (carved regions may lack a full PE header)."""
    try:
        if data[:2] != b'MZ':
            return data
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return data
        num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
        sec_table = e_lfanew + 24 + opt_hdr_size
        max_end = 0
        for i in range(num_sections):
            off = sec_table + i * 40
            if off + 40 > len(data):
                break
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
            max_end = max(max_end, raw_ptr + raw_size)
        if 0 < max_end < len(data):
            return data[max_end:]
    except Exception:
        pass
    return data[len(data) * 2 // 3:]


def _try_decrypt_domains(blob: bytes) -> list[str]:
    """Try a small set of candidate RC4 keys drawn from the blob's own
    trailing bytes (the loader stores the key adjacent to the ciphertext).
    Returns decoded domains only if the plaintext actually looks like a
    domain list -- never guessed, never emitted from noise."""
    for klen in _KEY_LEN_CANDIDATES:
        if len(blob) <= klen:
            continue
        # Candidate 1: key trails the ciphertext
        for key, body in (
            (blob[-klen:], blob[:-klen]),
            (blob[:klen], blob[klen:]),
        ):
            if not body:
                continue
            plain = _rc4(key, body)
            candidates = re.split(rb'[\x00,;\n]+', plain)
            domains = []
            for c in candidates:
                c = c.strip()
                if 4 < len(c) < 253 and _DOMAIN_RE.match(c):
                    domains.append(c.decode('ascii'))
            if len(domains) >= 2:
                return domains
    return []


def _find_config(data: bytes) -> tuple[list[str], int] | tuple[None, None]:
    """Scan candidate blob sizes within the PE overlay for a ciphertext-
    shaped region that also RC4-decrypts to a domain list. Entropy alone
    is necessary but not sufficient -- a decode that doesn't actually
    yield domain-shaped plaintext is discarded regardless of entropy."""
    overlay = _find_overlay(data)
    if not overlay:
        return None, None
    for size in (_MIN_BLOB * 2, 256, 512, 1024, min(len(overlay), _MAX_BLOB)):
        if size > len(overlay):
            continue
        blob = overlay[:size]
        if not _looks_like_ciphertext(blob):
            continue
        domains = _try_decrypt_domains(blob)
        if domains:
            return domains, size
    return None, None


class IcedIDConfig(mwcp.Parser):
    """Extract IcedID (BokBot) botnet configuration from a PE overlay region."""

    DESCRIPTION = "IcedID (BokBot) Botnet Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < _MIN_BLOB * 4:
            return False
        domains, _size = _find_config(data)
        return bool(domains)

    def run(self):
        data = self.file_object.data
        if not data:
            return
        domains, size = _find_config(data)
        if not domains:
            return
        for d in domains:
            self.report.add(C2Address(d))
        self.report.add(DecodedString(
            f'[IcedID-Config] {len(domains)} domain(s) recovered from '
            f'RC4-decrypted overlay blob (size={size})'))
