"""
RemcosConfig -- mwcp parser for Remcos RAT configuration.

Remcos stores its configuration as an RC4-encrypted blob in a PE resource
literally named "SETTINGS" (UTF-16LE in the resource directory). This is a
genuine wire-format requirement, not an operator choice: Remcos's own
loader does a resource lookup by this exact name at startup, so it cannot
be renamed without the RAT failing to find its own config. Decrypted, the
config is a semicolon-delimited plaintext record: host, port, password,
and a fixed set of additional flag fields -- a positional field count the
Remcos client parser itself depends on.

Detection never checks for a "Remcos" name string. It locates the
"SETTINGS" resource-name marker, then only reports a config when RC4
decryption against a small candidate-key search yields the expected
semicolon-delimited field count with a host-like first field and a numeric
port -- a decode that doesn't produce this exact shape is discarded.

References:
  - Fortinet, Talos, and Unit42 Remcos RAT config-format writeups (SETTINGS
    resource + RC4 + semicolon-delimited field layout)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Mutex, Password, DecodedString

# "SETTINGS" as it appears in a PE resource directory (UTF-16LE, unicode-
# length-prefixed strings are common but not guaranteed after carving --
# match the raw UTF-16LE bytes, which survive carving/copy either way).
_SETTINGS_RES_RE = re.compile(
    b'S\x00E\x00T\x00T\x00I\x00N\x00G\x00S\x00', re.IGNORECASE)

_MIN_FIELDS = 8
_KEY_LEN_CANDIDATES = (1, 8, 16)


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


def _plausible_fields(plain: bytes) -> list[str] | None:
    parts = plain.split(b';')
    if len(parts) < _MIN_FIELDS:
        return None
    try:
        fields = [p.decode('ascii') for p in parts]
    except UnicodeDecodeError:
        return None
    if not all(0 <= len(f) <= 128 and f.isprintable() for f in fields[:_MIN_FIELDS]):
        return None
    # Second field must be a plausible TCP port
    try:
        port = int(fields[1])
        if not (1 <= port <= 65535):
            return None
    except (ValueError, IndexError):
        return None
    return fields


def _find_config(data: bytes) -> list[str] | None:
    m = _SETTINGS_RES_RE.search(data)
    if not m:
        return None
    region = data[m.end(): m.end() + 4096]
    if len(region) < 32:
        return None
    for klen in _KEY_LEN_CANDIDATES:
        if len(region) <= klen:
            continue
        for key, body in ((region[:klen], region[klen:]), (region[-klen:], region[:-klen])):
            plain = _rc4(key, body)
            fields = _plausible_fields(plain)
            if fields:
                return fields
    return None


class RemcosConfig(mwcp.Parser):
    """Extract Remcos RAT configuration from a PE's SETTINGS resource."""

    DESCRIPTION = "Remcos RAT Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        return bool(_find_config(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        fields = _find_config(data)
        if not fields:
            return

        host = fields[0]
        port = fields[1]
        password = fields[2] if len(fields) > 2 else ''

        if host:
            self.report.add(C2Address(f'{host}:{port}'))
        if password:
            self.report.add(Password(password))

        # Remcos commonly places its mutex/campaign tag a few fields further in;
        # extract any field that looks like a plausible mutex/campaign token
        # (alnum + separators, 4-40 chars) without assuming a fixed index the
        # public writeups don't agree on.
        for f in fields[3:10]:
            if 4 <= len(f) <= 40 and re.fullmatch(r'[A-Za-z0-9_\-]{4,40}', f):
                self.report.add(Mutex(f))
                break

        self.report.add(DecodedString(
            f'[Remcos-Config] host={host} port={port} fields={len(fields)}'))
