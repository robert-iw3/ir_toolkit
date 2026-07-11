"""
NjRATConfig -- mwcp parser for NjRAT (Bladabindi) configuration blocks.

NjRAT stores its configuration as pipe-delimited plaintext embedded in the PE
binary (often in .rsrc or .text). The canonical format is:

    host|port|registry_key|name|campaign[|...]

The port is always a numeric string (2-5 digits) between the first two pipes.
Variants exist with fewer fields (host|port alone) or additional fields.

NjRAT is extremely common in MENA/SEA threat actor campaigns. This parser runs
against all file types because config strings can appear in memory dumps, packed
payloads, and .NET resources without a complete PE header.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Mutex, DecodedString

# Core pattern: host|port|... where port is 2-5 digits.
# Allow host to be an IP, hostname, or domain (3-100 chars, no pipes/nulls).
# Looser variant also catches host|port-only configs.
_NJRAT_FULL_RE = re.compile(
    rb'([^\|\x00\r\n]{3,100})\|(\d{2,5})\|([^\|\x00\r\n]{0,80})\|([^\|\x00\r\n]{0,50})\|',
    re.IGNORECASE
)
# Minimal: host|port (pipe-delimited, port 2-5 digits, followed by another pipe or end-of-reasonable-string)
_NJRAT_MIN_RE = re.compile(
    rb'([^\|\x00\r\n]{3,100})\|(\d{2,5})\|',
    re.IGNORECASE
)

# Filter out obvious garbage: the "host" field must look plausible
_VALID_HOST_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\.\-_]{1,98}[a-zA-Z0-9])?$'
)

# Pipe-safe character blacklist in host field
_JUNK_RE = re.compile(r'[<>"\'\x00-\x1f\x7f-\xff]')


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _host_looks_valid(host: str) -> bool:
    """Sanity-check the extracted host field to reduce FP rate."""
    if not host or len(host) < 3:
        return False
    if _JUNK_RE.search(host):
        return False
    # Must be plausible hostname/IP characters
    return bool(_VALID_HOST_RE.match(host))


class NjRATConfig(mwcp.Parser):
    """Extract NjRAT (Bladabindi) pipe-delimited configuration from PE or memory regions."""

    DESCRIPTION = "NjRAT/Bladabindi Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        # Run on everything: PE, UNKNOWN (carved memory), scripts
        return True

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen_c2 = set()
        seen_decoded = set()

        # Try full pattern first (host|port|key|name|campaign|...)
        for m in _NJRAT_FULL_RE.finditer(data):
            host_b    = m.group(1)
            port_b    = m.group(2)
            key_b     = m.group(3)
            name_b    = m.group(4)

            host = _clean(host_b)
            port = _clean(port_b)
            key  = _clean(key_b)
            name = _clean(name_b)

            if not _host_looks_valid(host):
                continue

            try:
                p = int(port)
                if not (1 <= p <= 65535):
                    continue
            except ValueError:
                continue

            c2 = f'{host}:{port}'
            if c2 not in seen_c2:
                seen_c2.add(c2)
                self.report.add(C2Address(c2))

            # Campaign / mutex from name or key fields
            for field_val in (name, key):
                if field_val and len(field_val) > 1 and field_val not in seen_decoded:
                    seen_decoded.add(field_val)
                    self.report.add(Mutex(field_val))

            # Full config line as a decoded string for analyst review
            raw_str = _clean(m.group(0))
            tag = f'[NjRAT-Config] {raw_str}'
            if tag not in seen_decoded:
                seen_decoded.add(tag)
                self.report.add(DecodedString(tag))

        # Minimal fallback: host|port| -- catches stripped/partial configs
        if not seen_c2:
            for m in _NJRAT_MIN_RE.finditer(data):
                host = _clean(m.group(1))
                port = _clean(m.group(2))

                if not _host_looks_valid(host):
                    continue
                try:
                    p = int(port)
                    if not (1 <= p <= 65535):
                        continue
                except ValueError:
                    continue

                # Require at least a dot (domain) or exactly 4 octets (IP) to reduce FP
                has_dot = '.' in host
                is_ip = bool(re.match(
                    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
                if not has_dot and not is_ip:
                    continue

                c2 = f'{host}:{port}'
                if c2 not in seen_c2:
                    seen_c2.add(c2)
                    self.report.add(C2Address(c2))
                    self.report.add(DecodedString(f'[NjRAT-MinConfig] {host}|{port}'))
