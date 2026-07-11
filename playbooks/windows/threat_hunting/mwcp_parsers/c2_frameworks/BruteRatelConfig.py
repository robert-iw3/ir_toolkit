"""
BruteRatelConfig -- mwcp parser for Brute Ratel C4 (BRc4) payloads.

BRc4 badger payloads have a documented RC4-encrypted config block. The RC4 key
is derived from a hardcoded seed XOR'd against PE metadata. Several public
analysis reports document the config format.

Config fields (decrypted): listener URI, user agent, sleep, jitter, kill date,
spawn process, mutex name.

Detection: BRc4 payloads contain characteristic strings even without decryption:
  - "badger", "BruteRatel", "Ratel", "brute_ratel"
  - Specific API hash values used by BRc4 IAT resolution
  - Named pipe patterns: "\\\\.\\pipe\\ratel"

Fallback approach (without RC4 key): scan for characteristic markers and
extract any plaintext URLs/addresses visible in the binary.

References:
  - Palo Alto Unit 42 BRc4 analysis
  - CISA Advisory AA22-321A
"""

import re
import mwcp
from mwcp.metadata import C2URL, C2Address, Mutex, DecodedString

# BRc4 structural indicators. The named pipe format is part of the C2 protocol
# for SMB beacon mode and cannot be renamed without breaking inter-implant comms.
# Do NOT use "BruteRatel", "badger", or "Ratel" -- operators strip these.
_BRC4_PROTO_INDICATORS = [
    b'\\\\.\\pipe\\ratel',    # SMB C2 pipe name: protocol-required format
    b'BADGER_EXECUTE',         # internal command dispatch token in the agent
    b'badger_http_get',        # HTTP transport function name (wire protocol)
    b'badger_http_post',       # HTTP transport function name (wire protocol)
]

_URL_RE    = re.compile(rb'https?://[^\s\x00\'"<>]{8,200}', re.IGNORECASE)
_PIPE_RE   = re.compile(rb'\\\\[.\w]+\\pipe\\[^\x00\s]{3,80}', re.IGNORECASE)
_MUTEX_RE  = re.compile(rb'(?:mutex|Mutex)\x00{0,4}([A-Za-z0-9_\-\{\}]{4,64})', re.IGNORECASE)
_SLEEP_RE  = re.compile(rb'(?:sleep_time|SleepTime|sleep)\s*[=:\x00]\s*(\d{1,6})', re.IGNORECASE)
_HOST_RE   = re.compile(
    rb'(?:listener|server|host|uri)\s*[=:\x00\'"]{0,3}(https?://[^\s\x00\'"<>]{8,200})',
    re.IGNORECASE
)


class BruteRatelConfig(mwcp.Parser):
    """Extract Brute Ratel C4 badger configuration."""

    DESCRIPTION = "Brute Ratel C4 Config Extractor"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''
        # Protocol indicators that are embedded in the C2 transport protocol,
        # not in debug symbols. An operator cannot rename these without
        # breaking compatibility with the BRc4 team server.
        hits = sum(1 for i in _BRC4_PROTO_INDICATORS if i in data)
        return hits >= 1

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen: set[str] = set()

        # Listener / C2 URLs (most reliably extracted)
        for m in _HOST_RE.finditer(data):
            url = m.group(1).decode('utf-8', 'ignore').strip()
            if url not in seen:
                seen.add(url)
                self.report.add(C2URL(url))

        for m in _URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').strip()
            if url not in seen:
                seen.add(url)
                self.report.add(C2URL(url))

        # Named pipe (C2 channel for SMB-mode)
        for m in _PIPE_RE.finditer(data):
            pipe = m.group(0).decode('utf-8', 'ignore')
            self.report.add(DecodedString(f'[BRc4-Pipe] {pipe}'))

        # Mutex
        for m in _MUTEX_RE.finditer(data):
            val = m.group(1).decode('utf-8', 'ignore').strip('\x00')
            if len(val) > 3:
                self.report.add(Mutex(val))

        # Sleep time
        for m in _SLEEP_RE.finditer(data):
            try:
                sleep = int(m.group(1))
                if 0 < sleep < 86400:
                    self.report.add(DecodedString(f'[BRc4-Sleep] {sleep}s'))
                    break
            except ValueError:
                pass
