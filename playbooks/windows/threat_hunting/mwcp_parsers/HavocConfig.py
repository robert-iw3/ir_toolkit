"""
HavocConfig -- mwcp parser for Havoc C2 demon payloads.

Havoc C2 demon payloads have a documented binary config structure that is
prepended to the shellcode. The config block begins with a 4-byte magic
(0xDEADBEEF by default, but operator-configurable) followed by config fields.

Structure (from public Havoc source analysis):
  [magic:4][config_size:4][agent_id:4][sleep:4][jitter:4]
  [killdate:8][working_hours:8][hostname:variable][uri:variable]
  [useragent:variable][headers:variable][spawn_x86:variable][spawn_x64:variable]

Fallback: scan for JSON config blob (newer Havoc versions) or string cluster
  containing Havoc-specific markers: "DemonID", "SleepTime", "Injection.Technique"

References:
  - HavocFramework/Havoc source (GitHub)
  - Zscaler Havoc analysis
"""

import re
import json
import struct
import mwcp
from mwcp.metadata import C2URL, C2Address, DecodedString

_HAVOC_MAGIC = b'\xde\xad\xbe\xef'  # default demon magic

# Structural indicators: these are internal field names in Havoc's binary
# config format and its demon agent communication protocol. They survive
# operator customization because they are encoded in the agent's self-
# describing config block, not in debug symbols.
# Do NOT check for "Havoc", "demon", or "TeamServer" -- those are stripped.
_HAVOC_PROTO_FIELDS = [
    b'DemonID',      # agent ID field in the check-in packet -- protocol-required
    b'SleepTime',    # field name in the binary config block serialization
    b'Injection',    # injection settings sub-struct -- protocol-required
    b'encrypted_exchange_check',   # key exchange protocol field
    b'sleeping for', # internal agent status log format string
]

_JSON_RE = re.compile(
    rb'\{[^{}]{20,4000}(?:DemonID|SleepTime|Teamserver|Injection\.Technique)[^{}]{0,4000}\}',
    re.DOTALL | re.IGNORECASE
)

_SLEEP_RE = re.compile(rb'(?:SleepTime|Sleep)\s*[=:]\s*(\d{1,6})', re.IGNORECASE)
_HOST_RE  = re.compile(rb'(?:Teamserver|Host)\s*[=:]\s*[\x22\x27]?([a-zA-Z0-9\.\-]{4,100}:\d{2,5})', re.IGNORECASE)
_URL_RE   = re.compile(rb'https?://[^\s\x00\'"<>]{8,200}', re.IGNORECASE)


class HavocConfig(mwcp.Parser):
    """Extract Havoc C2 demon configuration."""

    DESCRIPTION = "Havoc C2 Framework Config Extractor"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''
        # Check 1: binary magic (0xDEADBEEF) followed by plausible config_size
        if _HAVOC_MAGIC in data:
            pos = data.find(_HAVOC_MAGIC)
            if pos + 8 <= len(data):
                import struct
                try:
                    size = struct.unpack_from('<I', data, pos + 4)[0]
                    if 0 < size < 8192:
                        return True
                except Exception:
                    pass
        # Check 2: protocol field names required by Havoc's internal serialization
        hits = sum(1 for f in _HAVOC_PROTO_FIELDS if f in data)
        return hits >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen: set[str] = set()

        # 1. Binary magic-based extraction
        pos = 0
        while True:
            pos = data.find(_HAVOC_MAGIC, pos)
            if pos == -1:
                break
            try:
                if pos + 24 > len(data):
                    break
                config_size = struct.unpack_from('<I', data, pos + 4)[0]
                sleep       = struct.unpack_from('<I', data, pos + 12)[0]
                jitter      = struct.unpack_from('<I', data, pos + 16)[0]

                if 0 < config_size < 8192 and 0 < sleep < 86400:
                    self.report.add(DecodedString(
                        f'[Havoc-Config] magic=0xDEADBEEF config_size={config_size} '
                        f'sleep={sleep}s jitter={jitter}%'
                    ))
                    # Extract variable-length strings after the fixed header (offset 24+)
                    blob = data[pos + 24: pos + 24 + min(config_size, 4096)]
                    for m in _URL_RE.finditer(blob):
                        url = m.group(0).decode('utf-8', 'ignore').strip()
                        if url not in seen:
                            seen.add(url)
                            self.report.add(C2URL(url))
            except struct.error:
                pass
            pos += 4

        # 2. JSON config (newer Havoc versions or extracted configs)
        for m in _JSON_RE.finditer(data):
            try:
                obj = json.loads(m.group(0).decode('utf-8', 'ignore'))
                if isinstance(obj, dict):
                    host = obj.get('Teamserver', obj.get('Host', ''))
                    if host:
                        self.report.add(C2Address(host))
                    sleep = obj.get('SleepTime', obj.get('Sleep', 0))
                    if sleep:
                        self.report.add(DecodedString(f'[Havoc-Sleep] {sleep}s'))
                    technique = obj.get('Injection', {})
                    if isinstance(technique, dict):
                        t = technique.get('Technique', '')
                        if t:
                            self.report.add(DecodedString(f'[Havoc-Injection] {t}'))
            except Exception:
                pass

        # 3. String-based fallback
        for m in _HOST_RE.finditer(data):
            host = m.group(1).decode('utf-8', 'ignore').strip()
            if host not in seen:
                seen.add(host)
                self.report.add(C2Address(host))

        for m in _URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').strip()
            if url not in seen:
                seen.add(url)
                self.report.add(C2URL(url))
