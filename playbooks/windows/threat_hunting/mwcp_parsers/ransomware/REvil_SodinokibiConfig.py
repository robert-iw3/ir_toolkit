"""
REvil_SodinokibiConfig -- mwcp parser for REvil/Sodinokibi JSON configuration.

REvil (Sodinokibi) uses a compact, abbreviated-key JSON config -- documented
across multiple leaked builders and public analyses (McAfee, Group-IB,
KPMG, and others) with a stable schema of short field names the binary's
own deserializer expects: `pk` (public key), `pid` (affiliate/campaign ID),
`sub` (sub-affiliate ID), `dbg` (anti-debug flag), `wht` (whitelist:
folder/file/extension exclusions), `nname` (ransom note filename), `net`
(network-spreading flag), `exp` (self-deletion flag). Deliberately terse
key names -- but still structurally required, not operator-chosen; an
affiliate build cannot rename them without breaking the binary's own config
parser.

Detection never checks for a "REvil"/"Sodinokibi" name string. Requires 4+
of the schema field names in one JSON-shaped region, and only reports
values from a blob that actually parses as JSON.

References:
  - Multiple independent public REvil/Sodinokibi builder-config-schema writeups

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import json
import mwcp
from mwcp.metadata import DecodedString

_SCHEMA_FIELDS = [b'"pk"', b'"pid"', b'"sub"', b'"dbg"', b'"wht"', b'"nname"', b'"net"', b'"exp"']
_MIN_FIELD_HITS = 4

_JSON_RE = re.compile(
    rb'\{[^{}]{0,6000}"pk"[^{}]{0,6000}\}|\{[^{}]{0,6000}"nname"[^{}]{0,6000}\}',
    re.DOTALL)


class REvil_SodinokibiConfig(mwcp.Parser):
    """Extract REvil/Sodinokibi builder-generated JSON configuration."""

    DESCRIPTION = "REvil/Sodinokibi Ransomware Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 128:
            return False
        hits = sum(1 for f in _SCHEMA_FIELDS if f in data)
        return hits >= _MIN_FIELD_HITS

    def run(self):
        data = self.file_object.data
        if not data:
            return
        hits = sum(1 for f in _SCHEMA_FIELDS if f in data)
        if hits < _MIN_FIELD_HITS:
            return

        parsed = {}
        for m in _JSON_RE.finditer(data):
            try:
                obj = json.loads(m.group(0).decode('utf-8', 'ignore'))
                if isinstance(obj, dict):
                    parsed.update(obj)
            except Exception:
                pass

        pid = parsed.get('pid')
        sub = parsed.get('sub')
        if pid is not None or sub is not None:
            self.report.add(DecodedString(f'[REvil-Campaign] pid={pid} sub={sub}'))

        nname = parsed.get('nname')
        if nname:
            self.report.add(DecodedString(f'[REvil-NoteFile] {nname}'))

        wht = parsed.get('wht')
        if isinstance(wht, dict):
            self.report.add(DecodedString(f'[REvil-Whitelist] {list(wht.keys())}'))

        self.report.add(DecodedString(
            f'[REvil-Config] {hits}/8 builder-schema fields matched'))
