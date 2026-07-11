"""
LockBitConfig -- mwcp parser for LockBit 3.0 (Black) builder-generated configuration.

The LockBit 3.0 (Black) builder leaked in 2022. Its output config (consumed
by the LockBit binary's own JSON deserializer) uses a documented, stable
field-name schema: `encrypt_filename`, `kill_processes`, `local_disks`,
`network_disks`, `note_full_paths`, `anti_debug`. These are structurally
required by the binary's own config parser -- an affiliate customizes the
VALUES (which processes to kill, which disks to touch) but not the field
NAMES the leaked builder's C code expects, so this cluster survives
affiliate-to-affiliate customization the same way AsyncRAT's field cluster
survives operator rebuilds.

This detects the SCHEMA, not the group -- relevant beyond LockBit's own
operational status. Law enforcement disruption of LockBit's own
infrastructure (e.g. Operation Cronos, Feb 2024) does not retire a leaked
builder: builders that leak keep getting reused by unrelated actors
independently of the original group's fate, and a binary built from that
leaked tooling still emits this exact config shape regardless of who ran
the builder or when.

Detection never checks for a "LockBit" name string. It requires 4+ of the
builder-schema field names within one JSON-shaped region.

References:
  - LockBit 3.0 (Black) builder leak (2022) and subsequent public analyses
    of the leaked C source and its generated config schema, plus ongoing
    tracking of builder reuse by unrelated actors after the leak

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import json
import mwcp
from mwcp.metadata import DecodedString, Mutex

_BUILDER_FIELDS = [
    b'"encrypt_filename"', b'"kill_processes"', b'"local_disks"',
    b'"network_disks"', b'"note_full_paths"', b'"anti_debug"',
    b'"kill_services"', b'"impers_priv"',
]
_MIN_FIELD_HITS = 4

_JSON_RE = re.compile(
    rb'\{[^{}]{0,8000}(?:encrypt_filename|kill_processes|local_disks|network_disks)'
    rb'[^{}]{0,8000}\}', re.DOTALL)


class LockBitConfig(mwcp.Parser):
    """Extract LockBit 3.0 (Black) builder-generated configuration."""

    DESCRIPTION = "LockBit 3.0 (Black) Builder Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 128:
            return False
        hits = sum(1 for f in _BUILDER_FIELDS if f in data)
        return hits >= _MIN_FIELD_HITS

    def run(self):
        data = self.file_object.data
        if not data:
            return
        hits = sum(1 for f in _BUILDER_FIELDS if f in data)
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

        kill_list = parsed.get('kill_processes') or parsed.get('kill_services')
        if isinstance(kill_list, list) and kill_list:
            self.report.add(DecodedString(
                f'[LockBit-KillList] {len(kill_list)} process/service target(s): '
                f'{kill_list[:10]}'))

        note = parsed.get('note_full_paths')
        if note:
            self.report.add(DecodedString(f'[LockBit-NotePath] {note}'))

        for flag in ('encrypt_filename', 'local_disks', 'network_disks', 'anti_debug'):
            if flag in parsed:
                self.report.add(DecodedString(f'[LockBit-Config] {flag}={parsed[flag]}'))

        self.report.add(DecodedString(
            f'[LockBit-Config] {hits}/8 builder-schema fields matched'))
