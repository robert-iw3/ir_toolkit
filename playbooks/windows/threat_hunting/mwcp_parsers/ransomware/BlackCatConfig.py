"""
BlackCatConfig -- mwcp parser for BlackCat/ALPHV ransomware JSON configuration.

BlackCat (ALPHV) is written in Rust, and Rust binaries commonly retain their
string data uncompressed/unstripped by default -- unlike most C/C++
ransomware, BlackCat's per-affiliate JSON config is frequently recoverable
as PLAINTEXT directly in the binary, a documented and consistent trait
across BlackCat samples (Microsoft, Sophos, Recorded Future, Trellix
writeups all independently confirm the same JSON schema). Builder-required
field names: `config_id`, `public_key`, `extension`, `note_file_name`,
`kill_services`, `kill_processes`, `exclude_directory_names`,
`exclude_file_names`, `exclude_file_extensions`. These are what the
binary's own Rust deserializer (serde) expects by field name -- an
affiliate cannot rename them without the binary failing to parse its own
config.

Detection never checks for a "BlackCat"/"ALPHV" name string. Requires 4+
of the schema field names, then only extracts values from a JSON blob that
actually parses.

References:
  - Multiple independent public BlackCat/ALPHV JSON-config-schema writeups

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import json
import mwcp
from mwcp.metadata import DecodedString

_SCHEMA_FIELDS = [
    b'"config_id"', b'"public_key"', b'"extension"', b'"note_file_name"',
    b'"kill_services"', b'"kill_processes"', b'"exclude_directory_names"',
    b'"exclude_file_names"', b'"exclude_file_extensions"', b'"strict_include_paths"',
]
_MIN_FIELD_HITS = 4

_JSON_RE = re.compile(
    rb'\{[^{}]{0,12000}(?:config_id|public_key|note_file_name|exclude_directory_names)'
    rb'[^{}]{0,12000}\}', re.DOTALL)


class BlackCatConfig(mwcp.Parser):
    """Extract BlackCat/ALPHV per-affiliate JSON configuration."""

    DESCRIPTION = "BlackCat/ALPHV Ransomware Config Extractor"

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

        ext = parsed.get('extension')
        if ext:
            self.report.add(DecodedString(f'[BlackCat-Extension] .{ext}'))

        note = parsed.get('note_file_name')
        if note:
            self.report.add(DecodedString(f'[BlackCat-NoteFile] {note}'))

        config_id = parsed.get('config_id')
        if config_id:
            self.report.add(DecodedString(f'[BlackCat-ConfigID] {config_id}'))

        kill_procs = parsed.get('kill_processes')
        if isinstance(kill_procs, list) and kill_procs:
            self.report.add(DecodedString(
                f'[BlackCat-KillList] {len(kill_procs)} process target(s): {kill_procs[:10]}'))

        self.report.add(DecodedString(
            f'[BlackCat-Config] {hits}/10 builder-schema fields matched'))
