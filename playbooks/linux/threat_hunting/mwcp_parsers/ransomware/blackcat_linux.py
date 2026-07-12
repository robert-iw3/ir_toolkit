"""BlackCat (ALPHV) is a single Rust codebase compiled to both Windows and Linux/ESXi
targets -- the Linux/ESXi build uses the identical serde-JSON config schema as the
Windows build, since it's the same struct definition compiled for a different target,
not a separately-written config format.

Builder-required field names: config_id, public_key, extension, note_file_name,
kill_services, kill_processes, exclude_directory_names, exclude_file_names,
exclude_file_extensions, strict_include_paths -- what the binary's own Rust
deserializer expects by field name; an affiliate cannot rename them without the binary
failing to parse its own config, on either OS.

Detection never checks for a "BlackCat"/"ALPHV" name string. Requires 4+ of the schema
field names, then only extracts values from a JSON blob that actually parses."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

_SCHEMA_FIELDS = [
    b'"config_id"', b'"public_key"', b'"extension"', b'"note_file_name"',
    b'"kill_services"', b'"kill_processes"', b'"exclude_directory_names"',
    b'"exclude_file_names"', b'"exclude_file_extensions"', b'"strict_include_paths"',
]
_MIN_FIELD_HITS = 4
_JSON_RE = re.compile(
    rb'\{[^{}]{0,12000}(?:config_id|public_key|note_file_name|exclude_directory_names)'
    rb'[^{}]{0,12000}\}', re.DOTALL)


def identify(data: bytes) -> bool:
    if len(data) < 128:
        return False
    return sum(1 for f in _SCHEMA_FIELDS if f in data) >= _MIN_FIELD_HITS


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    hits = sum(1 for f in _SCHEMA_FIELDS if f in data)
    parsed: Dict[str, Any] = {}
    for m in _JSON_RE.finditer(data):
        try:
            obj = json.loads(m.group(0).decode('utf-8', 'ignore'))
            if isinstance(obj, dict):
                parsed.update(obj)
        except Exception:
            pass
    kill_procs = parsed.get('kill_processes')
    return {
        'family': 'Ransomware: BlackCat/ALPHV-lineage JSON Schema (Linux)',
        'schema_fields_matched': f'{hits}/10',
        'extension': parsed.get('extension'),
        'note_file_name': parsed.get('note_file_name'),
        'config_id': parsed.get('config_id'),
        'kill_processes_count': len(kill_procs) if isinstance(kill_procs, list) else None,
        'note': ('Matches BlackCat/ALPHV\'s own Rust serde-JSON config schema (4+/10 '
                 'builder-required field names) -- same struct definition on the Linux/ESXi '
                 'build as Windows, not a guessed port.'),
    }
