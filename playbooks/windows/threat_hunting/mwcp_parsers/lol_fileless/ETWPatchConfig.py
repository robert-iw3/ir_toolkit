"""
ETWPatchConfig -- mwcp parser for an embedded ETW-patch: the documented
byte sequence that neutralizes EtwEventWrite (or NtTraceEvent), packaged
together with the exact API name it patches.

The x64 patch shape (`xor eax, eax; ret` -- opcode bytes `33 C0 C3`) is a
publicly-documented, minimal patch that makes EtwEventWrite report success
without ever emitting the event -- silencing ETW-based telemetry (the same
channel most EDR sensors and PowerShell Script Block Logging rely on).
This exact byte sequence IS the mechanism (Rule 3 exception).

A 3-byte patch shape alone is far too short to be meaningful evidence by
itself (guaranteed to coincide by chance in any non-trivial binary).
Detection requires it to appear near a literal reference to the
"EtwEventWrite" or "NtTraceEvent" export name -- the patch bytes ALONE are
not reported.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

# xor eax, eax ; ret  (EtwEventWrite/NtTraceEvent silently "succeeds" without emitting)
_PATCH_BYTES = bytes.fromhex('33C0' 'C3')
_ETW_NAME_RE = re.compile(rb'EtwEventWrite|NtTraceEvent')
_PROXIMITY = 128


class ETWPatchConfig(mwcp.Parser):
    """Detect the EtwEventWrite/NtTraceEvent no-op patch shape near the
    API name it targets."""

    DESCRIPTION = "ETW Patch Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        for m in _ETW_NAME_RE.finditer(data):
            window = data[max(0, m.start() - _PROXIMITY): m.end() + _PROXIMITY]
            if _PATCH_BYTES in window:
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        found = False
        for m in _ETW_NAME_RE.finditer(data):
            window = data[max(0, m.start() - _PROXIMITY): m.end() + _PROXIMITY]
            if _PATCH_BYTES not in window:
                continue
            name = m.group(0).decode('utf-8', 'ignore')
            self.report.add(DecodedString(
                f'[ETW-Patch] no-op return patch bytes near {name} reference @ offset {m.start():#x}'))
            found = True
        if not found:
            return
