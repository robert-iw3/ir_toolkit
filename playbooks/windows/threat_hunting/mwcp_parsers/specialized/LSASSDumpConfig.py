"""
LSASSDumpConfig -- mwcp parser for a credential-dumping tool targeting
lsass.exe: a `MiniDumpWriteDump` API reference paired with an `lsass`
process-name reference in the same file.

Two independent mechanisms, both required:
  1. `MiniDumpWriteDump` -- the exact Win32 API a tool must call to write
     a process memory dump (or its `comsvcs.dll` LOLBin equivalent,
     `MiniDump`, invoked via `rundll32`), not operator-chosen.
  2. An `lsass` process-name reference in the same file -- WER/crash-
     reporting tools call `MiniDumpWriteDump` constantly against
     arbitrary crashing processes; only a dump call co-located with a
     literal reference to the LSASS process name is credential-theft
     relevant.

`MiniDumpWriteDump` alone is legitimate crash-reporting infrastructure
(every Windows Error Reporting handler uses it). An `lsass` string alone
is not evidence (it appears in benign security tooling/documentation).
Only the API reference paired with the LSASS target name, in the same
file, is the credential-dump shape.

Detection never checks for a malware/tool name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_DUMP_API_RE = re.compile(rb'MiniDumpWriteDump|comsvcs\.dll[^\x00\r\n]{0,40}MiniDump\b')
_LSASS_RE = re.compile(rb'lsass\.exe|\blsass\b')


class LSASSDumpConfig(mwcp.Parser):
    """Detect a credential-dump tool: MiniDumpWriteDump API + lsass
    target-name reference."""

    DESCRIPTION = "LSASS Credential Dump Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_DUMP_API_RE.search(data)) and bool(_LSASS_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        api_m = _DUMP_API_RE.search(data)
        lsass_m = _LSASS_RE.search(data)
        if not (api_m and lsass_m):
            return

        self.report.add(DecodedString(
            f'[LSASS-Dump] {api_m.group(0).decode("utf-8","ignore")} + LSASS target reference -- '
            f'credential-dump tool shape'))
