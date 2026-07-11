"""
COMHijackConfig -- mwcp parser for an embedded COM CLSID hijack: a
`CLSID\\{...}\\InProcServer32` registry path whose DLL value targets a
staging directory.

`CLSID\\{GUID}\\InProcServer32` is Windows COM's own fixed registration
schema (the exact key structure `CoCreateInstance` resolves through) --
not operator-chosen, the same Rule 3 exception class as the other registry
persistence checks in this directory. A CLSID path alone is not evidence:
every installed COM component has one.

Detection requires the CLSID/InProcServer32 key path structure TOGETHER
WITH its DLL value targeting a user-writable staging directory
(Temp/AppData/Public/Downloads) -- reusing this toolkit's established
staging-path signal (RegistryPersistenceConfig.py / EDR_Toolkit.ps1's BITS
detection) as the second, independent mechanism.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, FilePath

_CLSID_INPROC_RE = re.compile(
    rb'(?i)CLSID\\\{[0-9A-Fa-f\-]{36}\}\\InProcServer32[\x00-\x08]{0,8}'
    rb'([A-Za-z]:\\[^\x00"\'\r\n]{4,260}\.dll)')
_STAGING_DIR_RE = re.compile(rb'(?i)\\(?:temp|tmp|appdata|public|downloads|programdata)\\')


class COMHijackConfig(mwcp.Parser):
    """Detect a CLSID\\InProcServer32 registration whose DLL targets a
    staging directory."""

    DESCRIPTION = "COM CLSID Hijack Staging-Path Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        for m in _CLSID_INPROC_RE.finditer(data):
            if _STAGING_DIR_RE.search(m.group(1)):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        found = False
        for m in _CLSID_INPROC_RE.finditer(data):
            dll_path = m.group(1)
            if not _STAGING_DIR_RE.search(dll_path):
                continue
            path_s = dll_path.decode('utf-8', 'ignore')
            self.report.add(FilePath(path_s))
            self.report.add(DecodedString(
                f'[COMHijack-StagingPath] CLSID\\InProcServer32 DLL targets a '
                f'user-writable staging directory: {path_s}'))
            found = True
        if not found:
            return
