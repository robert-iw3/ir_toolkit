"""
RegistryPersistenceConfig -- mwcp parser for an embedded registry-
persistence key path whose value data points at a staging directory.

The registry key paths themselves (`...\\CurrentVersion\\Run`,
`...\\CurrentVersion\\RunOnce`, `...\\Session Manager\\AppInit_DLLs`,
`...\\Image File Execution Options\\...`) are Windows' own fixed key
names -- not operator-chosen strings, the same Rule 3 exception class as
BootExecute's exact value. But a dropper embedding a Run-key PATH alone
proves nothing: legitimate installers write to these same keys constantly.

Detection reuses this toolkit's existing, already-validated principle from
EDR_Toolkit.ps1 (`readme.md`: "Staging-path destination is the BITS
signal -- not the job display name"): the registry key path is the fixed
mechanism, but the actual TP signal is that key's VALUE pointing at a
user-writable staging directory (Temp/AppData/Public/Downloads) rather
than a normal installed-program location. Both together -- the exact key
path AND a staging-path-shaped value -- is what's exclusive to the TTP.

Detection never checks for a malware name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, FilePath

_PERSIST_KEYS_RE = re.compile(
    rb'(?i)\\(?:CurrentVersion\\Run(?:Once)?|Session Manager\\AppInit_DLLs|'
    rb'Image File Execution Options\\[^\\\x00]{1,64}\\Debugger)\b')

_VALUE_DATA_RE = re.compile(rb'[A-Za-z]:\\[^\x00"\'\r\n]{4,260}\.(?:exe|dll|ps1|vbs|bat|cmd)\b',
                            re.IGNORECASE)
_STAGING_DIR_RE = re.compile(rb'(?i)\\(?:temp|tmp|appdata|public|downloads|programdata)\\')


class RegistryPersistenceConfig(mwcp.Parser):
    """Detect an embedded Run/AppInit/IFEO key path whose value targets a
    user-writable staging directory."""

    DESCRIPTION = "Registry Persistence Staging-Path Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32 or not _PERSIST_KEYS_RE.search(data):
            return False
        for m in _VALUE_DATA_RE.finditer(data):
            if _STAGING_DIR_RE.search(m.group(0)):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        key_m = _PERSIST_KEYS_RE.search(data)
        if not key_m:
            return
        found = False
        for m in _VALUE_DATA_RE.finditer(data):
            path = m.group(0)
            if not _STAGING_DIR_RE.search(path):
                continue
            path_s = path.decode('utf-8', 'ignore')
            self.report.add(FilePath(path_s))
            found = True
        if found:
            self.report.add(DecodedString(
                f'[RegistryPersistence-StagingPath] key={key_m.group(0).decode("utf-8","ignore")} '
                f'value targets a user-writable staging directory'))
