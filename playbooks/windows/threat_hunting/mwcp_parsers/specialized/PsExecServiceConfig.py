"""
PsExecServiceConfig -- mwcp parser for PsExec-style remote service
execution: the `PSEXESVC` named-pipe/service-name marker paired with a
service binary path targeting a user-writable staging directory.

Two independent mechanisms, both required:
  1. The `PSEXESVC` name -- Sysinternals PsExec's own fixed default
     service/pipe name (installed as a Windows service named `PSEXESVC`
     communicating over the named pipe of the same name), not
     operator-chosen.
  2. A service binary path targeting a staging directory (Temp/AppData/
     Public/Downloads/ProgramData) -- reusing this toolkit's established
     staging-path signal.

PsExec is legitimate, widely-used sysadmin tooling -- the `PSEXESVC` name
alone is not evidence of misuse (it appears in countless benign remote-
administration sessions). Only PSEXESVC paired with a service binary
staged in a user-writable directory (rather than a proper install path)
is the shape worth surfacing.

Detection never checks for a malware/tool name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, FilePath

_PSEXESVC_RE = re.compile(rb'PSEXESVC')
# Case-sensitive, applied to the FULL buffer -- avoid (?i) here (perf; see
# README.md "Guidance for Writing a New Parser"). Matches both cases of the
# .exe extension explicitly instead.
_SERVICE_PATH_RE = re.compile(rb'[A-Za-z]:\\[^\x00"\'\r\n]{4,260}\.[eE][xX][eE]')
# Applied only to an already-matched, <=264-byte path substring -- small
# bounded input, so (?i) here has no meaningful perf cost.
_STAGING_DIR_RE = re.compile(rb'(?i)\\(?:temp|tmp|appdata|public|downloads|programdata)\\')


class PsExecServiceConfig(mwcp.Parser):
    """Detect PsExec-style service execution: PSEXESVC marker + staging-
    path service binary."""

    DESCRIPTION = "PsExec Remote Service Staging-Path Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24 or not _PSEXESVC_RE.search(data):
            return False
        for m in _SERVICE_PATH_RE.finditer(data):
            if _STAGING_DIR_RE.search(m.group(0)):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data or not _PSEXESVC_RE.search(data):
            return
        found = False
        for m in _SERVICE_PATH_RE.finditer(data):
            path = m.group(0)
            if not _STAGING_DIR_RE.search(path):
                continue
            path_s = path.decode('utf-8', 'ignore')
            self.report.add(FilePath(path_s))
            self.report.add(DecodedString(
                f'[PsExec-Staging] PSEXESVC marker + service binary in staging directory: '
                f'{path_s}'))
            found = True
        if not found:
            return
