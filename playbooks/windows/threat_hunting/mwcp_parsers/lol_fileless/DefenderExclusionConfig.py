"""
DefenderExclusionConfig -- mwcp parser for an embedded PowerShell command
that adds a Windows Defender exclusion before dropping a payload.

`Add-MpPreference` is the PowerShell module cmdlet -- and `-ExclusionPath`/
`-ExclusionProcess` its exact parameter names -- required to programmatically
add a Defender exclusion. There is no behavioral proxy for "the API call
that disables scanning of a specific path": this exact cmdlet+parameter
combination IS the mechanism (Rule 3 exception, same class as
BootExecute's exact string).

A single `-ExclusionPath` argument by itself is not sufficient: legitimate
IT automation/deployment scripts add Defender exclusions too (build
servers, dev tooling). Detection requires the cmdlet call TOGETHER WITH
the exclusion target itself being a staging-directory-shaped path
(Temp/AppData/Public/Downloads) -- reusing this toolkit's established
staging-path signal (see RegistryPersistenceConfig.py / EDR_Toolkit.ps1's
BITS detection) rather than treating any exclusion as suspicious.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, FilePath

_ADD_MP_RE = re.compile(
    rb'(?i)Add-MpPreference\b[^\x00\r\n]{0,300}-Exclusion(?:Path|Process|Extension)\b'
    rb'[^\x00\r\n]{0,20}["\']?([^"\'\x00\r\n]{4,260})')
_STAGING_DIR_RE = re.compile(rb'(?i)\\(?:temp|tmp|appdata|public|downloads|programdata)\\')


class DefenderExclusionConfig(mwcp.Parser):
    """Detect an embedded Add-MpPreference call excluding a staging directory."""

    DESCRIPTION = "Defender Exclusion Staging-Path Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        for m in _ADD_MP_RE.finditer(data):
            if _STAGING_DIR_RE.search(m.group(1)):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        for m in _ADD_MP_RE.finditer(data):
            target = m.group(1)
            if not _STAGING_DIR_RE.search(target):
                continue
            target_s = target.decode('utf-8', 'ignore')
            self.report.add(FilePath(target_s))
            self.report.add(DecodedString(
                f'[DefenderExclusion-StagingPath] Add-MpPreference exclusion targets a '
                f'user-writable staging directory: {target_s}'))
