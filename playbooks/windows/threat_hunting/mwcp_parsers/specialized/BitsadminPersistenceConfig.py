"""
BitsadminPersistenceConfig -- mwcp parser for BITS Jobs persistence
(MITRE ATT&CK T1197): a BITS job's completion-notification command set
to re-execute a payload, rather than an ordinary staged download.

Two independent mechanisms, both required:
  1. The `/SetNotifyCmdLine` bitsadmin verb (or PowerShell's
     `-NotifyCmdLine` / `Set-BitsTransfer -NotifyCmdLine` equivalent)
     -- the BITS API's own fixed command for registering a program to
     run when a job completes or errors; this is the actual
     persistence primitive (T1197), distinct from a one-shot download.
  2. The notify command line's target being either a script interpreter
     (`powershell.exe`/`cmd.exe`/`wscript.exe`/`mshta.exe`/`rundll32.exe`)
     or a path in a user-writable staging directory (Temp/AppData/
     Public/Downloads/ProgramData) -- reusing this toolkit's established
     staging-path signal (RegistryPersistenceConfig.py / EDR_Toolkit.ps1's
     BITS detection).

`/SetNotifyCmdLine` alone is not evidence -- legitimate BITS-based
software updaters use it to relaunch an installer after a background
download completes. Only the notify command targeting a script
interpreter or a staging-directory path, in the same file, is the
persistence-abuse shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, FilePath

_NOTIFY_CMDLINE_RE = re.compile(
    rb'(?i)(?:/SetNotifyCmdLine\s+\S+\s+|-NotifyCmdLine\s+)'
    rb'["\']?([A-Za-z]:\\[^\x00"\'\r\n]{4,260})["\']?')
_SCRIPT_INTERPRETER_RE = re.compile(
    rb'(?i)\\(powershell(?:_ise)?|cmd|wscript|cscript|mshta|rundll32)\.exe\b')
_STAGING_DIR_RE = re.compile(rb'(?i)\\(?:temp|tmp|appdata|public|downloads|programdata)\\')


class BitsadminPersistenceConfig(mwcp.Parser):
    """Detect BITS Jobs persistence: /SetNotifyCmdLine + script interpreter
    or staging-path target."""

    DESCRIPTION = "BITS Jobs (T1197) Persistence Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        for m in _NOTIFY_CMDLINE_RE.finditer(data):
            target = m.group(1)
            if _SCRIPT_INTERPRETER_RE.search(target) or _STAGING_DIR_RE.search(target):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        found = False
        for m in _NOTIFY_CMDLINE_RE.finditer(data):
            target = m.group(1)
            interp_m = _SCRIPT_INTERPRETER_RE.search(target)
            staging_m = _STAGING_DIR_RE.search(target)
            if not (interp_m or staging_m):
                continue
            target_s = target.decode('utf-8', 'ignore')
            self.report.add(FilePath(target_s))
            reason = 'script interpreter' if interp_m else 'staging directory'
            self.report.add(DecodedString(
                f'[BITS-Persistence] /SetNotifyCmdLine target ({reason}): {target_s} -- '
                f'T1197 completion-notification persistence shape'))
            found = True
        if not found:
            return
