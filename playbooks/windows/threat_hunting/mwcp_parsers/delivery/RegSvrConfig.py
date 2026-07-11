"""
RegSvrConfig -- mwcp parser for the "Squiblydoo" regsvr32 LOLBin abuse
technique: the exact `/i:<URL> scrobj.dll` command-line combination that
makes regsvr32.exe fetch and execute a remote COM scriptlet.

Two independent mechanisms, both required:
  1. The `/i:` flag with an http(s) argument -- regsvr32's own
     documented `/i[:cmdline]` switch is the only way to pass a remote
     install argument to a scriptlet DLL; a plain local path here is
     ordinary DLL registration, but a URL argument is not something
     regsvr32 supports for any legitimate local-registration use.
  2. A reference to `scrobj.dll` -- the Windows Script Component Runtime
     DLL that actually interprets the fetched .sct scriptlet; this is
     the fixed DLL name the technique depends on, not operator-chosen.

Neither `/i:` alone (used legitimately by some installers for local
cmdline args) nor a `scrobj.dll` reference alone (loaded by unrelated,
benign script-component workflows) is evidence. Only the combination --
a URL-valued `/i:` switch feeding into `scrobj.dll` -- is exclusive to
Squiblydoo.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_SQUIBLYDOO_RE = re.compile(
    rb'(?i)regsvr32(?:\.exe)?[^\x00\r\n]{0,60}/i:(https?://[^\s"\'<>\x00]{6,200})'
    rb'[^\x00\r\n]{0,40}\bscrobj\.dll\b')


class RegSvrConfig(mwcp.Parser):
    """Detect the Squiblydoo regsvr32 /i:<URL> scrobj.dll pattern."""

    DESCRIPTION = "Regsvr32 Squiblydoo LOLBin Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_SQUIBLYDOO_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        m = _SQUIBLYDOO_RE.search(data)
        if not m:
            return

        url = m.group(1).decode('utf-8', 'ignore').rstrip('"\'<> \x00')
        self.report.add(C2URL(url))
        self.report.add(DecodedString(
            f'[Squiblydoo] regsvr32 /i:{url} scrobj.dll -- remote scriptlet execution'))
