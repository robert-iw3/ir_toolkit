"""
MacroExtractor -- mwcp parser for a downloader-shaped Office macro: an
auto-exec entry point combined with a Win32 API declaration for a
network-fetch or execution primitive.

VBA cannot call an arbitrary Win32 API without an explicit
`Declare Function ... Lib "..."` statement naming the exact function --
this is a structural requirement of VBA's own FFI mechanism, not an
operator choice (Rule 3 exception, same class as AmsiScanBuffer). Detects
Declare statements for `URLDownloadToFileA/W`, `ShellExecuteA/W`, or
`WinExec` -- the three classic macro-downloader Win32 primitives.

An auto-exec entry point alone (Document_Open/AutoOpen/Workbook_Open) is
present in countless benign macros (opening a template, showing a
welcome dialog). A Win32 Declare statement for one of these three APIs
alone could theoretically appear in legitimate automation. Only BOTH
together -- an auto-exec trigger AND a Declare for a download/execute
primitive -- is the downloader-macro shape.

Detection never checks for a malware/campaign name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_AUTOEXEC_RE = re.compile(
    rb'(?i)\b(Sub\s+AutoOpen|Sub\s+AutoExec|Sub\s+Document_Open|'
    rb'Sub\s+Workbook_Open|Sub\s+AutoClose)\b')

_DECLARE_RE = re.compile(
    rb'(?i)Declare\s+(?:PtrSafe\s+)?(?:Function|Sub)\s+'
    rb'(URLDownloadToFile[AW]?|ShellExecute[AW]?|WinExec)\s+Lib\s+["\'][^"\']+["\']')

_URL_RE = re.compile(rb'(?i)https?://[^\s"\'<>\x00]{6,200}')


class MacroExtractor(mwcp.Parser):
    """Detect a downloader-shaped Office macro: auto-exec entry point +
    Win32 API Declare for a download/execute primitive."""

    DESCRIPTION = "Downloader Macro Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        return bool(_AUTOEXEC_RE.search(data)) and bool(_DECLARE_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        autoexec = _AUTOEXEC_RE.search(data)
        declare = _DECLARE_RE.search(data)
        if not (autoexec and declare):
            return

        api = declare.group(1).decode('utf-8', 'ignore')
        entry = autoexec.group(1).decode('utf-8', 'ignore')
        self.report.add(DecodedString(
            f'[MacroDownloader] auto-exec entry point: {entry}; Win32 API Declare for {api}'))

        for m in _URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').rstrip('"\'<> \x00')
            self.report.add(C2URL(url))
