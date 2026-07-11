"""
MacroPackConfig -- mwcp parser for auto-generated obfuscated macro/script
loaders (the shape MacroPack and similar macro-generation frameworks emit).

Detection does NOT check for the string "MacroPack", any tool watermark, or
any other name an operator could strip -- name/watermark strings are the
first thing removed from a released build (see [[feedback-detection-design]]
Rule 3). Instead this targets the MECHANISM that is structurally required
for a macro-generator's auto-obfuscated payload to actually execute:

  1. An auto-exec entry point (AutoOpen/AutoExec/Document_Open/Workbook_Open) --
     required by Office/the script host to run the payload without a user
     click beyond opening the file.
  2. A programmatic character-code string-reconstruction loop -- Chr(n) called
     in a loop, or Split() over a delimited numeric/char list, assembled into
     a single string at runtime. This SHAPE is what defeats static string
     scanning; the generator has no way to deliver an obfuscated payload
     without emitting some form of this reconstruction loop, so it cannot be
     stripped without also breaking the obfuscation it exists to provide.
  3. A shell-out primitive (Shell / CreateObject("WScript.Shell") / .Run /
     .Exec) that consumes the reconstructed string -- the actual execution
     step; without it the reconstructed string is inert data.

All three together in one file is the structural fingerprint of an
auto-generated obfuscated macro loader, independent of which generator
produced it.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, C2URL

_AUTOEXEC_RE = re.compile(
    rb'(?i)\b(Sub\s+AutoOpen|Sub\s+AutoExec|Sub\s+Document_Open|'
    rb'Sub\s+Workbook_Open|Sub\s+AutoClose)\b')

# Chr()-loop or delimited-code-array reconstruction -- the obfuscation shape,
# not any particular generator's name.
_CHR_LOOP_RE = re.compile(rb'(?i)(?:Chr\s*\(\s*\d{1,3}\s*\)\s*&\s*){4,}')
_SPLIT_CODE_ARRAY_RE = re.compile(
    rb'(?i)Split\s*\(\s*"(?:\d{1,3}[,\|]){4,}\d{1,3}"\s*,\s*"[,\|]"\s*\)')

_SHELLOUT_RE = re.compile(
    rb'(?i)\b(CreateObject\s*\(\s*"WScript\.Shell"\s*\)|Shell\s*\(|\.Run\s*\(|\.Exec\s*\()')

_URL_RE = re.compile(rb'(?i)https?://[^\s"\'<>\x00]{6,200}')


class MacroPackConfig(mwcp.Parser):
    """Detect an auto-generated obfuscated macro/script loader by its
    auto-exec + char-code-reconstruction + shell-out structure."""

    DESCRIPTION = "Auto-Generated Obfuscated Macro Loader Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        # Short-circuit on the cheapest/rarest signal first -- the
        # reconstruction-loop regexes are the expensive ones (nested
        # quantifiers), so skip them entirely on the (common) case where
        # there is no auto-exec entry point at all.
        if not _AUTOEXEC_RE.search(data):
            return False
        if not _SHELLOUT_RE.search(data):
            return False
        return bool(_CHR_LOOP_RE.search(data)) or bool(_SPLIT_CODE_ARRAY_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return

        autoexec = _AUTOEXEC_RE.search(data)
        reconstruction = _CHR_LOOP_RE.search(data) or _SPLIT_CODE_ARRAY_RE.search(data)
        shellout = _SHELLOUT_RE.search(data)
        if not (autoexec and reconstruction and shellout):
            return

        entry = autoexec.group(1).decode('utf-8', 'ignore')
        self.report.add(DecodedString(
            f'[MacroLoader] auto-exec entry point: {entry}; '
            f'char-code reconstruction loop present; shell-out primitive present'))

        seen: set[str] = set()
        for m in _URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').rstrip('"\'<> ')
            if url not in seen:
                seen.add(url)
                self.report.add(C2URL(url))
