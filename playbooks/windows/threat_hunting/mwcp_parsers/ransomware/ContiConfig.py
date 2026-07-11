"""
ContiConfig -- mwcp parser for Conti ransomware command-line argument schema.

Conti's full C++ source code was leaked in 2022 (a disgruntled affiliate
leak), making its command-line argument parser genuinely public: the
binary's own `main()` expects a specific flag set --
`-p <path>` (target path), `-m local|net|all|backups` (encryption mode),
`-size <n>` (max file size threshold), `-nomutex`, `-log <path>`. This is
the leaked source's own `getopt`-style parser -- the exact flag spelling
is a structural requirement of that parser, not an operator naming choice.

Detection never checks for a "Conti" name string. It requires the `-m`
mode flag with one of Conti's own documented mode values, plus at least
one other flag from the same parser, both appearing together in a command
line or embedded argument-string blob.

References:
  - Conti ransomware source code leak, 2022 (leaked C++ source, `main.cpp`
    argument parser)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_MODE_RE  = re.compile(rb'-m\s+(local|net|all|backups)\b')
_OTHER_FLAGS_RE = re.compile(rb'(?:^|\s)(-p\s+\S+|-size\s+\d+|-nomutex\b|-log\s+\S+)')


class ContiConfig(mwcp.Parser):
    """Detect Conti's leaked-source command-line argument schema."""

    DESCRIPTION = "Conti Ransomware Argument-Schema Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 16:
            return False
        return bool(_MODE_RE.search(data)) and bool(_OTHER_FLAGS_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        mode_m = _MODE_RE.search(data)
        other_m = _OTHER_FLAGS_RE.search(data)
        if not (mode_m and other_m):
            return

        mode = mode_m.group(1).decode('ascii')
        flags = [m.group(1).decode('utf-8', 'ignore') for m in _OTHER_FLAGS_RE.finditer(data)]
        self.report.add(DecodedString(
            f'[Conti-Args] mode={mode} flags={flags[:10]} -- matches the leaked-source '
            f'command-line argument schema'))
