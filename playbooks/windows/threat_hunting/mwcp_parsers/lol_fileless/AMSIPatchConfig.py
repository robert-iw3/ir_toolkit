"""
AMSIPatchConfig -- mwcp parser for an embedded AMSI-bypass patch: the
documented byte sequence that forces AmsiScanBuffer to return
E_INVALIDARG immediately, packaged together with the exact API name it
patches.

The x64 patch shape (`mov eax, 0x80070057; ret` -- opcode bytes
`B8 57 00 07 80 C3`) is the specific, publicly-documented mechanism used
across numerous AMSI-bypass proofs-of-concept: it is the shortest
sequence that makes AmsiScanBuffer report "invalid argument" for every
call without actually inspecting the buffer. This exact byte sequence IS
the mechanism (Rule 3 exception) -- there is no behavioral proxy for "the
specific machine code that neutralizes this one Windows API function."

A patch-shaped byte sequence alone is not sufficient (six bytes can
coincide by chance in a large binary); detection requires it to appear
near a literal reference to the "AmsiScanBuffer" export name -- the two
together (the patch bytes AND proximity to the API name they target) is
what is exclusive to this TTP.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

# mov eax, 0x80070057 ; ret  (forces AmsiScanBuffer to always report E_INVALIDARG)
_PATCH_BYTES = bytes.fromhex('B8570007' '80C3')
_AMSI_NAME_RE = re.compile(rb'AmsiScanBuffer')
_PROXIMITY = 512


class AMSIPatchConfig(mwcp.Parser):
    """Detect the AmsiScanBuffer force-E_INVALIDARG patch shape near the
    API name it targets."""

    DESCRIPTION = "AMSI Bypass Patch Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32 or _PATCH_BYTES not in data:
            return False
        idx = data.find(_PATCH_BYTES)
        window = data[max(0, idx - _PROXIMITY): idx + len(_PATCH_BYTES) + _PROXIMITY]
        return bool(_AMSI_NAME_RE.search(window))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        pos = 0
        found = False
        while True:
            idx = data.find(_PATCH_BYTES, pos)
            if idx == -1:
                break
            window = data[max(0, idx - _PROXIMITY): idx + len(_PATCH_BYTES) + _PROXIMITY]
            if _AMSI_NAME_RE.search(window):
                self.report.add(DecodedString(
                    f'[AMSI-Patch] E_INVALIDARG force-return patch bytes near '
                    f'AmsiScanBuffer reference @ offset {idx:#x}'))
                found = True
            pos = idx + len(_PATCH_BYTES)
        if not found:
            return
