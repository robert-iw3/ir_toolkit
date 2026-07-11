"""
ClipboardHijackConfig -- mwcp parser for cryptocurrency clipboard-hijacking
malware: the clipboard-access API pair combined with a cluster of 2+
distinct cryptocurrency address-format regexes used as swap-replacement
targets.

Two independent mechanisms, both required:
  1. `SetClipboardData` AND `GetClipboardData` -- the Win32 API pair a
     program must call together to read the current clipboard contents
     and overwrite them; either call alone is used by countless benign
     clipboard-manager utilities.
  2. 2+ DISTINCT cryptocurrency address formats present (Bitcoin
     base58/bech32, Ethereum `0x`-hex, Monero base58) -- a single
     address-shaped string alone is not evidence (could be one
     hardcoded donation address in an unrelated app); a cluster of
     MULTIPLE DIFFERENT chains' address formats is what a real-time
     swap-replacement target list requires, since the malware cannot
     know in advance which currency the victim will copy.

Distinct TTP from credential-exfiltration stealers: this is real-time
in-memory substitution (clipboard monitored and silently rewritten),
not data exfiltration to a C2 server.

Detection never checks for a malware/tool name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_CLIPBOARD_API_RE = re.compile(rb'SetClipboardData')
_CLIPBOARD_API2_RE = re.compile(rb'GetClipboardData')

_BTC_RE = re.compile(rb'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,60})\b')
_ETH_RE = re.compile(rb'\b0x[0-9a-fA-F]{40}\b')
_XMR_RE = re.compile(rb'\b4[0-9AB][0-9A-Za-z]{93}\b')

_ADDR_CATEGORIES = (('btc', _BTC_RE), ('eth', _ETH_RE), ('xmr', _XMR_RE))


def _distinct_address_categories(data: bytes) -> list:
    return [name for name, rx in _ADDR_CATEGORIES if rx.search(data)]


class ClipboardHijackConfig(mwcp.Parser):
    """Detect clipboard-hijacking malware: clipboard API pair + 2+
    distinct cryptocurrency address formats."""

    DESCRIPTION = "Cryptocurrency Clipboard Hijack Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        if not (_CLIPBOARD_API_RE.search(data) and _CLIPBOARD_API2_RE.search(data)):
            return False
        return len(_distinct_address_categories(data)) >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return
        if not (_CLIPBOARD_API_RE.search(data) and _CLIPBOARD_API2_RE.search(data)):
            return
        cats = _distinct_address_categories(data)
        if len(cats) < 2:
            return

        self.report.add(DecodedString(
            f'[Clipboard-Hijack] SetClipboardData + GetClipboardData + {len(cats)} distinct '
            f'address formats ({", ".join(cats)}) -- real-time swap-replacement shape'))
