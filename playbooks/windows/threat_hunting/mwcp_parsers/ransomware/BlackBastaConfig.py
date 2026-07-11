"""
BlackBastaConfig -- mwcp parser for Black Basta's required runtime key argument.

Black Basta's encryptor is documented (multiple independent public
technical analyses, spanning the group's activity through its 2025
internal chat-log leak) to refuse to run without a `-key <base64-blob>`
(or `--key`) command-line argument supplying the affiliate's decryption
material at execution time -- an anti-sandbox/anti-analysis measure that
is a structural requirement of the binary's own entry point, not an
operator-chosen string. A sample missing this argument simply exits.

A single argument match is not sufficient evidence on its own (a `-key`
flag could coincidentally appear in unrelated command-line-parsing code)
-- detection requires the runtime-key argument TOGETHER WITH at least one
of the family-agnostic ransomware structural markers (embedded RSA public
key DER block, or shadow-copy/recovery-disable command syntax -- see
RansomwareIndicators.py) present in the same file.

Confidence note: like AkiraConfig, Black Basta's static config format (if
any exists beyond this required argument) is less publicly dissected than
leaked-builder/leaked-source families, and tooling iterates over time --
treat this as best-current public knowledge, not a permanently fixed spec.

Detection never checks for a "Black Basta" name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, Password

_KEY_ARG_RE = re.compile(rb'-{1,2}key[\s=]+([A-Za-z0-9+/=]{20,400})\b')

# Shared family-agnostic ransomware markers (mirrors RansomwareIndicators.py) --
# used here only as the SECOND required signal, never alone.
_RSA_PUBKEY_RE = re.compile(rb'\x30\x82..\x02\x82(..)', re.DOTALL)
_RSA_EXPONENT  = b'\x02\x03\x01\x00\x01'
_VSS_RE = re.compile(
    rb'(?i)(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|'
    rb'bcdedit(?:\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no|'
    rb'wbadmin(?:\.exe)?\s+delete\s+catalog)')


def _has_rsa_pubkey(data: bytes) -> bool:
    # See RansomwareIndicators.py's _has_rsa_pubkey for why the search window
    # is computed from the modulus length rather than a fixed small gap.
    for m in _RSA_PUBKEY_RE.finditer(data):
        mod_len = int.from_bytes(m.group(1), 'big')
        if not (1 <= mod_len <= 1024):
            continue
        exp_pos = m.end() + mod_len
        window = data[max(0, exp_pos - 4): exp_pos + 8]
        if window.find(_RSA_EXPONENT) != -1:
            return True
    return False


class BlackBastaConfig(mwcp.Parser):
    """Detect Black Basta's required runtime -key argument, corroborated by
    a family-agnostic ransomware structural marker."""

    DESCRIPTION = "Black Basta Ransomware Runtime-Key Argument Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        if not _KEY_ARG_RE.search(data):
            return False
        return _has_rsa_pubkey(data) or bool(_VSS_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        if not (_has_rsa_pubkey(data) or _VSS_RE.search(data)):
            return
        m = _KEY_ARG_RE.search(data)
        if not m:
            return
        key = m.group(1).decode('utf-8', 'ignore')
        self.report.add(Password(key))
        self.report.add(DecodedString(
            f'[BlackBasta-RuntimeKey] required -key argument present ({len(key)} chars) -- '
            f'matches Black Basta\'s documented anti-sandbox execution requirement'))
