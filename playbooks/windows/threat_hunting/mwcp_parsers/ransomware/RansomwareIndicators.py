"""
RansomwareIndicators -- mwcp parser for universal ransomware structural
signals, family-agnostic.

Nearly every ransomware family shares three mechanically-required
components regardless of family or builder:

  1. An embedded RSA (or ECC) public key, DER/ASN.1-encoded, used to wrap
     the per-victim symmetric key. The ASN.1 SEQUENCE/INTEGER tag structure
     and the near-universal 65537 (0x010001) public exponent are wire-format
     requirements of RSA key encoding itself -- not a family choice.
  2. The exact command syntax to delete shadow copies / disable recovery
     (`vssadmin delete shadows`, `wmic shadowcopy delete`,
     `bcdedit ... recoveryenabled no`, `wbadmin delete catalog`) -- these
     are Windows' own command syntax, not operator-chosen strings; there is
     no other way to invoke this OS functionality (Rule 3 exception, same
     class as the BootExecute exact-string check).
  3. A large cluster of distinct file-extension-shaped tokens (the
     encryption include/exclude list) sitting together in one region.

Detection requires 2+ of these three independently to fire -- a single
signal (e.g. an RSA key alone, which also appears in ordinary TLS/crypto
libraries) is not sufficient on its own.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

# ASN.1 DER RSA public key: SEQUENCE (0x30 0x82 <len16>) containing an
# INTEGER modulus (0x02 0x82 <len16>, 128/256/384/512 bytes for RSA
# 1024/2048/3072/4096) followed shortly by the near-universal 65537
# exponent encoding (0x02 0x03 0x01 0x00 0x01).
_RSA_PUBKEY_RE = re.compile(rb'\x30\x82..\x02\x82(..)', re.DOTALL)
_RSA_EXPONENT = b'\x02\x03\x01\x00\x01'

# Matched against data.lower() -- (?i) case-folding across a multi-MB buffer
# combined with variable-whitespace (\s+) alternation was the dominant cost
# here (1.2s+ against a large carved region); lower()-once + case-sensitive
# match is equivalent and the lower() step runs at C speed.
_VSS_COMMANDS = [
    rb'vssadmin(?:\.exe)?\s+delete\s+shadows',
    rb'wmic\s+shadowcopy\s+delete',
    rb'bcdedit(?:\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no',
    rb'wbadmin(?:\.exe)?\s+delete\s+catalog',
    rb'vssadmin(?:\.exe)?\s+resize\s+shadowstorage',
]
_VSS_RE = re.compile(b'(?:' + b'|'.join(_VSS_COMMANDS) + b')')

_EXT_CLUSTER_RE = re.compile(rb'\.[a-zA-Z0-9]{2,10}(?:\x00|\s|,|;)')
_MIN_EXT_CLUSTER = 15
_EXT_WINDOW = 4096


def _has_rsa_pubkey(data: bytes) -> bool:
    for m in _RSA_PUBKEY_RE.finditer(data):
        mod_len = int.from_bytes(m.group(1), 'big')
        if not (1 <= mod_len <= 1024):   # RSA-1024 through RSA-8192 modulus sizes
            continue
        # The exponent INTEGER immediately follows the modulus bytes -- a
        # fixed 16-byte lookahead only works for a tiny/synthetic modulus;
        # a real RSA-2048 key has a 256-byte modulus, so the exponent sits
        # ~256 bytes past here. Search a small tolerance window around the
        # exact expected offset instead of assuming a fixed small gap.
        exp_pos = m.end() + mod_len
        window = data[max(0, exp_pos - 4): exp_pos + 8]
        if window.find(_RSA_EXPONENT) != -1:
            return True
    return False


def _has_ext_cluster(data: bytes) -> bool:
    """Sliding window over sorted match offsets -- O(n) amortized. The prior
    nested-loop form (re-scanning all hits for every hit) was O(n^2) and
    became pathological against dense file-path-heavy carved regions
    (tens of thousands of extension-shaped substrings in a multi-MB
    PowerShell memory dump)."""
    hits = [m.start() for m in _EXT_CLUSTER_RE.finditer(data)]
    if len(hits) < _MIN_EXT_CLUSTER:
        return False
    left = 0
    for right in range(len(hits)):
        while hits[right] - hits[left] > _EXT_WINDOW:
            left += 1
        if right - left + 1 >= _MIN_EXT_CLUSTER:
            return True
    return False


class RansomwareIndicators(mwcp.Parser):
    """Detect family-agnostic ransomware structural indicators: RSA pubkey
    DER block, VSS/recovery-disable command syntax, extension-list cluster."""

    DESCRIPTION = "Universal Ransomware Indicator Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 256:
            return False
        signals = (
            _has_rsa_pubkey(data),
            bool(_VSS_RE.search(data.lower())),
            _has_ext_cluster(data),
        )
        return sum(signals) >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return

        has_rsa = _has_rsa_pubkey(data)
        vss_matches = _VSS_RE.findall(data.lower())
        has_ext = _has_ext_cluster(data)

        if sum((has_rsa, bool(vss_matches), has_ext)) < 2:
            return

        parts = []
        if has_rsa:
            parts.append('embedded RSA public key (DER, 65537 exponent)')
        if vss_matches:
            cmds = sorted({m.decode('utf-8', 'ignore') for m in vss_matches})
            parts.append(f'shadow-copy/recovery-disable command(s): {cmds}')
        if has_ext:
            parts.append('dense file-extension cluster (encryption target list)')

        self.report.add(DecodedString(
            f'[Ransomware-Indicators] {"; ".join(parts)}'))
