"""
ISOLNKChain -- mwcp parser for an ISO disk image with an embedded LNK
shortcut, the "ISO+LNK" Mark-of-the-Web bypass delivery chain (Qakbot,
Bumblebee, IcedID, and other loader families since MotW started blocking
Office macros from downloaded archives).

Two independent structural mechanisms, both required:
  1. An ISO9660 Primary Volume Descriptor: the fixed `CD001` signature at
     byte offset 32769 (sector 16 + 1) -- ISO9660's own spec-mandated
     signature location, not operator-chosen.
  2. An embedded MS-SHLLINK structure: the same LNK magic + CLSID check
     used by LNKParser.py, found anywhere in the image (the CLSID/UDF
     wrapping around an embedded LNK inside an ISO makes a byte-exact
     offset infeasible to compute generically, so this scans for the
     signature).

An ISO alone is a completely normal container format (installers, disc
images). An LNK magic sequence alone can appear coincidentally in binary
data. Only an ISO9660 PVD signature CONTAINING an embedded LNK structure
is the delivery-chain shape -- mounting the ISO exposes what looks like a
single shortcut, which is actually the malicious LNK.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import mwcp
from mwcp.metadata import DecodedString

_ISO_PVD_OFFSET = 32769
_ISO_PVD_SIG = b'CD001'
_LNK_MAGIC = b'\x4c\x00\x00\x00'
_LNK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
_LNK_HEADER = _LNK_MAGIC + _LNK_CLSID


class ISOLNKChain(mwcp.Parser):
    """Detect an ISO9660 image with an embedded LNK shortcut structure."""

    DESCRIPTION = "ISO+LNK Delivery Chain Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < _ISO_PVD_OFFSET + len(_ISO_PVD_SIG):
            return False
        if data[_ISO_PVD_OFFSET:_ISO_PVD_OFFSET + len(_ISO_PVD_SIG)] != _ISO_PVD_SIG:
            return False
        return _LNK_HEADER in data

    def run(self):
        data = self.file_object.data
        if not data:
            return
        if data[_ISO_PVD_OFFSET:_ISO_PVD_OFFSET + len(_ISO_PVD_SIG)] != _ISO_PVD_SIG:
            return
        lnk_off = data.find(_LNK_HEADER)
        if lnk_off < 0:
            return

        self.report.add(DecodedString(
            f'[ISO-LNK-Chain] ISO9660 PVD signature at offset {_ISO_PVD_OFFSET} '
            f'with an embedded LNK (MS-SHLLINK) structure at offset {lnk_off} -- '
            f'Mark-of-the-Web bypass delivery chain shape'))
