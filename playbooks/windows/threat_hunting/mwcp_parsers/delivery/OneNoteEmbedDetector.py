"""
OneNoteEmbedDetector -- mwcp parser for the OneNote embedded-executable
delivery technique (widespread since late 2022 once macro-based delivery
was blocked by default): a .one file with an executable-shaped file
embedded behind a decoy "double-click to view" image/button.

Two independent structural mechanisms, both required, per MS-ONESTORE:
  1. The OneNote file-format header GUID `{7B5C52E4-D88C-4DA7-AEB1-
     5378D02996D3}` -- the fixed guidFileType every .one file begins with,
     not operator-chosen.
  2. The FileDataStoreObject GUID `{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}`
     -- MS-ONESTORE's own fixed marker for an embedded opaque file blob --
     found near a filename string with an executable-shaped extension
     (.exe/.vbs/.js/.jse/.wsf/.hta/.bat/.cmd/.ps1/.scr/.chm/.msi).

The container header alone just identifies "this is a OneNote file" --
completely benign on its own (OneNote is a legitimate, widely-used
application). Only a OneNote file that ALSO embeds a FileDataStoreObject
whose filename is executable-shaped is the delivery-technique shape --
OneNote pages routinely embed benign attachments (PDFs, images, Office
docs) via the exact same structural mechanism, so the executable-extension
requirement on the second signal is what makes this exclusive to the TTP.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString, FilePath

# guidFileType {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3} in MS-ONESTORE binary GUID order
_ONE_HEADER_GUID = bytes([
    0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
    0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
])

# FileDataStoreObject GUID {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC} in MS-ONESTORE binary order
_FILEDATASTORE_GUID = bytes([
    0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
    0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC,
])

_EXE_EXT_RE = re.compile(
    rb'(?i)[^\x00\\/:*?"<>|\r\n]{1,120}\.(exe|vbs|js|jse|wsf|hta|bat|cmd|ps1|scr|chm|msi)\x00',
)

_PROXIMITY_WINDOW = 4096


class OneNoteEmbedDetector(mwcp.Parser):
    """Detect a OneNote file embedding an executable-shaped attachment via
    FileDataStoreObject."""

    DESCRIPTION = "OneNote Embedded-Executable Delivery Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64 or data[:16] != _ONE_HEADER_GUID:
            return False
        for m in re.finditer(re.escape(_FILEDATASTORE_GUID), data):
            window = data[m.end():m.end() + _PROXIMITY_WINDOW]
            if _EXE_EXT_RE.search(window):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data or data[:16] != _ONE_HEADER_GUID:
            return

        found = False
        for m in re.finditer(re.escape(_FILEDATASTORE_GUID), data):
            window = data[m.end():m.end() + _PROXIMITY_WINDOW]
            ext_m = _EXE_EXT_RE.search(window)
            if not ext_m:
                continue
            fname_bytes = ext_m.group(0).rstrip(b'\x00')
            fname = fname_bytes.decode('utf-16-le', 'ignore') if b'\x00' in fname_bytes[1::2] else \
                fname_bytes.decode('utf-8', 'ignore')
            fname = fname.strip('\x00') or fname_bytes.decode('latin-1', 'ignore')
            self.report.add(FilePath(fname))
            self.report.add(DecodedString(
                f'[OneNote-EmbeddedExecutable] FileDataStoreObject embeds executable-shaped '
                f'attachment: {fname}'))
            found = True
        if not found:
            return
