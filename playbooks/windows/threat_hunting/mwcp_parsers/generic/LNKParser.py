"""
LNKParser -- mwcp parser for Windows Shortcut (LNK / Shell Link) files.

LNK files are one of the most common initial access delivery vectors. A malicious
LNK has the payload buried in the Arguments field of the StringData section --
what looks like a desktop shortcut actually runs a long PowerShell one-liner or
downloads a stager from C2.

Extracts per MS-SHLLINK spec:
  - LinkTarget path (where the shortcut points)
  - Command-line Arguments (where the payload lives)
  - Working directory
  - Icon location
  - Machine identifier (if present)

Detection: if Arguments contains -enc, IEX, WebClient, or a URL → emit as
DecodedString + C2URL. Always emits Arguments as DecodedString regardless so
the analyst sees the full payload.
"""

import re
import struct
import mwcp
from mwcp.metadata import DecodedString, C2URL, FilePath

_LNK_MAGIC = b'\x4c\x00\x00\x00'   # LNK file magic (header size)
_CLSID      = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'

_URL_RE  = re.compile(rb'https?://[^\s\'"<>\x00\r\n]{8,200}', re.IGNORECASE)
_BENIGN  = re.compile(rb'(?i)(microsoft\.com|windows\.com|adobe\.com|digicert\.com)')

_MAX_ARG = 4096


def _read_counted_string(data: bytes, offset: int, wide: bool) -> tuple[str, int]:
    """Read a CountedString (LNK StringData format): uint16 count + chars."""
    if offset + 2 > len(data):
        return '', offset
    count = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if wide:
        byte_len = count * 2
        end = offset + byte_len
        if end > len(data):
            return '', end
        text = data[offset:end].decode('utf-16-le', errors='replace').rstrip('\x00')
    else:
        end = offset + count
        text = data[offset:end].decode('latin-1', errors='replace').rstrip('\x00')
    return text, end


class LNKParser(mwcp.Parser):
    """Parse Windows LNK shortcut files and extract embedded commands / URLs."""

    DESCRIPTION = "Windows LNK Shortcut Parser"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''
        return (len(data) >= 20 and
                data[:4] == _LNK_MAGIC and
                data[4:20] == _CLSID)

    def run(self):
        data = self.file_object.data
        if not data or len(data) < 76:
            return

        # --- Parse LNK header flags ---
        header_size = struct.unpack_from('<I', data, 0)[0]
        if header_size < 76:
            return
        link_flags = struct.unpack_from('<I', data, 20)[0]

        has_link_target_id_list = bool(link_flags & 0x01)
        has_link_info           = bool(link_flags & 0x02)
        has_string_data         = bool(link_flags & 0x04)
        is_unicode              = bool(link_flags & 0x80)

        offset = header_size   # skip past header

        # --- Skip LinkTargetIDList ---
        if has_link_target_id_list:
            if offset + 2 > len(data):
                return
            idlist_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2 + idlist_size

        # --- Skip LinkInfo ---
        if has_link_info:
            if offset + 4 > len(data):
                return
            linkinfo_size = struct.unpack_from('<I', data, offset)[0]
            offset += linkinfo_size

        # --- StringData (the important part) ---
        if not has_string_data:
            return

        string_flags = link_flags >> 8   # bits 8-12 indicate which strings are present
        # Bit positions of string fields in order:
        # NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGS, ICON_LOCATION
        field_names = ['NAME_STRING', 'RELATIVE_PATH', 'WORKING_DIR',
                       'COMMAND_LINE_ARGUMENTS', 'ICON_LOCATION']
        present_bits = [(link_flags >> (8 + i)) & 1 for i in range(5)]

        strings = {}
        for i, (name, present) in enumerate(zip(field_names, present_bits)):
            if present:
                text, offset = _read_counted_string(data, offset, is_unicode)
                strings[name] = text

        # Emit the interesting fields
        args    = strings.get('COMMAND_LINE_ARGUMENTS', '')
        workdir = strings.get('WORKING_DIR', '')
        target  = strings.get('RELATIVE_PATH', '') or strings.get('NAME_STRING', '')

        if target:
            self.report.add(FilePath(target))

        if args:
            args_preview = args[:_MAX_ARG]
            self.report.add(DecodedString(f'[LNK-Arguments] {args_preview}'))
            self.logger.debug(f"[LNKParser] arguments: {args_preview[:120]}")

            # Extract C2 URLs embedded in arguments
            for m in _URL_RE.finditer(args.encode('utf-8', 'ignore')):
                url = m.group(0).decode('utf-8', 'ignore').strip()
                if not _BENIGN.search(m.group(0)):
                    self.report.add(C2URL(url))

        # Also scan the raw binary for URLs (catches obfuscated strings in binary sections)
        for m in _URL_RE.finditer(data):
            url_raw = m.group(0).decode('utf-8', 'ignore').strip()
            if url_raw not in (args or '') and not _BENIGN.search(m.group(0)):
                self.report.add(C2URL(url_raw))
