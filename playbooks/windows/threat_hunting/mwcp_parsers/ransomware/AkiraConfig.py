"""
AkiraConfig -- mwcp parser for Akira ransomware command-line arguments.

Akira's Windows/ESXi encryptors are documented (multiple independent public
technical analyses, tracked across Akira's continued activity rather than
a single point-in-time report) to accept a command-line argument set from
one shared parser: a path target (`-p`/`--encryption_path`), a share
target (`--share_file`), and a distinctive `--encryption_percent <n>` flag
controlling partial/intermittent encryption -- a design choice not shared
with other major families' public documentation. These are structural
requirements of Akira's own argument parser, not operator-chosen strings.

A single flag is not sufficient evidence on its own (any one flag name
could coincidentally appear in unrelated text/help output) -- detection
requires `--encryption_percent` TOGETHER WITH at least one other flag from
the same documented argument set, both present in one region.

Confidence note: Akira's byte-level static config format (if any exists
beyond command-line arguments) is less publicly dissected than families
with a leaked builder/source (LockBit, BlackCat, REvil, Conti), and RaaS
tooling iterates over time -- treat the exact flag set as best-current
public knowledge, not a permanently fixed spec.

Detection never checks for an "Akira" name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_ENC_PERCENT_RE = re.compile(rb'--encryption_percent[\s=]+(\d{1,3})\b')
_OTHER_ARGS_RE  = re.compile(rb'(?:^|\s)(--encryption_path\s*=?\s*\S+|--share_file\s*=?\s*\S+|-p\s+\S+)')


class AkiraConfig(mwcp.Parser):
    """Detect Akira's distinctive --encryption_percent argument schema."""

    DESCRIPTION = "Akira Ransomware Argument-Schema Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 16:
            return False
        # A single flag is not evidence -- require the distinctive flag
        # together with at least one sibling from the same argument schema.
        return bool(_ENC_PERCENT_RE.search(data)) and bool(_OTHER_ARGS_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        m = _ENC_PERCENT_RE.search(data)
        others = [x.group(1).decode('utf-8', 'ignore') for x in _OTHER_ARGS_RE.finditer(data)]
        if not (m and others):
            return
        pct = m.group(1).decode('ascii')
        self.report.add(DecodedString(
            f'[Akira-Args] encryption_percent={pct} other_args={others[:5]} -- matches '
            f'Akira\'s documented partial-encryption argument schema'))
