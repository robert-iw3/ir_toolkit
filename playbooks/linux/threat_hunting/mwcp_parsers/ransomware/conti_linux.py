"""Conti's leaked C++ source (main.cpp's getopt-style argument parser) is compiled
identically into both the Windows and the Linux/ESXi builds -- one shared codebase, so
the exact flag spelling is a structural requirement of that parser, not an operator
naming choice, on either OS.

Detection never checks for a "Conti" name string. Requires the `-m` mode flag with one
of Conti's own documented mode values, plus at least one other flag from the same
parser, both appearing together."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_MODE_RE = re.compile(rb'-m\s+(local|net|all|backups)\b')
_OTHER_FLAGS_RE = re.compile(rb'(?:^|\s)(-p\s+\S+|-size\s+\d+|-nomutex\b|-log\s+\S+)')


def identify(data: bytes) -> bool:
    if len(data) < 16:
        return False
    return bool(_MODE_RE.search(data)) and bool(_OTHER_FLAGS_RE.search(data))


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    mode_m = _MODE_RE.search(data)
    flags = [m.group(1).decode('utf-8', 'ignore') for m in _OTHER_FLAGS_RE.finditer(data)]
    return {
        'family': 'Ransomware: Conti-lineage Argument Schema (Linux)',
        'mode': mode_m.group(1).decode('ascii'),
        'flags': flags[:10],
        'note': ('Matches the leaked Conti C++ source\'s own command-line argument schema '
                 '(-m local|net|all|backups + a sibling flag) -- the same leaked codebase as '
                 'the Windows build, not a guessed port. Conti\'s lineage lives on in Royal and '
                 'other successor families sharing the same argument schema.'),
    }
