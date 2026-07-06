"""Shared parsing helpers for Linux investigation modules.

Every module here reads the free-text `Details` string a collector script
wrote (edr_hunt.py / analyze_memory_linux.py / journal_analysis.py /
container_hunt.py / remote_access_triage.py / memory_enrich.py /
c2_config_extract.py) rather than a structured schema -- these helpers
centralise the regexes so 19 modules don't each reinvent "find the exe= path"
or "is this path writable."
"""
from __future__ import annotations

import re
from typing import Optional

from ..models.linux_noise import IMPLANT_PATH_PREFIXES, TRUSTED_PATH_PREFIXES

_PATH_RE = re.compile(r'(?:path|exe|Path|ImagePath)[=:]\s*([^\s,;]+)')
_COMM_RE = re.compile(r'comm=([^\s,;]+)')
_PARENT_RE = re.compile(r'[Pp]arent=([^\s,;]+)')


def extract_path(text: str) -> str:
    m = _PATH_RE.search(text or '')
    return m.group(1) if m else ''


def extract_comm(text: str) -> str:
    m = _COMM_RE.search(text or '')
    return m.group(1) if m else ''


def is_implant_path(path: str) -> bool:
    return bool(path) and path.startswith(IMPLANT_PATH_PREFIXES)


def is_trusted_path(path: str) -> bool:
    return bool(path) and path.startswith(TRUSTED_PATH_PREFIXES)


def path_verdict(path: str) -> str:
    """'writable' | 'trusted' | 'unknown' -- structural prior only; the
    adjudicator's package-ownership check is the actual trust anchor."""
    if is_implant_path(path):
        return 'writable'
    if is_trusted_path(path):
        return 'trusted'
    return 'unknown'


def first_group(pattern: str, text: str, flags=re.IGNORECASE) -> Optional[str]:
    m = re.search(pattern, text or '', flags)
    return m.group(1) if m else None
