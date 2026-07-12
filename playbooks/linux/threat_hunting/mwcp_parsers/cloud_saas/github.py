"""GitHub as a C2/exfil/dead-drop channel. Requires the GitHub REST API endpoint AND a
GitHub Personal Access Token in one of its two API-validated formats (classic 40-hex,
or the newer ghp_-prefixed 36-alphanumeric form) -- GitHub's own token-format
validation is what constrains this shape, not operator choice."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_ENDPOINT = b'api.github.com/repos/'
_PAT_RE = re.compile(rb'\bghp_[A-Za-z0-9]{36}\b|\b[a-f0-9]{40}\b')


def identify(data: bytes) -> bool:
    return _ENDPOINT in data and bool(_PAT_RE.search(data))


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    m = _PAT_RE.search(data)
    token_kind = 'fine-grained/classic-new' if m.group(0).startswith(b'ghp_') else 'classic-40hex'
    return {
        'family': 'SaaS C2: GitHub API',
        'token_format': token_kind,
        'note': ('GitHub REST API endpoint co-occurring with a Personal Access Token matching '
                 'one of GitHub\'s own two validated token formats -- repo-as-dead-drop / '
                 'gist-based C2 channel indicator.'),
    }
