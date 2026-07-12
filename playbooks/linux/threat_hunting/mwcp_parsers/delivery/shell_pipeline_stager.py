"""curl|bash / wget|sh dropper pipeline -- the dominant Linux initial-access/staging
technique (no Windows equivalent in mwcp_parsers, since this is a shell-pipeline
mechanism specific to how Unix shells compose commands). The mechanism: a network
fetch command's stdout piped DIRECTLY into a shell interpreter invocation, so the
fetched script executes without ever touching disk as a separate, inspectable step.

Requires the fetch command to carry a URL argument AND that fetch to be followed by a
pipe into an interpreter within a short token distance -- a bare "curl" or "| bash"
occurring anywhere in a large log/config file is common and meaningless on its own;
the PIPE RELATIONSHIP between them (not just co-occurrence) is the actual technique."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_PIPELINE_RE = re.compile(
    rb'(?:curl|wget)\s+[^\n\x00|]{0,10}https?://[^\s\x00|]{4,200}[^\n\x00]{0,20}'
    rb'\|\s*(?:sudo\s+)?(?:bash|sh|python3?|perl)\b', re.IGNORECASE)
# Process-substitution variant: bash <(curl ...) / . <(wget -qO- ...)
_PROCESS_SUB_RE = re.compile(
    rb'(?:bash|sh|source|\.)\s+<\(\s*(?:curl|wget)\s+[^\)]{0,200}https?://', re.IGNORECASE)


def identify(data: bytes) -> bool:
    return bool(_PIPELINE_RE.search(data)) or bool(_PROCESS_SUB_RE.search(data))


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    m = _PIPELINE_RE.search(data) or _PROCESS_SUB_RE.search(data)
    shape = 'pipe' if _PIPELINE_RE.search(data) else 'process-substitution'
    return {
        'family': 'Delivery: Shell Pipeline Stager',
        'shape': shape,
        'sample': m.group(0).decode('utf-8', 'ignore')[:160],
        'note': ('Fetch command\'s output piped directly into a shell interpreter (or the '
                 'process-substitution equivalent) -- the fetched script never touches disk as '
                 'an inspectable file. Requires an actual pipe/substitution relationship '
                 'between the fetch and the interpreter, not just both appearing somewhere.'),
    }
