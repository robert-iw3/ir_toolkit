"""base64-decode-and-execute dropper -- a base64 payload blob decoded to disk (or
directly piped) then made executable and run, the standard way a Linux dropper script
smuggles an ELF payload past content filters that inspect for raw ELF magic bytes but
not base64-encoded ones.

Requires a base64-decode invocation (mechanism-required flag: -d/--decode, since
without it the tool encodes rather than decodes) co-occurring with EITHER an
executable-permission grant (chmod +x / chmod 755/750/777 on the decoded output path)
or a direct pipe into a shell -- decoding alone is extremely common (config files,
certs, arbitrary data) and means nothing without the follow-on execution step."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_DECODE_RE = re.compile(rb'base64\s+(?:-d|--decode)\b|openssl\s+enc\s+-d\s+-base64', re.IGNORECASE)
_CHMOD_EXEC_RE = re.compile(rb'chmod\s+(?:\+x|[0-7]*7[0-7]{2})\b')
_PIPE_EXEC_RE = re.compile(rb'\|\s*(?:sudo\s+)?(?:bash|sh)\b')


def identify(data: bytes) -> bool:
    if not _DECODE_RE.search(data):
        return False
    return bool(_CHMOD_EXEC_RE.search(data)) or bool(_PIPE_EXEC_RE.search(data))


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    return {
        'family': 'Delivery: base64-ELF Dropper',
        'chmod_exec_grant': bool(_CHMOD_EXEC_RE.search(data)),
        'direct_pipe_exec': bool(_PIPE_EXEC_RE.search(data)),
        'note': ('base64 decode invocation co-occurring with an executable-permission grant or '
                 'a direct pipe into a shell -- decoding alone (config/cert data) is common and '
                 'not flagged; the follow-on execution step is the actual dropper behavior.'),
    }
