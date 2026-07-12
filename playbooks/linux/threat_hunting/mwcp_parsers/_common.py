"""Shared helpers used by every family parser in c2_parsers/."""
from __future__ import annotations

import json
import re
from typing import List


def decode(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def find_json_objects(data: bytes, anchor_re: 're.Pattern', max_len: int = 4000) -> List[dict]:
    """Extract JSON objects near an anchor pattern (config blobs embedded in a Go
    binary are not always at a clean object boundary, so search a window)."""
    out = []
    for m in anchor_re.finditer(data):
        start = max(0, m.start() - max_len)
        end = min(len(data), m.end() + max_len)
        window = data[start:end]
        brace_start = window.rfind(b'{', 0, m.start() - start + 1)
        if brace_start == -1:
            continue
        depth = 0
        for i in range(brace_start, len(window)):
            if window[i:i + 1] == b'{':
                depth += 1
            elif window[i:i + 1] == b'}':
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(window[brace_start:i + 1].decode('utf-8', 'ignore'))
                        if isinstance(obj, dict):
                            out.append(obj)
                    except (ValueError, UnicodeDecodeError):
                        pass
                    break
    return out
