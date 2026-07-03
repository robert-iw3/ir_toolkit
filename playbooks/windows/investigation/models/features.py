"""Feature extraction from memory_forensic.py finding strings for ML classification."""
from __future__ import annotations
import math
import re
from typing import Any, Dict, List, Optional


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def path_depth(path: str) -> int:
    return path.replace('/', '\\').count('\\')


def extract_m13_signals(details: str) -> Dict[str, Any]:
    """Parse Module 13 Details free-text string into structured fields."""
    cv_m    = re.search(r'CV=([\d.]+)%', details)
    ascii_m = re.search(r'ASCII=([\d.]+)%', details)
    mz_m    = re.search(r'MZ-remnant=(True|False)', details)
    adj_m   = re.search(r'AdjAnonExec=(True|False)', details)
    ent_m   = re.search(r'entropy=([\d.]+)', details)
    size_m  = re.search(r'size=(\d+)', details)
    return {
        'cv_pct':       float(cv_m.group(1)) if cv_m else None,
        'ascii_pct':    float(ascii_m.group(1)) if ascii_m else None,
        'mz_remnant':   mz_m.group(1) == 'True' if mz_m else None,
        'adj_anon_exec': adj_m.group(1) == 'True' if adj_m else None,
        'entropy':      float(ent_m.group(1)) if ent_m else None,
        'size':         int(size_m.group(1)) if size_m else None,
        'is_uniform':   'UNIFORM' in details,
    }


def process_feature_vector(process_name: str, process_path: str,
                           parent_name: str, m13: Dict[str, Any]) -> List[float]:
    """5D feature vector for ML noise filter.

    Dimensions:
      [0] name_entropy  -- Shannon entropy of process name sans extension.
                           System processes have low-entropy meaningful names (svchost, lsass).
                           Blending malware often uses random or mangled names.
      [1] path_depth    -- Number of path separators. C:\\Windows\\System32 = 3.
      [2] ascii_pct_n   -- Module 13 ASCII% / 100. High ASCII = structured data (benign).
      [3] cv_pct_n      -- Module 13 CV% / 250 (capped). High CV = non-uniform (benign).
      [4] adj_exec_flag -- 1.0 if AdjAnonExec=True (suspicious), 0.0 otherwise.
    """
    name_ent = shannon_entropy(process_name.lower().replace('.exe', '').replace('.dll', ''))
    pd = float(path_depth(process_path))
    ascii_n = (m13.get('ascii_pct') or 0.0) / 100.0
    cv_n = min((m13.get('cv_pct') or 0.0) / 250.0, 1.0)
    adj_flag = 1.0 if m13.get('adj_anon_exec') else 0.0
    return [name_ent, pd, ascii_n, cv_n, adj_flag]
