"""ML noise filter: separates normal Windows system background from anomalous blending.

Pipeline:
  1. Hard structural checks (path mismatch, M13 benign profiles) -- deterministic.
  2. IsolationForest on 5D feature vector -- unsupervised anomaly detection.
  3. Fallback heuristic (sklearn absent) -- parent-child tuple check.

Goal: identify processes that are "normal machine background noise -- certainty
without shadow of doubt" so the engine can close them out without module investigation.
This is NOT about catching everything; it is about NOT wasting CPU on taskhostw.exe
task-scheduler work items, COM infrastructure, audio subsystem data, etc.

Anomaly detection is trained on known-benign behavioral profiles (see _benign_baseline()).
Anomalies have shorter isolation paths -> higher score -> require full investigation.
Benign background has longer isolation paths -> lower/negative score -> noise close.
"""
from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    from sklearn.ensemble import IsolationForest as _IsoForest
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False

from .features import extract_m13_signals, process_feature_vector
from .windows_noise import (
    KNOWN_SYSTEM_PROCESSES, BENIGN_PARENT_CHILD,
    EXPECTED_PATHS, M13_BENIGN_PROFILES,
)

# IsolationForest decision_function: scores < NOISE_THRESHOLD are noise (benign).
# Negative scores are inliers (normal); positive scores are outliers (anomalous).
# Threshold tuned against the benign baseline: tight enough to not false-close TP.
NOISE_THRESHOLD = -0.05


def _benign_baseline() -> List[List[float]]:
    """Feature vectors for known-benign system process behavioral profiles.

    Each row: [name_entropy, path_depth, ascii_pct_n, cv_pct_n, adj_exec_flag]
    Derived from live Windows memory observations documented in the worked examples.
    """
    rows = []

    # taskhostw.exe -- task scheduler work items: high CV (190-234%), high ASCII (42-46%),
    # shallow path (System32 = depth 3), no adjacent exec region.
    # This is the canonical benign example from the investigation guide.
    for cv_n, ascii_n in [(0.94, 0.42), (0.85, 0.44), (0.80, 0.46), (0.76, 0.43)]:
        rows.append([2.5, 3.0, ascii_n, cv_n, 0.0])

    # svchost.exe -- service host with key material (lsass proxy ranges):
    # very low entropy name, System32 path, low printable, medium-high CV.
    for cv_n, ascii_n in [(0.90, 0.10), (0.85, 0.15), (0.92, 0.08), (0.88, 0.12)]:
        rows.append([2.3, 3.0, ascii_n, cv_n, 0.0])

    # wmiprvse.exe / dllhost.exe -- COM infrastructure:
    # moderate name entropy, 4-level path (wbem sub-dir), low printable.
    for cv_n, ascii_n in [(0.88, 0.12), (0.92, 0.08), (0.85, 0.05)]:
        rows.append([2.8, 4.0, ascii_n, cv_n, 0.0])

    # audiodg.exe -- audio sub-system PCM data: very low printable, high CV.
    for cv_n in [0.96, 0.94, 0.98]:
        rows.append([2.9, 3.0, 0.02, cv_n, 0.0])

    # lsass.exe -- key material: low printable, very low CV (crypto-ish but known path).
    for cv_n in [0.10, 0.08, 0.12]:
        rows.append([2.6, 3.0, 0.02, cv_n, 0.0])

    # msmpeng.exe -- AV signature databases: very high entropy, very low printable.
    for cv_n in [0.05, 0.06, 0.04]:
        rows.append([3.0, 4.0, 0.01, cv_n, 0.0])

    # explorer.exe -- shell data regions: medium ASCII, medium CV, shallow path.
    for cv_n, ascii_n in [(0.75, 0.30), (0.70, 0.35), (0.80, 0.28)]:
        rows.append([3.0, 2.0, ascii_n, cv_n, 0.0])

    # dwm.exe -- desktop compositor: low printable, high CV, System32.
    for cv_n in [0.80, 0.78, 0.82]:
        rows.append([2.2, 3.0, 0.08, cv_n, 0.0])

    # searchindexer.exe -- index database buffers: very high CV (binary index data).
    for cv_n, ascii_n in [(0.92, 0.05), (0.88, 0.08)]:
        rows.append([3.2, 3.0, ascii_n, cv_n, 0.0])

    rows.extend(_observed_baseline())
    return rows


_OBSERVED_BASELINE_PATH = os.path.join(os.path.dirname(__file__), 'observed_baseline.json')


def _observed_baseline() -> List[List[float]]:
    """Feature vectors harvested from live report data (see calibrate_baseline.py).

    Every row here passed a deterministic (non-ML) benign check at harvest time --
    see calibrate_baseline.py's docstring for why this isn't circular self-training.
    Absent file (never calibrated) is a normal, supported state -- synthetic
    baseline alone is still usable.
    """
    if not os.path.exists(_OBSERVED_BASELINE_PATH):
        return []
    try:
        with open(_OBSERVED_BASELINE_PATH, encoding='utf-8') as f:
            data = json.load(f)
        return [r['vector'] for r in data.get('rows', [])]
    except (ValueError, OSError, KeyError):
        return []


_forest: Optional[object] = None
_trained = False


def _get_forest():
    global _forest, _trained
    if _trained:
        return _forest
    if not _HAS_SKLEARN:
        _trained = True
        return None
    X = np.array(_benign_baseline(), dtype=float)
    _forest = _IsoForest(n_estimators=150, contamination=0.05, random_state=42)
    _forest.fit(X)
    _trained = True
    return _forest


def _check_path_legitimacy(process_name: str, process_path: str) -> Optional[Tuple[bool, str]]:
    """Returns (is_bad, rationale) if path is provably wrong; None if unknown/no data."""
    proc_lower = process_name.lower()
    if proc_lower not in EXPECTED_PATHS:
        return None
    path_lower = process_path.lower().replace('/', '\\').rstrip('\\')
    if not path_lower:
        return None
    expected = EXPECTED_PATHS[proc_lower]
    # msmpeng has a prefix match (version-numbered dir)
    if proc_lower == 'msmpeng.exe':
        for prefix in expected:
            if path_lower.startswith(prefix):
                return None
        return False, (f'{process_name} running from unexpected path: {process_path} '
                       f'(expected under Windows Defender platform directory)')
    if path_lower not in expected:
        return False, (f'{process_name} running from unexpected path: {process_path} '
                       f'(expected: {", ".join(expected)}). Path masquerading likely.')
    return None  # path is expected -- no red flag from this check


def _check_m13_benign_profile(m13: Dict[str, Any]) -> Optional[str]:
    """Returns rationale string if M13 signals match a documented-benign structural profile."""
    cv = m13.get('cv_pct')
    ascii_p = m13.get('ascii_pct')
    mz = m13.get('mz_remnant')
    adj = m13.get('adj_anon_exec')
    if cv is None:
        return None
    for profile in M13_BENIGN_PROFILES:
        if (cv >= profile['cv_pct_min'] and
                (ascii_p is not None and ascii_p >= profile['ascii_pct_min']) and
                mz is not None and mz == profile['mz_remnant'] and
                adj is not None and adj == profile['adj_anon_exec']):
            return (
                f"{profile['label']}: CV={cv:.0f}% (non-uniform), "
                f"ASCII={ascii_p:.0f}% (printable), "
                f"AdjAnonExec=False, MZ-remnant=False -- "
                "all Module 13 signals are in the benign column"
            )
    return None


def classify_noise(process_name: str, process_path: str, parent_name: str,
                   m13_details: str) -> Tuple[bool, float, str]:
    """Return (is_noise, score, rationale).

    is_noise=True means: this is certain system background noise, close without investigation.
    score: IsolationForest decision_function value, or synthetic sentinel.
    """
    m13 = extract_m13_signals(m13_details) if m13_details else {}

    # --- Rule 1: Path legitimacy (deterministic red-flag) ---
    path_check = _check_path_legitimacy(process_name, process_path)
    if path_check is not None:
        is_bad, rationale = path_check
        if is_bad is False:
            # Bad path: definitely NOT noise, requires investigation
            return False, 1.0, rationale

    # --- Rule 1b: Security process (lsass, AV, VTL1) with tagged key material ---
    # The memory workflow tags lsass and security processes with SECURITY-PROC.
    # A UNIFORM region in a security process with no adjacent exec region is
    # documented key material (AES session keys, DPAPI master keys, etc.).
    # An adversary injecting into lsass would produce AdjAnonExec=True in the
    # adjacent exec loader, which prevents this rule from firing incorrectly.
    if ('SECURITY-PROC' in m13_details and
            m13.get('adj_anon_exec') is False and
            m13.get('mz_remnant') is False):
        size = m13.get('size') or 999999
        if size < 65536:  # key material is small; large UNIFORM regions stay suspicious
            return True, -0.85, (
                f'SECURITY-PROC key material: {process_name} is a known security process; '
                f'UNIFORM region size={size}B with no adjacent exec region is documented '
                'key material (AES/DPAPI session key). AdjAnonExec=False confirms no loader stub.'
            )

    # --- Rule 2: M13 structural benign profile (deterministic close-out) ---
    m13_benign = _check_m13_benign_profile(m13)
    if m13_benign:
        return True, -0.9, m13_benign

    # --- Rule 3: IsolationForest on 5D feature vector ---
    # If the finding had no embedded path, use the canonical expected path so that
    # path_depth is representative; an empty path would produce depth=0 which makes
    # every known-good system process look anomalous to IsolationForest.
    effective_path = process_path
    if not effective_path:
        proc_lower = process_name.lower()
        canonical = EXPECTED_PATHS.get(proc_lower)
        if canonical:
            effective_path = next(iter(canonical))
    vec = process_feature_vector(process_name, effective_path, parent_name, m13)
    forest = _get_forest()
    if forest is not None:
        arr = np.array([vec], dtype=float)
        score = float(forest.decision_function(arr)[0])
        is_noise = score < NOISE_THRESHOLD
        if is_noise:
            rationale = (
                f'ML IsolationForest score={score:.3f} (threshold={NOISE_THRESHOLD}): '
                f'process behavioral profile is indistinguishable from normal system '
                f'background noise -- no investigation required'
            )
        else:
            rationale = (
                f'ML IsolationForest score={score:.3f}: anomalous vs. system baseline '
                f'-- process is NOT normal background noise; module investigation required'
            )
        return is_noise, score, rationale

    # --- Rule 4: Fallback heuristic (sklearn absent) ---
    proc_lower = process_name.lower()
    parent_lower = parent_name.lower()
    if (proc_lower in KNOWN_SYSTEM_PROCESSES and
            (parent_lower, proc_lower) in BENIGN_PARENT_CHILD):
        return True, -0.5, (
            f'Fallback: {process_name} with known-benign parent-child tuple '
            f'({parent_name} -> {process_name})'
        )

    return False, 0.0, (
        'sklearn unavailable and no structural match found -- '
        'conservative: route to module investigation'
    )
