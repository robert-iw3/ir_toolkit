"""Deterministic noise filter: separates normal Linux system background from
anomalous blending -- stdlib only, no numpy/sklearn dependency.

Unlike the Windows engine's ML-based filter (which interprets raw byte-
distribution signals -- CV%, ASCII%, entropy -- from unstructured memory
regions), Linux's collector scripts (edr_hunt.py, analyze_memory_linux.py)
already emit typed, largely pre-interpreted findings. The Linux noise
filter's job is narrower and fully deterministic: confirm a known system
daemon is running from its expected path, and that every finding on it is
individually weak/expected for that daemon, before skipping module
investigation.

Goal: close out `rsyslogd`/`systemd-udevd`/`sshd`/... background WITHOUT
wasting cycles on module logic, while never suppressing a finding whose
signal cannot be explained by "known daemon behaving normally."
"""
from __future__ import annotations
from typing import List, Tuple

from .linux_noise import (
    KNOWN_SYSTEM_PROCESSES, EXPECTED_PATH_PREFIXES, IO_URING_EXPECTED,
)

# Finding Types that are expected/benign FOR A KNOWN SYSTEM DAEMON specifically
# (never globally benign -- the same Type on an unknown process still routes
# to full module investigation). Kept narrow and explicit.
_BENIGN_ON_KNOWN_DAEMON = frozenset({
    'Process Preload', 'Process Preload (memory)',
    'io_uring In Use (memory, verify)', 'io_uring In Use (verify)',
    'Listening Service', 'Memory Capabilities (capa)',
})


def _check_path_legitimacy(process_name: str, process_path: str) -> Tuple[bool, str]:
    """Returns (is_bad, rationale). is_bad=True means a known-daemon name is
    running from an unexpected path -- a masquerade red flag, never noise."""
    proc_lower = process_name.lower()
    expected = EXPECTED_PATH_PREFIXES.get(proc_lower)
    if not expected or not process_path:
        return False, ''
    if any(process_path.startswith(p) for p in expected):
        return False, ''
    return True, (f'{process_name} running from unexpected path {process_path!r} '
                  f'(expected under one of {expected}) -- path masquerading likely.')


def classify_noise(process_name: str, process_path: str, parent_name: str,
                   pid_findings: List[dict]) -> Tuple[bool, float, str]:
    """Return (is_noise, score, rationale).

    is_noise=True means: certain system background, skip module investigation.
    score is a simple confidence sentinel (not a trained model output) kept
    for schema parity with the Windows engine's Verdict.noise_score field.
    """
    proc_lower = process_name.lower()

    is_bad_path, path_rationale = _check_path_legitimacy(process_name, process_path)
    if is_bad_path:
        return False, 1.0, path_rationale

    if proc_lower not in KNOWN_SYSTEM_PROCESSES:
        return False, 0.0, f'{process_name!r} is not a recognised system daemon -- full investigation required.'

    non_benign = [f for f in pid_findings
                  if f.get('Type', '') not in _BENIGN_ON_KNOWN_DAEMON]
    if non_benign:
        types = ', '.join(sorted({f.get('Type', '') for f in non_benign}))
        return False, 0.2, (f'{process_name!r} is a known daemon but carries finding type(s) '
                            f'outside the benign-on-daemon set ({types}) -- investigate.')

    # io_uring verify findings still need the "expected service" check for THIS name
    io_uring_findings = [f for f in pid_findings if 'io_uring' in f.get('Type', '')]
    if io_uring_findings and proc_lower not in IO_URING_EXPECTED and proc_lower not in KNOWN_SYSTEM_PROCESSES:
        return False, 0.3, f'{process_name!r} has io_uring activity but is not a documented io_uring user.'

    return True, -0.9, (f'{process_name!r} is a known system daemon running from its expected '
                        f'path with only benign-on-daemon finding type(s) -- closing without '
                        f'module investigation.')
