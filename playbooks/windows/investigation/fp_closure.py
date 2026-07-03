"""FP closure: structured rationale for documented benign verdicts.

A valid FP closure must:
  1. List every checked dimension and its verdict
  2. State why the combination cannot simultaneously be malicious
  3. Note any actions required before final closure (binary hash verification, etc.)
"""
from __future__ import annotations
from typing import List

from .verdict import Verdict, VerdictLabel, Dimension

_HASH_REQUIRED_TYPES = {'Dormant Beacon Candidate (Memory)', 'YARA Hit (Memory)'}


def build_fp_closure(pid: int, process: str, dims: List[Dimension],
                     findings: List[dict]) -> Verdict:
    neg = [d for d in dims if not d.positive]
    pos = [d for d in dims if d.positive]

    requires_hash = any(f.get('Type', '') in _HASH_REQUIRED_TYPES for f in findings)

    lines = [f'FP closure for PID {pid} ({process}):']
    lines.append(f'  Checked {len(dims)} dimension(s): {len(pos)} positive, {len(neg)} negative.')

    if dims:
        lines.append('')
        for d in dims:
            tag = 'TP' if d.positive else 'FP'
            lines.append(f'  [{tag}] M{d.source_module} {d.name}: {d.rationale}')

    lines.append('')
    if pos:
        lines.append(f'  NOTE: {len(pos)} positive dimension(s) present -- classification is '
                     'UNDETERMINED, not FP. Full corroboration required before any closure.')
    else:
        lines.append('  All checked dimensions converge on benign explanation. '
                     'No TP-class signal is present.')

    if requires_hash:
        lines.append('')
        lines.append('  ACTION REQUIRED before final closure: verify binary hash.')
        lines.append('  Command: Get-FileHash "<process_path>" -Algorithm SHA256')
        lines.append('  If Authenticode signer != Microsoft Windows or hash differs: '
                     'do NOT close -- escalate as stomped binary.')

    label = VerdictLabel.FALSE_POSITIVE if not pos else VerdictLabel.UNDETERMINED
    return Verdict(
        pid=pid, process=process, label=label,
        dimensions=dims, positive_count=len(pos), negative_count=len(neg),
        rationale='\n'.join(lines), findings=findings,
    )


def build_noise_closure(pid: int, process: str, noise_rationale: str,
                        findings: List[dict], noise_score: float) -> Verdict:
    """ML noise closure: process is certain background noise; skip module investigation."""
    rationale = (
        f'NOISE closure for PID {pid} ({process}):\n'
        f'  {noise_rationale}\n'
        f'  ML score: {noise_score:.3f}\n'
        f'  Module investigation skipped: confirmed system background noise.\n'
        f'  CPU cycles saved: no further analysis required.'
    )
    return Verdict(
        pid=pid, process=process, label=VerdictLabel.NOISE_CLOSED,
        dimensions=[], positive_count=0, negative_count=0,
        rationale=rationale, noise_score=noise_score, findings=findings,
    )
