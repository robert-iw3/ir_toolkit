"""FP closure: structured rationale for documented benign verdicts (Linux).

A valid FP closure must:
  1. List every checked dimension and its verdict
  2. State why the combination cannot simultaneously be malicious
  3. Note any actions required before final closure (package integrity
     verification, binary hash, upgrade-window correlation)
"""
from __future__ import annotations
from typing import List

from .verdict import Verdict, VerdictLabel, Dimension

# Finding types whose FP closure is only final after the on-disk binary has
# been tied back to a distro package (the Linux trust anchor -- there is no
# Authenticode; dpkg/rpm ownership + integrity is what stands in for it).
_PKG_VERIFY_TYPES = {
    'Process Running Deleted Binary (memory)', 'Deleted Running Binary',
    'YARA Memory Match', 'Injected Code (memory YARA)',
    'io_uring In Use (memory, verify)', 'io_uring In Use (verify)',
    'External Connection (memory)', 'External Connection',
}


def build_fp_closure(pid: int, process: str, dims: List[Dimension],
                     findings: List[dict]) -> Verdict:
    neg = [d for d in dims if not d.positive]
    pos = [d for d in dims if d.positive]

    # Only ask the analyst to go verify manually if package verification did
    # NOT already happen -- correlator.py's _package_integrity_dimension /
    # _package_upgrade_window_dimension add a real M_PackageIntegrity_* dimension
    # when Adjudication_*.json / package-manager-log data was actually available.
    pkg_verified = any(d.name.startswith('M_PackageIntegrity_') for d in dims)
    requires_pkg = (not pkg_verified and
                    any(f.get('Type', '') in _PKG_VERIFY_TYPES for f in findings))

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

    if requires_pkg:
        lines.append('')
        lines.append('  ACTION REQUIRED before final closure: verify package ownership + integrity.')
        lines.append('  Commands: dpkg -S <path> && dpkg -V <pkg>   (Debian/Ubuntu)')
        lines.append('            rpm -qf <path> && rpm -V <pkg>    (RHEL/SUSE/Fedora)')
        lines.append('  If the file is owned by no package, or the package reports it modified: '
                     'do NOT close -- escalate as a trojanised/unowned binary.')

    label = VerdictLabel.FALSE_POSITIVE if not pos else VerdictLabel.UNDETERMINED
    return Verdict(
        pid=pid, process=process, label=label,
        dimensions=dims, positive_count=len(pos), negative_count=len(neg),
        rationale='\n'.join(lines), findings=findings,
    )


def build_noise_closure(pid: int, process: str, noise_rationale: str,
                        findings: List[dict], noise_score: float) -> Verdict:
    """Noise closure: process is certain background noise; skip module investigation."""
    rationale = (
        f'NOISE closure for PID {pid} ({process}):\n'
        f'  {noise_rationale}\n'
        f'  Score: {noise_score:.3f}\n'
        f'  Module investigation skipped: confirmed system background noise.'
    )
    return Verdict(
        pid=pid, process=process, label=VerdictLabel.NOISE_CLOSED,
        dimensions=[], positive_count=0, negative_count=0,
        rationale=rationale, noise_score=noise_score, findings=findings,
    )
