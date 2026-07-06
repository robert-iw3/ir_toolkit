"""Module 9 -- persistence quick-sweep.

Toolkit signals: Cron Persistence, Systemd Persistence, udev Rule
Persistence, rc.local Persistence, Autostart Persistence, Shell Init
Backdoor, Recently Modified PAM Module (verify), SSH Forced-Command
Backdoor, Scheduled at-job Present, Suspicious Cron Job, Suspicious Service
Execution, New Account Created, Remote Root Logon, Remote-Access Service.

From DETAILED-FOLLOW-ON-LINUX.md Section 9: a persistence entry invoking a
download-and-execute one-liner (curl/wget/base64/nc) or running from a temp
dir has no legitimate explanation; an enabled unit/cron entry that IS a
known package (vendor path, signed) is the canonical FP. This module reads
the same signal the collector already embedded in Details rather than
re-deriving it.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension, Tier
from . import _shared

_DOWNLOAD_EXEC_RE = re.compile(
    r'curl|wget|/dev/tcp|base64|\bnc\b|ncat|python -c|bash -i|perl -e', re.IGNORECASE)


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    path = _shared.extract_path(details)

    has_download_exec = bool(_DOWNLOAD_EXEC_RE.search(details))
    in_writable = _shared.path_verdict(path) == 'writable' if path else False

    if has_download_exec:
        return [Dimension(
            name='M9_Persistence_DownloadExec', positive=True, source_module=9,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: persistence entry invokes a download-and-execute or reverse-'
                       f'shell one-liner -- {details[:200]}')
        )]

    if in_writable:
        return [Dimension(
            name='M9_Persistence_WritablePath', positive=True, source_module=9,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: entry points at a writable/volatile path {path!r} -- no '
                      'legitimate service is installed from there.'
        )]

    if ftype == 'Recently Modified PAM Module (verify)':
        return [Dimension(
            name='M9_Persistence_PAMModified', positive=True, source_module=9,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- verify against the owning package '
                      '(dpkg -V / rpm -Vf) before treating as confirmed tampering.'
        )]

    return [Dimension(
        name='M9_Persistence_Generic', positive=True, source_module=9,
        tier=Tier.WEAK_STRUCTURAL,
        rationale=(f'{ftype}: {details[:200]} -- persistence mechanism present; verify package '
                   'ownership of the referenced unit/binary before escalating.')
    )]
