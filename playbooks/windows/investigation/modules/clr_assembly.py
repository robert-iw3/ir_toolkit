"""Module 16 -- CLR Execute-Assembly (BSJB in anonymous exec VAD).

From investigation guide:
  BSJB cannot appear naturally in a non-.NET process.
  If found in anonymous exec VAD of a native process -> definitive Donut/execute-assembly.
  Fully-managed hosts (PowerShell, dotnet, msbuild) are exclusions.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension

_MANAGED_HOSTS = frozenset({
    'powershell.exe', 'pwsh.exe', 'dotnet.exe', 'msbuild.exe',
    'csc.exe', 'vbc.exe', 'jsc.exe', 'devenv.exe',
    'testhost.exe', 'mstest.exe', 'vstest.console.exe',
    'installutil.exe', 'regasm.exe', 'regsvcs.exe',
})


def investigate(finding: dict) -> List[Dimension]:
    dims: List[Dimension] = []
    details = finding.get('Details', '')
    target  = finding.get('Target', '')

    proc_m  = re.search(r'PID\s+\d+\s+\(([^)]+)\)', target)
    process = proc_m.group(1).lower() if proc_m else ''

    is_managed  = process in _MANAGED_HOSTS
    has_bsjb    = bool(re.search(r'BSJB|bsjb|ecma.335', details, re.IGNORECASE))
    in_anon_exec = bool(re.search(r'anonymous.*exec|anon.*exec|private.*exec', details, re.IGNORECASE))

    if is_managed:
        dims.append(Dimension(
            name='Module16_ManagedHost_Expected', positive=False, source_module=16,
            rationale=(f'{process} is a managed (.NET) host -- BSJB signature in anonymous exec '
                       'VAD is expected CLR JIT behavior, not execute-assembly injection. '
                       f'Verify process is in the standard managed host list: {process}.')
        ))
        return dims

    if has_bsjb and in_anon_exec:
        dims.append(Dimension(
            name='Module16_CLR_Execute_Assembly', positive=True, source_module=16,
            rationale=(f'BSJB (ECMA-335 assembly magic) in anonymous executable VAD '
                       f'of {process} (native process). BSJB cannot appear naturally here -- '
                       'definitive: Donut/execute-assembly in-memory .NET injection.')
        ))
    elif has_bsjb:
        dims.append(Dimension(
            name='Module16_BSJB_Present', positive=True, source_module=16,
            rationale=(f'BSJB signature present in {process} -- '
                       'confirm region is anonymous exec (not file-backed) before finalizing verdict')
        ))

    return dims
