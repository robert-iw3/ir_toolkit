"""Module 18 -- COM VTable Hijacking investigation logic.

From investigation guide:
  src_address -> dst_address: pointer in .rdata/.data resolves to anonymous exec
  dst falls in Module 13/3 known-suspicious region -> TP
  YARA on dst -> family identification
  Dormant VTable (no active threads calling) -> may be corruption artifact
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension


def investigate(finding: dict) -> List[Dimension]:
    dims: List[Dimension] = []
    details = finding.get('Details', '')

    src_m = re.search(r'src[_\s]address[=:\s]*(0x[0-9a-f]+)', details, re.IGNORECASE)
    dst_m = re.search(r'dst[_\s]address[=:\s]*(0x[0-9a-f]+)', details, re.IGNORECASE)
    src_addr = src_m.group(1) if src_m else ''
    dst_addr = dst_m.group(1) if dst_m else ''

    in_anon_exec = bool(re.search(r'anonymous.*exec|anon.*exec|private.*exec', details, re.IGNORECASE))
    in_known_region = bool(re.search(r'Module.13|Module.3|dormant.*beacon|injected', details, re.IGNORECASE))
    yara_match   = bool(re.search(r'yara|YARA|rule.*match|family', details, re.IGNORECASE))
    no_active    = bool(re.search(r'dormant.*vtable|no.*active.*thread|not.*called', details, re.IGNORECASE))

    if in_anon_exec:
        dims.append(Dimension(
            name='Module18_VTable_AnonExec', positive=True, source_module=18,
            rationale=(f'COM VTable pointer ({src_addr} -> {dst_addr}) redirects to anonymous '
                       'executable region. Legitimate VTables point back into their own image. '
                       'This is a hijacked VTable (shellcode dispatch via COM method call).')
        ))

    if in_known_region:
        dims.append(Dimension(
            name='Module18_VTable_ToBeacon', positive=True, source_module=18,
            rationale=(f'VTable destination {dst_addr} falls inside a region already flagged '
                       'by Module 13/3 for this PID -- VTable hijack points directly into implant storage')
        ))

    if yara_match:
        dims.append(Dimension(
            name='Module18_VTable_YARAConfirmed', positive=True, source_module=18,
            rationale=(f'YARA rule matched the VTable destination region {dst_addr} -- '
                       'family identification confirmed; this is not a memory corruption artifact')
        ))

    if no_active and not (in_known_region or yara_match):
        dims.append(Dimension(
            name='Module18_DormantVTable', positive=False, source_module=18,
            rationale=(f'VTable pointer anomaly detected but COM interface appears dormant '
                       '(no active threads calling it). May be a memory corruption artifact '
                       'rather than deliberate hijacking. YARA on dst_addr and cross-check '
                       'Module 3/13 before concluding.')
        ))

    if not dims:
        dims.append(Dimension(
            name='Module18_VTable_Anomaly', positive=True, source_module=18,
            rationale=(f'COM VTable anomaly: {src_addr} -> {dst_addr}. '
                       'Verify dst in anonymous exec; check active thread usage; run YARA on dst region.')
        ))

    return dims
