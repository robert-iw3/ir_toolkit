"""Module 13 -- Dormant Beacon / W^X Region investigation logic.

From investigation guide:
  UNIFORM (CV < 15%) + AdjAnonExec=True + entropy >= 7.0 -> TP signals
  CV > 100% + AdjAnonExec=False + MZ-remnant=False -> benign signals
  Head=fc 48 83 e4 -> CobaltStrike preamble (TP)
  Head=7a 00 00 00 -> task scheduler work-item struct (FP)
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from ..verdict import Dimension

_CV_UNIFORM_MAX   = 15.0
_CV_MODERATE_MAX  = 40.0
_ENTROPY_HIGH     = 7.0
_ASCII_BENIGN_MIN = 30.0


def _parse(details: str) -> Dict[str, Any]:
    r: Dict[str, Any] = {}
    m = re.search(r'CV=([\d.]+)%', details)
    r['cv_pct'] = float(m.group(1)) if m else None
    m = re.search(r'ASCII=([\d.]+)%', details)
    r['ascii_pct'] = float(m.group(1)) if m else None
    r['mz_remnant']    = bool(re.search(r'MZ-remnant=True', details))
    r['adj_anon_exec'] = bool(re.search(r'AdjAnonExec=True', details))
    r['is_uniform']    = 'UNIFORM' in details
    m = re.search(r'entropy=([\d.]+)', details)
    r['entropy'] = float(m.group(1)) if m else None
    m = re.search(r'Head=([0-9a-f][0-9a-f ]{2,})', details)
    r['head_hex'] = m.group(1).strip() if m else ''
    return r


def investigate(finding: dict) -> List[Dimension]:
    dims: List[Dimension] = []
    d = _parse(finding.get('Details', ''))

    cv     = d.get('cv_pct')
    ascii_p = d.get('ascii_pct')
    mz     = d.get('mz_remnant', False)
    adj    = d.get('adj_anon_exec', False)
    ent    = d.get('entropy')
    head   = d.get('head_hex', '')

    # ---- Byte distribution (CV%) ----
    if cv is not None:
        if cv < _CV_UNIFORM_MAX:
            dims.append(Dimension(
                name='Module13_CV_UNIFORM', positive=True, source_module=13,
                rationale=(f'CV={cv:.0f}% < 15% -- near-flat byte distribution (UNIFORM), '
                           'characteristic of AES/RC4-encrypted payload at rest')
            ))
        elif cv > 100.0:
            dims.append(Dimension(
                name='Module13_CV_NonUniform', positive=False, source_module=13,
                rationale=(f'CV={cv:.0f}% > 100% -- highly non-uniform bytes; '
                           'inconsistent with encrypted payload; consistent with structured data buffer')
            ))
        else:
            dims.append(Dimension(
                name='Module13_CV_Moderate', positive=False, source_module=13,
                rationale=(f'CV={cv:.0f}% moderate (15-100%) -- ambiguous; '
                           'could be compressed data or partial-encryption; corroboration required')
            ))

    # ---- ASCII printable ratio ----
    if ascii_p is not None:
        if ascii_p < 5.0:
            dims.append(Dimension(
                name='Module13_ASCII_Low', positive=True, source_module=13,
                rationale=(f'ASCII={ascii_p:.0f}% < 5% -- near-zero printable bytes, '
                           'consistent with AES/RC4 encrypted payload')
            ))
        elif ascii_p >= _ASCII_BENIGN_MIN:
            dims.append(Dimension(
                name='Module13_ASCII_High', positive=False, source_module=13,
                rationale=(f'ASCII={ascii_p:.0f}% >= 30% -- high printable ratio '
                           'inconsistent with encrypted payload; suggests structured data with embedded strings')
            ))

    # ---- MZ remnant ----
    if mz:
        dims.append(Dimension(
            name='Module13_MZ_Remnant', positive=True, source_module=13,
            rationale='MZ-remnant=True -- PE header fragment in the region; '
                      'consistent with reflectively-loaded DLL or PE-derived shellcode'
        ))
    else:
        dims.append(Dimension(
            name='Module13_No_MZ', positive=False, source_module=13,
            rationale='MZ-remnant=False -- no PE header; reduces likelihood of PE-based implant'
        ))

    # ---- Adjacent anonymous exec region ----
    if adj:
        dims.append(Dimension(
            name='Module13_AdjAnonExec', positive=True, source_module=13,
            rationale='AdjAnonExec=True -- anonymous executable region adjacent to this buffer; '
                      'consistent with loader stub or decryption thunk positioned next to payload storage'
        ))
    else:
        dims.append(Dimension(
            name='Module13_No_AdjExec', positive=False, source_module=13,
            rationale='AdjAnonExec=False -- no adjacent anonymous exec region; '
                      'a sleep-masked beacon would typically have a loader stub nearby'
        ))

    # ---- Head bytes heuristic ----
    if head:
        fc48 = head.startswith('fc 48')                     # CobaltStrike preamble
        _4d5a = head.startswith('4d 5a') or head.startswith('4d5a')  # MZ
        struct_7a = head.startswith('7a 00')                # task-scheduler work-item
        zeros = all(b in ('00', '') for b in head.split()[:4])
        if fc48:
            dims.append(Dimension(
                name='Module13_HeadBytes_CSPrologue', positive=True, source_module=13,
                rationale=f'Head={head[:23]} -- matches CobaltStrike shellcode preamble (fc 48 83 e4 f0)'
            ))
        elif _4d5a:
            dims.append(Dimension(
                name='Module13_HeadBytes_MZ', positive=True, source_module=13,
                rationale=f'Head={head[:23]} -- MZ header (PE) at start of region'
            ))
        elif struct_7a:
            dims.append(Dimension(
                name='Module13_HeadBytes_StructMarker', positive=False, source_module=13,
                rationale=(f'Head={head[:23]} -- 0x7a DWORD header is consistent with '
                           'Windows task-scheduler work-item state structure, not a code preamble')
            ))
        elif zeros:
            dims.append(Dimension(
                name='Module13_HeadBytes_Zeroed', positive=False, source_module=13,
                rationale=f'Head={head[:23]} -- leading null bytes suggest zeroed/uninitialized region'
            ))

    return dims
