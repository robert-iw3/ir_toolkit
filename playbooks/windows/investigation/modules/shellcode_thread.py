"""Module 5 -- Shellcode Thread investigation logic.

JIT-consistent annotation does NOT clear a finding.
Corroboration checklist from investigation guide:
  Module 19 named-family rule in same PID -> TP regardless of JIT
  Module 12 patched stub -> JMP-AMSI fingerprint -> TP
  Cross-process creation -> definitive injection
  Start address in Module 3 or Module 5b region -> TP
  None of the above -> likely benign JIT -- document
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension


def investigate(finding: dict) -> List[Dimension]:
    dims: List[Dimension] = []
    details = finding.get('Details', '')

    # "Not JIT-consistent" must NOT match the positive JIT check
    is_jit        = bool(re.search(r'(?<!Not\s)JIT.consistent', details, re.IGNORECASE))
    is_cross_proc = bool(re.search(r'cross.process|CreateRemoteThread|remote.*thread', details, re.IGNORECASE))

    # File-backed (image) VAD findings include advisory text like
    # "Corroborate: check Module 3 for anonymous exec regions in same PID."
    # That advisory must NOT be treated as confirmation that THIS thread resides in an
    # anonymous exec region.  Detect file-backed first, then suppress the anon-exec checks.
    is_file_backed_image = bool(re.search(r'file.backed.*image|image.*vad|vad=image', details, re.IGNORECASE))

    if not is_file_backed_image:
        in_anon_exec = bool(re.search(r'anonymous.*exec|anon.*exec|private.*exec', details, re.IGNORECASE))
        # "Module 3 flagged VAD" = thread started inside a region already flagged by the
        # injected-memory module -- same semantic as anon exec
        m3_corroboration = bool(re.search(
            r'Module\s*3.*VAD|Module\s*3.*flagged|inside.*injected', details, re.IGNORECASE
        ))
        if m3_corroboration:
            in_anon_exec = True
    else:
        in_anon_exec = False
    has_mz        = bool(re.search(r'Module.5b|MZ.header|manually.mapped|reflective', details, re.IGNORECASE))
    yara_named    = bool(re.search(r'Module.19|named.family|YARA.*family', details, re.IGNORECASE))
    ntdll_patched = bool(re.search(r'Module.12|ntdll.*hook|JMP-AMSI|SysWhispers', details, re.IGNORECASE))

    if is_cross_proc:
        dims.append(Dimension(
            name='Module5_CrossProcessThread', positive=True, source_module=5,
            rationale='Thread created cross-process (CreateRemoteThread from another PID) -- '
                      'definitive remote code injection fingerprint'
        ))

    if has_mz:
        dims.append(Dimension(
            name='Module5_MZ_InAnonExec', positive=True, source_module=5,
            rationale='MZ header in anonymous exec VAD (Module 5b) -- '
                      'manually-mapped PE via Donut or reflective DLL injection'
        ))

    if yara_named:
        dims.append(Dimension(
            name='Module5_YARA_Named_Corroborated', positive=True, source_module=5,
            rationale='Module 19 named-family YARA rule corroborates this thread -- '
                      'TP regardless of JIT-consistent annotation'
        ))

    if ntdll_patched:
        dims.append(Dimension(
            name='Module5_NtdllHook_Corroborated', positive=True, source_module=5,
            rationale='Module 12 ntdll hook in same PID -- JMP-AMSI pattern; '
                      'patched stubs used to execute shellcode thread without syscall interception'
        ))

    if in_anon_exec and not is_jit:
        dims.append(Dimension(
            name='Module5_AnonExecThread', positive=True, source_module=5,
            rationale='Thread start address in anonymous executable region (non-JIT) -- '
                      'strong indicator of shellcode execution'
        ))
    elif in_anon_exec and is_jit:
        if not (yara_named or ntdll_patched or is_cross_proc or has_mz):
            dims.append(Dimension(
                name='Module5_JIT_Unconfirmed', positive=False, source_module=5,
                rationale='JIT-consistent: thread start in anon exec of known JIT host. '
                          'No corroborating signals (YARA, ntdll hook, cross-proc, MZ). '
                          'Likely benign JIT activity -- document and exclude. '
                          'Do not mark FP solely on JIT annotation; re-check with next collection pass.'
            ))
    elif is_jit and not in_anon_exec:
        # JIT annotation without anon-exec label in details -- still JIT-consistent.
        # If no corroboration, produce negative JIT dim (not a fallback positive).
        if not (yara_named or ntdll_patched or is_cross_proc or has_mz):
            dims.append(Dimension(
                name='Module5_JIT_Unconfirmed', positive=False, source_module=5,
                rationale='JIT-consistent annotation with no corroborating signals. '
                          'Thread start outside modules but in known JIT host. '
                          'Do not promote to TP without additional evidence.'
            ))

    if not dims:
        if is_file_backed_image:
            # Thread in image VAD that isn't in the PEB module list.
            # At this point: no cross-proc, no YARA, no anon exec, no MZ.
            # Could be snapshot race (DLL loaded but PEB not yet updated) or
            # a DLL injected without PEB linkage.  Without corroboration this
            # is NOT strong enough to call shellcode.
            dims.append(Dimension(
                name='Module5_PEB_Unlinked_Thread', positive=False, source_module=5,
                rationale='Thread start in file-backed image VAD absent from PEB module list. '
                          'Could be DLL injection without PEB linkage (T1055.003) or snapshot '
                          'race condition. No corroborating anon exec, cross-proc, or YARA hit. '
                          'Investigate: check Module 3 for anonymous exec regions in same PID.'
            ))
        else:
            dims.append(Dimension(
                name='Module5_ShellcodeThread', positive=True, source_module=5,
                rationale='Thread start outside all loaded modules in this process -- '
                          'consistent with shellcode execution'
            ))

    return dims
