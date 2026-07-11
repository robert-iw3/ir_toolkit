"""
AntiAnalysisStrings -- mwcp parser for embedded VM/sandbox/analyst-tool
artifact names a binary checks for before deciding whether to execute
its real payload (an anti-analysis / environment-awareness capability,
common in loaders and second-stage payloads that avoid detonating
inside a sandbox).

These are not malware-family name strings an operator can strip --
they are the FIXED third-party names (VMware/VirtualBox/QEMU process
and driver names, sandbox agent process names, analyst tool process
names) the malware MUST literally compare against for its evasion
check to function; the check is meaningless without referencing the
target's real, vendor-defined name. This is the same Rule 3 exception
class as a registry key path or protocol field name.

A single artifact-name match alone is not sufficient -- a legitimate
installer might reference "VMware Tools" once for compatibility
reasons (e.g. adjusting display resolution), and that is not evidence
of anti-analysis logic. Detection requires matches from 2+ DIFFERENT
artifact categories (virtualization platform, sandbox/agent, analyst
tool) in the same file -- a cluster of cross-category environment
checks is what distinguishes deliberate anti-analysis logic from one
incidental compatibility reference.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

# Matched against data.lower() -- avoids re's (?i) case-folding cost, which is
# markedly slower than a case-sensitive search across multi-MB inputs (the
# case-insensitive alternation here was the dominant cost against large
# carved memory regions; lower()-once + case-sensitive match is equivalent
# and runs at C speed for the lower() step).
_VM_RE = re.compile(
    rb'\b(vboxservice\.exe|vboxtray\.exe|vboxguest|vboxmouse|vboxsf|'
    rb'vmtoolsd\.exe|vmwaretray\.exe|vmwareuser\.exe|vmci\.sys|vmmouse|'
    rb'qemu-ga\.exe|virtio|prl_cc\.exe|prl_tools|vmwareservice\.exe)\b')
_SANDBOX_RE = re.compile(
    rb'\b(sbiedll\.dll|sxin\.dll|sandboxie|cuckoomon\.dll|'
    rb'joeboxserver\.exe|joeboxcontrol\.exe|wpespy\.dll|api_log\.dll)\b')
_ANALYST_TOOL_RE = re.compile(
    rb'\b(x32dbg\.exe|x64dbg\.exe|ollydbg\.exe|idaq(?:64)?\.exe|ida64\.exe|'
    rb'processhacker\.exe|procmon\.exe|procexp(?:64)?\.exe|wireshark\.exe|'
    rb'dumpcap\.exe|fiddler\.exe|hookexplorer|importrec|petools\.exe|'
    rb'lordpe\.exe|sysinspector\.exe)\b')

_CATEGORIES = (('vm', _VM_RE), ('sandbox', _SANDBOX_RE), ('analyst_tool', _ANALYST_TOOL_RE))


def _matched_categories(data: bytes) -> dict:
    lower = data.lower()
    out = {}
    for name, rx in _CATEGORIES:
        m = rx.search(lower)
        if m:
            out[name] = data[m.start(1):m.end(1)]   # original casing, same offsets
    return out


class AntiAnalysisStrings(mwcp.Parser):
    """Detect anti-analysis environment checks: 2+ distinct artifact
    categories (VM / sandbox / analyst tool) referenced in the same
    file."""

    DESCRIPTION = "Anti-Analysis (VM/Sandbox/Analyst-Tool Check) Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        return len(_matched_categories(data)) >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return
        hits = _matched_categories(data)
        if len(hits) < 2:
            return

        summary = ', '.join(
            f'{cat}={val.decode("utf-8","ignore")}' for cat, val in hits.items())
        self.report.add(DecodedString(
            f'[AntiAnalysis] {len(hits)} distinct artifact categories referenced ({summary}) -- '
            f'environment-awareness/evasion shape'))
