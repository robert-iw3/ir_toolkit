"""
ScheduledTaskConfig -- mwcp parser for an embedded Windows Scheduled Task
XML definition whose action arguments carry TWO independent obfuscation/
stealth primitives together.

Task Scheduler's own XML schema requires an `<Actions><Exec><Command>`
element to do anything -- that structural requirement is not optional and
not operator-chosen. But a `<Exec>` action alone is not suspicious: the
overwhelming majority of scheduled tasks on any Windows host are entirely
legitimate automation.

Detection requires the `<Exec>`/`<Command>` action structure TOGETHER WITH
its `<Arguments>` carrying BOTH of two independently-meaningful stealth
primitives: a hidden-window flag (`-WindowStyle Hidden` / `-w hidden`) AND
an encoded/obfuscated-command flag (`-EncodedCommand` / `-enc`). Each flag
is a distinct mechanism (suppressing UI feedback vs. hiding the actual
payload from static string review) -- legitimate scheduled automation
essentially never combines both, whereas a script-dropped persistence task
does so specifically to avoid both visual and static-analysis detection.

Detection never gates on which binary is invoked (LOLBin name) -- only on
this specific combination of behavioral flags in the task's own arguments.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_EXEC_RE = re.compile(
    rb'<Exec>\s*<Command>([^<]{2,260})</Command>\s*(?:<Arguments>([^<]{0,2000})</Arguments>)?',
    re.IGNORECASE | re.DOTALL)
_HIDDEN_RE  = re.compile(rb'(?i)-w(?:indowstyle)?\s+hidden\b')
_ENCODED_RE = re.compile(rb'(?i)-enc(?:odedcommand)?\b')


class ScheduledTaskConfig(mwcp.Parser):
    """Detect an embedded scheduled-task action combining hidden-window
    AND encoded-command stealth primitives."""

    DESCRIPTION = "Scheduled Task Stealth-Action Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32 or b'<Exec>' not in data:
            return False
        for m in _EXEC_RE.finditer(data):
            args = m.group(2) or b''
            if _HIDDEN_RE.search(args) and _ENCODED_RE.search(args):
                return True
        return False

    def run(self):
        data = self.file_object.data
        if not data:
            return
        for m in _EXEC_RE.finditer(data):
            command = m.group(1).decode('utf-8', 'ignore').strip()
            args = m.group(2) or b''
            if not (_HIDDEN_RE.search(args) and _ENCODED_RE.search(args)):
                continue
            args_s = args.decode('utf-8', 'ignore').strip()
            self.report.add(DecodedString(
                f'[ScheduledTask-StealthAction] command={command} args={args_s[:300]} -- '
                f'hidden-window AND encoded-command flags together'))
