"""
WMIPersistenceConfig -- mwcp parser for WMI event-subscription persistence
embedded in a dropper (the __EventFilter/__EventConsumer/
__FilterToConsumerBinding triad a dropper writes to establish persistence).

Two independent mechanisms, both required together:
  1. A WQL (WMI Query Language) trigger clause: `SELECT ... FROM
     __InstanceCreationEvent` / `__InstanceModificationEvent` / `__Timer...`
     -- WQL's own SQL-like grammar, dictated by WMI's query engine, not
     operator-chosen.
  2. A consumer payload field: `CommandLineTemplate` (CommandLineEventConsumer)
     or `ScriptText`/`ScriptingEngine` (ActiveScriptEventConsumer) -- the
     exact property names WMI's own consumer classes require.

A WQL query alone is common in legitimate WMI tooling/management scripts.
A command-line/script string alone is not evidence of anything. Only the
SAME file containing both the trigger grammar AND a consumer payload field
is the actual persistence-registration shape -- distinct mechanisms
(trigger condition + execution payload) that only co-occur when a dropper
is constructing the full subscription triad.

Detection never checks for a malware name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_WQL_RE = re.compile(
    rb'(?i)SELECT\s+[^\x00]{0,200}\s+FROM\s+__(?:Instance(?:Creation|Modification|Deletion)Event|'
    rb'(?:Absolute|Interval)Timer)')

_CONSUMER_RE = re.compile(rb'CommandLineTemplate|ScriptText|ScriptingEngine')

_CMD_ARG_RE = re.compile(rb'CommandLineTemplate["\']?\s*[:=]\s*["\']?([^\x00"\']{4,300})')


class WMIPersistenceConfig(mwcp.Parser):
    """Detect an embedded WMI event-subscription persistence triad."""

    DESCRIPTION = "WMI Event-Subscription Persistence Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        return bool(_WQL_RE.search(data)) and bool(_CONSUMER_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        wql_m = _WQL_RE.search(data)
        cons_m = _CONSUMER_RE.search(data)
        if not (wql_m and cons_m):
            return

        cmd_m = _CMD_ARG_RE.search(data)
        cmd = cmd_m.group(1).decode('utf-8', 'ignore') if cmd_m else ''
        if cmd:
            self.report.add(DecodedString(f'[WMI-Persistence-Command] {cmd}'))
        self.report.add(DecodedString(
            f'[WMI-Persistence] WQL trigger ({wql_m.group(0)[:80].decode("utf-8","ignore")}) '
            f'+ consumer payload field ({cons_m.group(0).decode()}) -- full subscription triad shape'))
