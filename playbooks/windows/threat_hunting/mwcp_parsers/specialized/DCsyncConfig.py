"""
DCsyncConfig -- mwcp parser for DCSync attack tooling (mimikatz
`lsadump::dcsync`, Impacket `secretsdump.py -just-dc`): a client-side
DRSUAPI replication call requesting the AD replication rights, not a
legitimate domain controller performing real inter-DC replication.

Two independent mechanisms, both required, both Microsoft-defined
fixed identifiers (Rule 3 exception -- neither is operator-chosen):
  1. The DRSUAPI RPC interface UUID `e3514235-4b06-11d1-ab04-
     00c04fc2dcd2` -- the fixed COM/RPC interface identifier a client
     must bind to before it can call `IDL_DRSGetNcChanges`, the RPC
     method that IS the DCSync technique.
  2. One of the AD replication extended-rights GUIDs referenced when
     requesting/verifying replication permissions: `1131f6aa-9c07-
     11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes) or
     `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
     (DS-Replication-Get-Changes-All).

The DRSUAPI interface UUID alone can appear in legitimate AD
replication tooling/logs (real DCs replicate constantly). The
extended-rights GUIDs alone can appear in benign AD ACL auditing
scripts. Only the DRSUAPI interface UUID paired with an explicit
replication-rights GUID reference, in the same file, is the
DCSync-tool-config shape (a real DC never needs to look up its own
replication-rights GUID to replicate -- only client-side tooling
constructing or checking for that permission does).

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_DRSUAPI_INTERFACE_RE = re.compile(
    rb'(?i)e3514235-4b06-11d1-ab04-00c04fc2dcd2')
_REPL_RIGHTS_GUID_RE = re.compile(
    rb'(?i)1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2')


class DCsyncConfig(mwcp.Parser):
    """Detect DCSync tooling: DRSUAPI interface UUID + AD replication
    rights GUID."""

    DESCRIPTION = "DCSync (DRSUAPI Replication Abuse) Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        return bool(_DRSUAPI_INTERFACE_RE.search(data)) and bool(_REPL_RIGHTS_GUID_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        iface_m = _DRSUAPI_INTERFACE_RE.search(data)
        rights_m = _REPL_RIGHTS_GUID_RE.search(data)
        if not (iface_m and rights_m):
            return

        self.report.add(DecodedString(
            f'[DCSync] DRSUAPI interface UUID + AD replication-rights GUID '
            f'({rights_m.group(0).decode("utf-8","ignore")}) -- DCSync attack config shape'))
