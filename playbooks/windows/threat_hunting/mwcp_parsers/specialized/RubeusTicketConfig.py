"""
RubeusTicketConfig -- mwcp parser for Kerberos ticket manipulation tooling
(Rubeus, Impacket ticketer/ticketConverter, etc.): the pass-the-ticket
inject flag paired with an embedded KRB-CRED structure.

Two independent mechanisms, both required:
  1. The `/ptt` (pass-the-ticket) inject flag -- Rubeus's own fixed
     command-line switch for injecting a ticket into the current logon
     session, not operator-chosen.
  2. An embedded KRB-CRED ASN.1 structure: the `\\x76\\x82` APPLICATION-22
     (AP-REQ/TGT wrapper) DER tag -- the exact ASN.1 tag byte Kerberos's
     own wire format uses to wrap a credential/ticket, dictated by RFC
     4120, not operator-chosen.

A bare `/ptt` string alone can appear in benign Kerberos documentation or
unrelated command-line parsing code. A `\\x76\\x82` byte sequence alone is
common coincidental binary noise. Only the inject flag paired with an
actual embedded ticket structure, in the same file, is the
ticket-manipulation-tool shape.

Detection never checks for a malware/tool name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import mwcp
from mwcp.metadata import DecodedString

_PTT_FLAG = b'/ptt'
_KRB_CRED_TAG = b'\x76\x82'


class RubeusTicketConfig(mwcp.Parser):
    """Detect Kerberos ticket manipulation: /ptt inject flag + embedded
    KRB-CRED structure."""

    DESCRIPTION = "Kerberos Ticket Manipulation (Pass-the-Ticket) Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return _PTT_FLAG in data and _KRB_CRED_TAG in data

    def run(self):
        data = self.file_object.data
        if not data:
            return
        if not (_PTT_FLAG in data and _KRB_CRED_TAG in data):
            return

        self.report.add(DecodedString(
            '[Rubeus-PTT] /ptt inject flag + embedded KRB-CRED structure -- '
            'pass-the-ticket tool shape'))
