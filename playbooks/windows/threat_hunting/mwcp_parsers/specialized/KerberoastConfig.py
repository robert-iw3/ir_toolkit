"""
KerberoastConfig -- mwcp parser for a PowerShell Kerberoasting script
(Invoke-Kerberoast/PowerView-style SPN-ticket-harvesting tooling): SPN
enumeration paired with programmatic TGS ticket requests.

Two independent mechanisms, both required:
  1. `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` -- the
     exact .NET class a PowerShell script must instantiate to
     programmatically request a Kerberos service ticket (TGS) without
     going through a normal Windows API call chain; this class name is
     dictated by the .NET Kerberos ticket API itself, not
     operator-chosen.
  2. An LDAP SPN-enumeration filter: `(&(objectClass=user)
     (servicePrincipalName=*))` (or the userAccountControl-based
     variant) -- the exact LDAP search filter syntax needed to
     enumerate SPN-bearing accounts, dictated by LDAP/AD schema
     grammar, not operator-chosen.

The KerberosRequestorSecurityToken class alone can appear in benign
.NET authentication code unrelated to enumeration. An SPN LDAP filter
alone can appear in benign AD auditing/reporting scripts. Only the
SPN-enumeration filter paired with programmatic ticket requests, in
the same file, is the collect-then-crack Kerberoasting shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_TGS_TOKEN_RE = re.compile(
    rb'System\.IdentityModel\.Tokens\.KerberosRequestorSecurityToken')
_SPN_LDAP_FILTER_RE = re.compile(
    rb'\(&\(objectClass=user\)\((?:servicePrincipalName=\*|'
    rb'!userAccountControl:1\.2\.840\.113556\.1\.4\.803:=2\))')


class KerberoastConfig(mwcp.Parser):
    """Detect a Kerberoasting script: KerberosRequestorSecurityToken +
    SPN LDAP enumeration filter."""

    DESCRIPTION = "Kerberoasting (SPN Ticket Harvest) Script Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        return bool(_TGS_TOKEN_RE.search(data)) and bool(_SPN_LDAP_FILTER_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        token_m = _TGS_TOKEN_RE.search(data)
        filter_m = _SPN_LDAP_FILTER_RE.search(data)
        if not (token_m and filter_m):
            return

        self.report.add(DecodedString(
            f'[Kerberoast] SPN LDAP enumeration filter + KerberosRequestorSecurityToken '
            f'TGS request -- collect-then-crack Kerberoasting shape'))
