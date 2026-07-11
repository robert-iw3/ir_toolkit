"""
BloodHoundCollectionConfig -- mwcp parser for SharpHound/BloodHound-style
Active Directory ACL/object collection: an LDAP wildcard enumeration
filter paired with the AD Security-Descriptor control OID.

Two independent mechanisms, both required:
  1. An LDAP wildcard enumeration filter: `(objectClass=*)` or
     `(objectCategory=*)` -- broad-enumeration filter syntax dictated by
     LDAP's own filter grammar (RFC 4515), not operator-chosen.
  2. The AD Security-Descriptor control OID `1.2.840.113556.1.4.801`
     (LDAP_SERVER_SD_FLAGS) -- the exact, Microsoft-assigned control OID
     a client must send to pull `nTSecurityDescriptor`/ACL data alongside
     an object query; ordinary AD reporting/inventory scripts have no
     reason to request ACL data on every object.

A wildcard enumeration filter alone is common in benign AD reporting
tools (inventory scripts routinely enumerate all users/computers). The
SD_FLAGS control OID alone could appear in unrelated ACL-management
tooling. Only a wildcard enumeration query paired with the ACL-pulling
control OID, in the same file, is the BloodHound-style collection shape.

Detection never checks for a malware/tool name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_LDAP_WILDCARD_RE = re.compile(rb'\((?:objectClass|objectCategory)=\*\)')
_SD_FLAGS_OID = b'1.2.840.113556.1.4.801'


class BloodHoundCollectionConfig(mwcp.Parser):
    """Detect AD ACL/object collection: LDAP wildcard filter + SD_FLAGS
    control OID."""

    DESCRIPTION = "AD ACL/Object Collection (SharpHound-style) Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_LDAP_WILDCARD_RE.search(data)) and _SD_FLAGS_OID in data

    def run(self):
        data = self.file_object.data
        if not data:
            return
        filter_m = _LDAP_WILDCARD_RE.search(data)
        if not (filter_m and _SD_FLAGS_OID in data):
            return

        self.report.add(DecodedString(
            f'[AD-Collection] LDAP wildcard filter ({filter_m.group(0).decode("utf-8","ignore")}) '
            f'+ SD_FLAGS control OID ({_SD_FLAGS_OID.decode()}) -- '
            f'ACL/object collection shape'))
