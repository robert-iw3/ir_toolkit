"""
DNSTunnelC2Config -- mwcp parser for DNS-based C2/exfiltration: a TXT-
record-specific DNS query construction paired with an encoded-looking,
oversized subdomain label.

Two independent mechanisms, both required:
  1. A TXT-record-specific query construction: PowerShell
     `Resolve-DnsName ... -Type TXT`, or the Win32 `DnsQuery_A`/
     `DnsQuery_W` API paired with the `DNS_TYPE_TEXT` (0x0010) constant
     -- TXT queries are the DNS tunneling technique's own required
     record type (large arbitrary payloads don't fit in an A/AAAA
     answer), not operator-chosen.
  2. An oversized subdomain label using the RFC 4648 base32 alphabet
     (`A-Z2-7` only) -- DNS labels are case-INSENSITIVE end-to-end
     (resolvers, caches, and some registrars fold case), which is why
     DNS tunneling tools (dnscat2, iodine, and the technique generally)
     encode payload data as base32, not base64: base64's mixed-case and
     `+/=` alphabet cannot survive a case-folding hop intact, while
     base32's restricted alphabet can. A 32+ character label drawn
     ONLY from `A-Z2-7` immediately before a routable TLD is therefore
     not just "looks encoded" -- it is the specific encoding alphabet
     the DNS channel's own case-insensitivity forces a tunneling tool
     to use.

A TXT query alone is completely ordinary (SPF/DKIM/verification record
lookups use TXT constantly). A long uppercase/digit label alone could
coincidentally occur. Only a TXT-specific query construction paired
with an oversized base32-alphabet label, in the same file, is the
DNS-tunneling shape.

Detection never checks for a malware/tool name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_TXT_QUERY_RE = re.compile(
    rb'Resolve-DnsName[^\x00\r\n]{0,80}-Type\s+TXT|DNS_TYPE_TEXT|DnsQuery_[AW][^\x00\r\n]{0,40}0x0010')

_ENCODED_LABEL_RE = re.compile(
    rb'\b[A-Z2-7]{32,63}\.[A-Za-z0-9-]{1,24}(?:\.[A-Za-z0-9-]{1,24}){0,3}\.[A-Za-z]{2,24}\b')


class DNSTunnelC2Config(mwcp.Parser):
    """Detect DNS tunneling: TXT-specific query construction + oversized
    encoded subdomain label."""

    DESCRIPTION = "DNS Tunneling (TXT Record) C2 Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32 or not _TXT_QUERY_RE.search(data):
            return False
        return bool(_ENCODED_LABEL_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        query_m = _TXT_QUERY_RE.search(data)
        if not query_m:
            return
        label_m = _ENCODED_LABEL_RE.search(data)
        if not label_m:
            return

        self.report.add(DecodedString(
            f'[DNS-Tunnel] TXT query construction ({query_m.group(0)[:40].decode("utf-8","ignore")}) '
            f'+ encoded subdomain label ({label_m.group(0).decode("utf-8","ignore")}) -- '
            f'DNS-tunneling shape'))
