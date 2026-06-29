"""
SliverConfig -- mwcp parser for Sliver C2 implant configuration.

Sliver is an open-source Go-based C2 framework. Implant config is embedded
in the Go binary as a JSON blob or as Go const values. Key identifiers:
  - JSON with fields: implant_name, reconnect_interval, server_url, c2s, dns_c2s
  - String cluster: "implant_name", "server_url", "mtls" or "https" or "wg" near each other
  - Sliver-specific strings: "ActiveC2", "sliver.implant", "ReconnectInterval"

Config extraction targets:
  - C2 server URLs (mtls://, https://, wg://, dns:// schemes)
  - Implant name
  - Reconnect interval
  - mTLS cert fingerprint (unique per team server -- pivot indicator)
  - Kill date

References:
  - BishopFox Sliver source (https://github.com/BishopFox/sliver)
  - SEKOIA Sliver analysis
"""

import re
import json
import mwcp
from mwcp.metadata import C2URL, C2Address, DecodedString, Mutex

# Structural indicators: these are WIRE-PROTOCOL field names baked into the
# Sliver agent/server serialization layer. An operator cannot rename these
# without breaking protocol compatibility with the Sliver team server.
# Do NOT check for "sliver" or "BishopFox" -- those are stripped in production.
_SLIVER_PROTO_FIELDS = [
    b'"implant_name"', b'"reconnect_interval"', b'"c2s"', b'"dns_c2s"',
    b'"ActiveC2"',     b'"PollTimeout"',        b'"MaxConnectionErrors"',
    b'mtls://',        b'wg://',    # protocol schemes unique to Sliver's transport layer
]

# JSON config extraction
_JSON_RE = re.compile(
    rb'\{[^{}]{50,4000}(?:implant_name|ActiveC2|reconnect_interval|server_url)[^{}]{0,4000}\}',
    re.DOTALL
)

# C2 URL schemes used by Sliver
_C2_SCHEMES = (b'mtls://', b'https://', b'wg://', b'dns://', b'http://')
_C2_URL_RE = re.compile(
    rb'(?:mtls|https|wg|dns|http)://[^\s\x00\'"<>{}\[\]]{4,200}',
    re.IGNORECASE
)

# String-cluster extraction for Go binary (null-separated or adjacent strings)
_IMPLANT_NAME_RE   = re.compile(rb'(?:SliverName|implant_name)\x00{0,8}([A-Za-z0-9_\-]{3,32})', re.IGNORECASE)
_RECONNECT_RE      = re.compile(rb'(?:ReconnectInterval|reconnect_interval)\x00{0,8}(\d{1,8})', re.IGNORECASE)
_CERT_FP_RE        = re.compile(rb'(?:ca_cert|CertFingerprint|fingerprint)[^\x00]{0,32}([0-9a-fA-F]{40,64})')


class SliverConfig(mwcp.Parser):
    """Extract Sliver C2 implant configuration from Go binaries and shellcode."""

    DESCRIPTION = "Sliver C2 Framework Config Extractor"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''
        # Require 2+ protocol field names that are structurally required by the
        # Sliver wire protocol. An operator can strip debug symbols but cannot
        # rename these without rewriting the C2 server's JSON serialization.
        hits = sum(1 for f in _SLIVER_PROTO_FIELDS if f in data)
        return hits >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen_urls: set[str] = set()
        config_fields = {}

        # 1. Try structured JSON extraction
        for m in _JSON_RE.finditer(data):
            try:
                candidate = m.group(0).decode('utf-8', 'ignore')
                obj = json.loads(candidate)
                if isinstance(obj, dict) and any(k in obj for k in
                        ('implant_name', 'ActiveC2', 'reconnect_interval', 'server_url')):
                    config_fields.update(obj)
            except Exception:
                pass

        # 2. Extract C2 URLs from JSON config or raw binary
        c2_list = config_fields.get('c2s', config_fields.get('C2s', []))
        if isinstance(c2_list, list):
            for entry in c2_list:
                url = entry.get('url', '') if isinstance(entry, dict) else str(entry)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    self.report.add(C2URL(url))

        server_url = config_fields.get('server_url', '')
        if server_url and server_url not in seen_urls:
            seen_urls.add(server_url)
            self.report.add(C2URL(server_url))

        # 3. Raw binary C2 URL scan -- Sliver uses mtls:// and wg:// schemes
        # that are unique to Sliver's transport implementation
        for m in _C2_URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').rstrip('\x00 /').strip()
            if url and url not in seen_urls and len(url) > 8:
                seen_urls.add(url)
                self.report.add(C2URL(url))

        # 4. Implant name as Mutex (unique per implant build -- IOC)
        implant_name = config_fields.get('implant_name', '')
        if not implant_name:
            m = _IMPLANT_NAME_RE.search(data)
            if m:
                implant_name = m.group(1).decode('utf-8', 'ignore').strip('\x00')
        if implant_name:
            self.report.add(Mutex(implant_name))
            self.report.add(DecodedString(f'[Sliver-ImplantName] {implant_name}'))

        # 5. Reconnect interval
        interval = config_fields.get('reconnect_interval', 0)
        if not interval:
            m = _RECONNECT_RE.search(data)
            if m:
                interval = int(m.group(1))
        if interval:
            self.report.add(DecodedString(f'[Sliver-ReconnectInterval] {interval}s'))

        # 6. mTLS cert fingerprint (unique per team server -- pivot indicator)
        for m in _CERT_FP_RE.finditer(data):
            fp = m.group(1).decode('utf-8', 'ignore')
            self.report.add(DecodedString(f'[Sliver-CertFingerprint] {fp}'))

        # 7. DNS C2 domains
        dns_list = config_fields.get('dns_c2s', config_fields.get('dns', []))
        if isinstance(dns_list, list):
            for entry in dns_list:
                dom = entry.get('domain', '') if isinstance(entry, dict) else str(entry)
                if dom:
                    self.report.add(C2Address(dom))
                    self.report.add(DecodedString(f'[Sliver-DNS] {dom}'))

        # Summary
        if seen_urls or implant_name:
            summary = [f'C2={list(seen_urls)[:3]}']
            if implant_name:
                summary.append(f'Name={implant_name}')
            self.report.add(DecodedString(f'[Sliver-Config] {" ".join(summary)}'))
