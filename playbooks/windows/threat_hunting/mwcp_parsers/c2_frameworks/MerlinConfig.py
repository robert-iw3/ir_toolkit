"""
MerlinConfig -- mwcp parser for Merlin C2 agent configuration.

Merlin is an open-source Go-based C2 agent. Config is embedded as JSON in the
compiled binary under field names from the merlin/pkg/agent/core package:
  - URL / url: C2 server URL
  - PSK / psk: pre-shared key for initial crypto
  - sleep / Sleep: check-in interval
  - skew / Skew: random jitter seconds
  - maxRetry / MaxRetry: reconnect attempts
  - padding / Padding: max padding bytes (traffic shaping)
  - proto / Proto: protocol (h1, h2, h2c, h3, quic, opaque)
  - ja3 / JA3: TLS fingerprint override (evasion)

Detection: characteristic JSON field cluster in Go binary strings section.

References:
  - Ne0nd0g/merlin source (GitHub)
"""

import re
import json
import mwcp
from mwcp.metadata import C2URL, DecodedString, Password

# Merlin wire-protocol field names. These appear in the agent's JSON config
# because they are the serialization keys used by the Merlin server API.
# The server expects exactly these key names in its REST/gRPC interface.
# Do NOT check for "merlin", "ne0nd0g", "Merlin" -- operators strip these.
_MERLIN_PROTO_FIELDS = [
    b'"psk"',       # pre-shared key: required for initial crypto handshake
    b'"PSK"',       # alternative casing in some Merlin versions
    b'"skew"',      # timing randomization: protocol-required config key
    b'"maxRetry"',  # reconnect logic: required by agent state machine
    b'"proto"',     # transport protocol selector: required config key
    b'"padding"',   # traffic shaping: present in all Merlin agent configs
    b'"opaque"',    # OPAQUE protocol variant: unique to Merlin
]

_JSON_RE = re.compile(
    rb'\{[^{}]{20,4000}(?:"(?:psk|PSK|url|URL|skew|maxRetry|proto)")[^{}]{0,4000}\}',
    re.DOTALL
)

_URL_RE  = re.compile(rb'https?://[^\s\x00\'"<>]{8,200}', re.IGNORECASE)
_PSK_RE  = re.compile(rb'"(?:psk|PSK)"\s*:\s*"([^"]{8,128})"')
_PROTO_RE= re.compile(rb'"(?:proto|Proto)"\s*:\s*"([^"]{1,20})"')
_SLEEP_RE= re.compile(rb'"(?:sleep|Sleep)"\s*:\s*(\d{1,9})')
_JA3_RE  = re.compile(rb'"(?:ja3|JA3)"\s*:\s*"([^"]{10,200})"')


class MerlinConfig(mwcp.Parser):
    """Extract Merlin C2 agent configuration from Go binaries."""

    DESCRIPTION = "Merlin C2 Agent Config Extractor"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''
        # Require 2+ protocol-required JSON field names. The Merlin server
        # parses these from the agent config by exact key name -- an operator
        # cannot change them without modifying the server-side parser too.
        hits = sum(1 for f in _MERLIN_PROTO_FIELDS if f in data)
        return hits >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen: set[str] = set()

        # 1. JSON config extraction
        for m in _JSON_RE.finditer(data):
            try:
                obj = json.loads(m.group(0).decode('utf-8', 'ignore'))
                if not isinstance(obj, dict):
                    continue

                # C2 server URL
                url = obj.get('url', obj.get('URL', ''))
                if url and url not in seen:
                    seen.add(url)
                    self.report.add(C2URL(url))

                # PSK (used for initial crypto before full TLS)
                psk = obj.get('psk', obj.get('PSK', ''))
                if psk:
                    self.report.add(Password(psk))
                    self.report.add(DecodedString(f'[Merlin-PSK] {psk[:32]}'))

                # Protocol
                proto = obj.get('proto', obj.get('Proto', ''))
                if proto:
                    self.report.add(DecodedString(f'[Merlin-Proto] {proto}'))

                # Timing
                sleep  = obj.get('sleep', obj.get('Sleep', 0))
                skew   = obj.get('skew', obj.get('Skew', 0))
                if sleep:
                    self.report.add(DecodedString(
                        f'[Merlin-Timing] sleep={sleep}s skew=±{skew}s'
                    ))

                # JA3 TLS fingerprint override (evasion indicator)
                ja3 = obj.get('ja3', obj.get('JA3', ''))
                if ja3:
                    self.report.add(DecodedString(f'[Merlin-JA3] {ja3[:64]}'))

                # Max retry
                maxr = obj.get('maxRetry', obj.get('MaxRetry', 0))
                if maxr:
                    self.report.add(DecodedString(f'[Merlin-MaxRetry] {maxr}'))

            except Exception:
                pass

        # 2. Raw extraction fallback
        for m in _URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').strip()
            if url not in seen:
                seen.add(url)
                self.report.add(C2URL(url))

        for m in _PSK_RE.finditer(data):
            psk = m.group(1).decode('utf-8', 'ignore')
            if psk not in seen:
                seen.add(psk)
                self.report.add(Password(psk))

        for m in _PROTO_RE.finditer(data):
            proto = m.group(1).decode('utf-8', 'ignore')
            self.report.add(DecodedString(f'[Merlin-Proto] {proto}'))

        for m in _JA3_RE.finditer(data):
            ja3 = m.group(1).decode('utf-8', 'ignore')
            self.report.add(DecodedString(f'[Merlin-JA3] {ja3[:64]}'))
