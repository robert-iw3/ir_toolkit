"""
MythicConfig -- mwcp parser for Mythic C2 agent configurations.

Mythic is a modular C2 framework. Agents (Poseidon, Apollo, Athena, Thanatos,
Medusa, etc.) embed their config as JSON. The JSON structure varies by agent
but all share common fields from the Mythic C2 profile spec:
  - uuid / agent_uuid / PayloadUUID
  - callback_interval / sleep_interval / callback_jitter
  - c2_profiles[] with server + port
  - crypto_type / AES_PSK / encryption_key

Detection: JSON blob with multiple Mythic-specific field names.

References:
  - MythicMeta/Mythic source (GitHub)
  - Per-agent C2 profiles (each has documented JSON structure)
"""

import re
import json
import mwcp
from mwcp.metadata import C2URL, C2Address, Mutex, DecodedString, Password

# Mythic C2 profile field names: these are REQUIRED by the C2 profile
# specification in the Mythic framework. Every compliant agent MUST use
# these exact names for the Mythic server to parse the callback.
# An operator cannot rename them without forking the entire Mythic server.
# Do NOT check for "Mythic" or "MythicMeta" -- those are stripped.
_MYTHIC_REQUIRED_FIELDS = [
    b'PayloadUUID',          # every agent registers with this exact field name
    b'callback_interval',    # required by Mythic C2 profile JSON spec
    b'c2_profiles',          # required JSON key for C2 profile list
    b'encrypted_exchange_check',  # key exchange field in Mythic's crypto spec
    b'AES_PSK',              # pre-shared key field in the standard C2 profile
    b'tasking_type',         # Mythic task dispatch field (server-required)
]

_JSON_RE = re.compile(
    rb'\{[^{}]{30,8000}(?:PayloadUUID|callback_interval|c2_profiles|agent_uuid|AES_PSK)[^{}]{0,8000}\}',
    re.DOTALL | re.IGNORECASE
)

_UUID_RE  = re.compile(
    rb'(?:PayloadUUID|agent_uuid|uuid)\s*[":=]\s*["\']?([0-9a-fA-F\-]{32,36})',
    re.IGNORECASE
)
_URL_RE   = re.compile(rb'https?://[^\s\x00\'"<>]{8,200}', re.IGNORECASE)
_KEY_RE   = re.compile(
    rb'(?:AES_PSK|encryption_key|crypto_key)\s*[":=]\s*["\']?([A-Za-z0-9+/=]{20,64})',
    re.IGNORECASE
)


class MythicConfig(mwcp.Parser):
    """Extract Mythic C2 agent configuration from PE and carved regions."""

    DESCRIPTION = "Mythic C2 Agent Config Extractor"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''
        # Require 2+ required C2 profile field names. These come from the
        # Mythic server-client protocol specification, not from debugging info.
        hits = sum(1 for f in _MYTHIC_REQUIRED_FIELDS if f in data)
        return hits >= 2

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen: set[str] = set()

        # 1. Structured JSON extraction
        for m in _JSON_RE.finditer(data):
            try:
                obj = json.loads(m.group(0).decode('utf-8', 'ignore'))
                if not isinstance(obj, dict):
                    continue

                # UUID (unique per payload -- pivot indicator)
                for k in ('PayloadUUID', 'agent_uuid', 'uuid', 'UNIQUE_ID'):
                    if k in obj and obj[k]:
                        uid = str(obj[k])
                        self.report.add(Mutex(uid))   # unique, pivot-worthy
                        self.report.add(DecodedString(f'[Mythic-UUID] {uid}'))
                        break

                # C2 profiles
                profiles = obj.get('c2_profiles', obj.get('C2Profiles', []))
                if isinstance(profiles, list):
                    for profile in profiles:
                        if isinstance(profile, dict):
                            params = profile.get('parameters', profile)
                            host = params.get('callback_host', params.get('host', ''))
                            port = params.get('callback_port', params.get('port', 0))
                            if host:
                                addr = f'{host}:{port}' if port else host
                                if addr not in seen:
                                    seen.add(addr)
                                    if host.startswith('http'):
                                        self.report.add(C2URL(host))
                                    else:
                                        self.report.add(C2Address(addr))

                # Intervals
                interval = obj.get('callback_interval', obj.get('sleep_interval', 0))
                jitter   = obj.get('callback_jitter', obj.get('sleep_jitter', 0))
                if interval:
                    self.report.add(DecodedString(
                        f'[Mythic-Timing] interval={interval}s jitter={jitter}%'
                    ))

                # AES PSK (team-server specific -- pivot indicator)
                psk = obj.get('AES_PSK', obj.get('encryption_key', ''))
                if psk:
                    self.report.add(Password(str(psk)))
                    self.report.add(DecodedString(f'[Mythic-AES_PSK] {str(psk)[:32]}'))

            except Exception:
                pass

        # 2. UUID extraction from raw binary (catches minified/non-JSON embedded configs)
        for m in _UUID_RE.finditer(data):
            uid = m.group(1).decode('utf-8', 'ignore').strip()
            if uid not in seen:
                seen.add(uid)
                self.report.add(Mutex(uid))
                self.report.add(DecodedString(f'[Mythic-UUID] {uid}'))

        # 3. URL fallback
        for m in _URL_RE.finditer(data):
            url = m.group(0).decode('utf-8', 'ignore').strip()
            if url not in seen:
                seen.add(url)
                self.report.add(C2URL(url))

        # 4. AES key fallback
        for m in _KEY_RE.finditer(data):
            key = m.group(1).decode('utf-8', 'ignore').strip()
            if len(key) >= 20 and key not in seen:
                seen.add(key)
                self.report.add(Password(key))
