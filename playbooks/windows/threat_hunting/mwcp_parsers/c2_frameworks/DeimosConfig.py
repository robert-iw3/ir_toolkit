"""
DeimosConfig -- mwcp parser for Deimos C2 agent configuration.

Deimos (github.com/DeimosC2/DeimosC2) is an open-source Go-based C2
framework. Agents register with the team server over HTTP(S)/DNS and store
their profile as either Go struct-tagged JSON or adjacent null-separated
strings in the compiled binary. The following field/struct names are part
of the agent<->server registration schema -- the server rejects a check-in
whose JSON is missing them, so an operator cannot rename them without
breaking their own C2:
    CallbackURL   -- team server check-in URL
    Interval      -- beacon sleep interval (seconds)
    PubKey        -- agent's RSA/EC public key (auth handshake)
    AgentID       -- per-implant identifier (pivot indicator)
    UserAgent     -- HTTP client UA string profile

Detection does not rely on the string "Deimos" -- Go binaries commonly
strip the module path, but the JSON field names above are structurally
required by the agent's own (un-stripped) serialization tags.

References:
  - DeimosC2 project source (github.com/DeimosC2/DeimosC2)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import json
import mwcp
from mwcp.metadata import C2URL, C2Address, Mutex, DecodedString

_PROTO_FIELDS = [
    b'"CallbackURL"', b'"Interval"', b'"PubKey"', b'"AgentID"', b'"UserAgent"',
]
_MIN_FIELD_HITS = 2

_JSON_RE = re.compile(
    rb'\{[^{}]{20,4000}(?:CallbackURL|AgentID|PubKey)[^{}]{0,4000}\}', re.DOTALL)

_CALLBACK_RE = re.compile(rb'CallbackURL"?\s*[:=]\s*"([a-zA-Z0-9:/_\.\-]{6,200})"')
_AGENTID_RE  = re.compile(rb'AgentID"?\s*[:=]\s*"([A-Za-z0-9\-]{4,64})"')
_INTERVAL_RE = re.compile(rb'Interval"?\s*[:=]\s*(\d{1,6})')


class DeimosConfig(mwcp.Parser):
    """Extract Deimos C2 agent configuration from a Go binary or carved region."""

    DESCRIPTION = "Deimos C2 Agent Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        hits = sum(1 for f in _PROTO_FIELDS if f in data)
        return hits >= _MIN_FIELD_HITS

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen: set[str] = set()
        parsed = {}

        for m in _JSON_RE.finditer(data):
            try:
                obj = json.loads(m.group(0).decode('utf-8', 'ignore'))
                if isinstance(obj, dict) and any(
                        k in obj for k in ('CallbackURL', 'AgentID', 'PubKey')):
                    parsed.update(obj)
            except Exception:
                pass

        callback = parsed.get('CallbackURL', '')
        if not callback:
            m = _CALLBACK_RE.search(data)
            if m:
                callback = m.group(1).decode('utf-8', 'ignore')
        if callback and callback not in seen:
            seen.add(callback)
            self.report.add(C2URL(callback) if '://' in callback else C2Address(callback))

        agent_id = parsed.get('AgentID', '')
        if not agent_id:
            m = _AGENTID_RE.search(data)
            if m:
                agent_id = m.group(1).decode('utf-8', 'ignore')
        if agent_id:
            self.report.add(Mutex(agent_id))

        interval = parsed.get('Interval', 0)
        if not interval:
            m = _INTERVAL_RE.search(data)
            if m:
                interval = int(m.group(1))
        if interval:
            self.report.add(DecodedString(f'[Deimos-Interval] {interval}s'))

        pubkey = parsed.get('PubKey', '')
        if pubkey:
            self.report.add(DecodedString(f'[Deimos-PubKey] {str(pubkey)[:64]}'))

        if callback or agent_id:
            self.report.add(DecodedString(
                f'[Deimos-Config] callback={callback} agent_id={agent_id}'))
