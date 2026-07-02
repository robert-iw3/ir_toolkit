"""
AdaptixC2Config -- mwcp parser for Adaptix C2 agent configuration.

Adaptix is a post-exploitation C2 framework (2023+).  Agents embed their
configuration as a JSON blob.  The JSON structure uses these protocol-required
field names (the Adaptix server refuses registration without them):
    agent_id       -- unique agent GUID / hex string
    callback_url   -- full URL of the Adaptix listener
    profile        -- C2 profile name (http-profile, dns-profile, etc.)
    callback_interval / callback_jitter -- timing fields

Detection: JSON blob containing BOTH agent_id AND callback_url.
These two together are specific to Adaptix -- callback_url alone is too generic,
and agent_id alone is too generic.

References:
    https://github.com/Adaptix-Framework/Adaptix (public framework)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import json
import mwcp
from mwcp.metadata import C2URL, C2Address, Mutex, DecodedString

# Required field presence check (fast pre-filter)
_ADAPTIX_FIELDS = [b'agent_id', b'callback_url', b'profile']
_MIN_FIELD_HITS = 2   # need agent_id + callback_url at minimum

_URL_RE  = re.compile(rb'https?://[^\s\x00\'"<>]{4,200}', re.IGNORECASE)
_AGENT_RE = re.compile(
    rb'"agent_id"\s*:\s*"([A-Za-z0-9_\-]{4,64})"',
    re.IGNORECASE
)
_CB_URL_RE = re.compile(
    rb'"callback_url"\s*:\s*"(https?://[^\s"]{4,200})"',
    re.IGNORECASE
)
_PROFILE_RE = re.compile(
    rb'"profile"\s*:\s*"([^"]{1,64})"',
    re.IGNORECASE
)
_INTERVAL_RE = re.compile(
    rb'"callback_interval"\s*:\s*(\d+)',
    re.IGNORECASE
)
_JITTER_RE = re.compile(
    rb'"callback_jitter"\s*:\s*(\d+)',
    re.IGNORECASE
)


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _field_hits(data: bytes) -> int:
    return sum(1 for f in _ADAPTIX_FIELDS if f in data)


class AdaptixC2Config(mwcp.Parser):
    """Extract Adaptix C2 agent configuration from PE or memory regions."""

    DESCRIPTION = "Adaptix C2 Agent Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        # Require agent_id + callback_url to be present (both protocol-required)
        return b'agent_id' in data and b'callback_url' in data

    def run(self):
        data = self.file_object.data
        if not data:
            return

        if _field_hits(data) < _MIN_FIELD_HITS:
            return

        seen = set()

        agent_id = None
        for m in _AGENT_RE.finditer(data):
            agent_id = _clean(m.group(1))
            if agent_id and agent_id not in seen:
                seen.add(agent_id)
                self.report.add(Mutex(agent_id))   # unique per-agent pivot
                break

        for m in _CB_URL_RE.finditer(data):
            url = _clean(m.group(1))
            if url and url not in seen:
                seen.add(url)
                self.report.add(C2URL(url))

        profile = None
        for m in _PROFILE_RE.finditer(data):
            profile = _clean(m.group(1))
            break

        interval, jitter = None, None
        for m in _INTERVAL_RE.finditer(data):
            interval = _clean(m.group(1))
            break
        for m in _JITTER_RE.finditer(data):
            jitter = _clean(m.group(1))
            break

        parts = ['[Adaptix-Config]']
        if agent_id:
            parts.append(f'agent_id={agent_id}')
        if profile:
            parts.append(f'profile={profile}')
        if interval:
            parts.append(f'interval={interval}s')
        if jitter:
            parts.append(f'jitter={jitter}%')

        if len(parts) > 1:
            self.report.add(DecodedString(' '.join(parts)))
