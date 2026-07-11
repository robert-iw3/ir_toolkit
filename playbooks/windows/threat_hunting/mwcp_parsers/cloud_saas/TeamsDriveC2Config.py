"""
TeamsDriveC2Config -- mwcp parser for Microsoft Teams-as-C2: a malware
sample POSTing to a Teams incoming webhook using Teams' own connector
card JSON schema (config pull / result exfil via a Teams channel
instead of a bespoke C2 protocol).

Two independent mechanisms, both required:
  1. A Teams incoming-webhook URL: `*.webhook.office.com/webhookb2/...`
     -- Microsoft's own fixed connector-webhook URL structure, not
     operator-chosen.
  2. A Teams MessageCard/Adaptive Card JSON schema field:
     `"@type":"MessageCard"` / `"@context":"http://schema.org/...`" /
     `"contentType":"application/vnd.microsoft.card.adaptive"` -- the
     exact payload schema Teams' webhook endpoint requires to render a
     posted message, dictated by Microsoft's connector spec.

A webhook URL alone is used by countless legitimate CI/monitoring
integrations (build notifications, alerting). A MessageCard schema
field alone could appear in unrelated JSON. Only a Teams webhook URL
paired with its own required card-schema field in the same file is
the POST-to-Teams-as-C2 shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_TEAMS_WEBHOOK_RE = re.compile(
    rb'(?i)https?://[A-Za-z0-9.-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/_-]{10,300}')
_TEAMS_CARD_SCHEMA_RE = re.compile(
    rb'(?i)"@type"\s*:\s*"MessageCard"|"@context"\s*:\s*"https?://schema\.org/'
    rb'extensions"|application/vnd\.microsoft\.card\.adaptive')


class TeamsDriveC2Config(mwcp.Parser):
    """Detect Microsoft Teams-as-C2: incoming webhook URL + connector card
    JSON schema."""

    DESCRIPTION = "Microsoft Teams Webhook C2 Channel Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_TEAMS_WEBHOOK_RE.search(data)) and bool(_TEAMS_CARD_SCHEMA_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        webhook_m = _TEAMS_WEBHOOK_RE.search(data)
        card_m = _TEAMS_CARD_SCHEMA_RE.search(data)
        if not (webhook_m and card_m):
            return

        url = webhook_m.group(0).decode('utf-8', 'ignore')
        self.report.add(C2URL(url))
        self.report.add(DecodedString(
            f'[Teams-C2] incoming webhook + connector card schema field '
            f'({card_m.group(0)[:60].decode("utf-8","ignore")}) -- '
            f'Teams-as-C2-channel shape'))
