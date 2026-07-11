"""
SlackC2Config -- mwcp parser for Slack-as-C2: a malware sample using
Slack's own Bot/OAuth API as a covert command channel (config pull /
result exfil via a Slack channel instead of a bespoke C2 protocol).

Two independent mechanisms, both required:
  1. A Slack token in Slack's own fixed prefix format: `xoxb-` (bot),
     `xoxp-` (user), or `xoxa-` (app) followed by the vendor-defined
     digit-dash-alphanumeric structure -- Slack's own token issuance
     format, not operator-chosen (Rule 3 exception, same class as
     Telegram's bot-token format in TelegramC2Config.py).
  2. A Slack API call target: `slack.com/api/` (chat.postMessage /
     conversations.history / files.upload, etc.) or a
     `hooks.slack.com/services/` incoming-webhook URL.

A bare token match alone risks matching a credential dump or secrets
scanner false positive. A `slack.com` reference alone is an extremely
common, entirely benign integration target. Only the token format AND
an API-call target together, in the same file, is the C2-channel shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, Credential, DecodedString

_SLACK_TOKEN_RE = re.compile(rb'xox[bpa]-[0-9A-Za-z-]{10,72}')
_SLACK_API_RE = re.compile(
    rb'(?i)(https?://)?(hooks\.slack\.com/services/[A-Za-z0-9/]+|'
    rb'slack\.com/api/[A-Za-z.]+)')


class SlackC2Config(mwcp.Parser):
    """Detect Slack-as-C2: bot/OAuth token + Slack API call target."""

    DESCRIPTION = "Slack API C2 Channel Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_SLACK_TOKEN_RE.search(data)) and bool(_SLACK_API_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        token_m = _SLACK_TOKEN_RE.search(data)
        api_m = _SLACK_API_RE.search(data)
        if not (token_m and api_m):
            return

        token = token_m.group(0).decode('utf-8', 'ignore')
        self.report.add(Credential(password=token).add_tag('slack_token'))
        api_target = api_m.group(0).decode('utf-8', 'ignore')
        url = api_target if api_target.startswith('http') else f'https://{api_target}'
        self.report.add(C2URL(url))
        self.report.add(DecodedString(
            f'[Slack-C2] token ({token[:9]}...) + API target ({api_target}) -- '
            f'Slack-as-C2-channel shape'))
