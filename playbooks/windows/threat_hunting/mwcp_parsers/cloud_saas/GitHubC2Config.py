"""
GitHubC2Config -- mwcp parser for GitHub-as-C2: a malware sample using
the GitHub REST API (typically Gists) as a covert C2 channel -- a
documented technique for both config-fetch (raw content) and
result-exfil (creating/updating a private gist).

Two independent mechanisms, both required:
  1. A GitHub Personal Access Token in GitHub's own fixed prefix format:
     `ghp_` (classic PAT) or `github_pat_` (fine-grained PAT) followed
     by the vendor-defined alphanumeric body -- GitHub's own token
     issuance format, not operator-chosen (Rule 3 exception, same class
     as Slack's `xoxb-` prefix).
  2. A GitHub API call target: `api.github.com/gists` (Gist
     create/update/list) or `api.github.com/repos/`.

A PAT-shaped string alone risks a credential-scanner false positive
from an unrelated secrets leak. An `api.github.com` reference alone is
an extremely common, entirely benign integration target (CI, tooling).
Only the token format AND an API-call target together, in the same
file, is the GitHub-as-C2-channel shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, Credential, DecodedString

_GITHUB_PAT_RE = re.compile(rb'(?:ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,255})')
_GITHUB_API_RE = re.compile(
    rb'(?i)https?://api\.github\.com/(gists\b|repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)')


class GitHubC2Config(mwcp.Parser):
    """Detect GitHub-as-C2: personal access token + GitHub API call
    target."""

    DESCRIPTION = "GitHub API C2 Channel Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_GITHUB_PAT_RE.search(data)) and bool(_GITHUB_API_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        pat_m = _GITHUB_PAT_RE.search(data)
        api_m = _GITHUB_API_RE.search(data)
        if not (pat_m and api_m):
            return

        token = pat_m.group(0).decode('utf-8', 'ignore')
        self.report.add(Credential(password=token).add_tag('github_pat'))
        url = api_m.group(0).decode('utf-8', 'ignore')
        self.report.add(C2URL(url))
        self.report.add(DecodedString(
            f'[GitHub-C2] personal access token ({token[:8]}...) + API target ({url}) -- '
            f'GitHub-as-C2-channel shape'))
