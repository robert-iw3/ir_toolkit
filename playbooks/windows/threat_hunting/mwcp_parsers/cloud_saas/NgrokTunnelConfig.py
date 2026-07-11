"""
NgrokTunnelConfig -- mwcp parser for ngrok-as-C2: a malware sample using
an ngrok tunnel to expose a local listener (reverse shell, RDP, C2
server) to the internet without port-forwarding/firewall changes.

Two independent mechanisms, both required:
  1. An ngrok tunnel domain: `ngrok.io` / `ngrok-free.app` /
     `ngrok-free.dev` -- ngrok's own fixed tunnel-endpoint domain suffix,
     not operator-chosen.
  2. ngrok's own config-file schema field: `proto: tcp`/`proto: http`
     (YAML) or `"proto":"tcp"` (JSON) paired with an `addr:`/`"addr":`
     local-forward target -- the exact key names ngrok's own agent
     config format requires to define a tunnel, dictated by ngrok, not
     the operator.

An ngrok domain reference alone is used constantly by legitimate
developers (webhook testing, demos, temporary sharing) -- ngrok is a
mainstream, widely-adopted developer tool. Only the domain paired with
ngrok's own tunnel-definition config schema, in the same file, is the
persistent-tunnel-config shape (as opposed to, e.g., a URL pasted in
documentation or a browser history entry).

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_NGROK_DOMAIN_RE = re.compile(rb'[A-Za-z0-9.-]*\.ngrok(?:-free)?\.(?:io|app|dev)\b')
_NGROK_CONFIG_RE = re.compile(
    rb'proto["\']?\s*[:=]\s*["\']?(?:tcp|http|tls)["\']?[^\x00]{0,200}addr["\']?\s*[:=]')


class NgrokTunnelConfig(mwcp.Parser):
    """Detect ngrok-as-C2: tunnel domain + ngrok agent config schema
    fields."""

    DESCRIPTION = "Ngrok Tunnel C2 Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24:
            return False
        return bool(_NGROK_DOMAIN_RE.search(data)) and bool(_NGROK_CONFIG_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        domain_m = _NGROK_DOMAIN_RE.search(data)
        config_m = _NGROK_CONFIG_RE.search(data)
        if not (domain_m and config_m):
            return

        domain = domain_m.group(0).decode('utf-8', 'ignore')
        self.report.add(C2URL(f'https://{domain}'))
        self.report.add(DecodedString(
            f'[Ngrok-C2] tunnel domain ({domain}) + ngrok agent config schema (proto/addr) -- '
            f'persistent-tunnel-config shape'))
