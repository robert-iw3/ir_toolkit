"""Ngrok tunnel as a C2 ingress channel (exposing a bind shell/listener on a compromised
host through ngrok's reverse-tunnel infrastructure, bypassing NAT/firewall egress-only
assumptions). Requires the ngrok-issued tunnel domain format (a subdomain under
ngrok.io/ngrok-free.app/ngrok.app -- ngrok's own DNS allocation, not chosen by the
operator) co-occurring with the ngrok agent's own config-file key names (the YAML
schema ngrok's agent binary itself requires to establish the tunnel)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_TUNNEL_DOMAIN_RE = re.compile(
    rb'\b([a-z0-9\-]{4,60}\.(?:ngrok\.io|ngrok-free\.app|ngrok\.app))\b', re.IGNORECASE)
_AGENT_CONFIG_KEYS = (b'authtoken:', b'tunnels:', b'proto: tcp', b'proto: http', b'addr:')


def identify(data: bytes) -> bool:
    return bool(_TUNNEL_DOMAIN_RE.search(data)) and any(k in data for k in _AGENT_CONFIG_KEYS)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    m = _TUNNEL_DOMAIN_RE.search(data)
    return {
        'family': 'SaaS C2: Ngrok Tunnel',
        'tunnel_domain': m.group(1).decode(),
        'note': ('Ngrok-allocated tunnel domain co-occurring with the ngrok agent\'s own '
                 'YAML config schema (authtoken/tunnels/proto/addr) -- both required for the '
                 'agent binary to actually establish the tunnel.'),
    }
