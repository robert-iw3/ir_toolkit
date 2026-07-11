"""
CryptoMinerConfig -- mwcp parser for cryptocurrency miner pool configs
(XMRig and Stratum-protocol-compatible miners embedded as a loader
payload or dropped by a post-compromise cryptojacking stage).

Two independent mechanisms, both required:
  1. A `stratum+tcp://` or `stratum+ssl://` pool URL -- the Stratum
     mining protocol's own fixed URI scheme, not operator-chosen; no
     other application legitimately uses this scheme.
  2. Either of two independently-sufficient corroborating mechanisms
     that the URL is actually being USED to mine, not just referenced:
       a. A Stratum JSON-RPC method name sent over the wire:
          `mining.subscribe` or `mining.authorize` -- the exact RPC
          method names the protocol spec requires for a client to
          register and authenticate.
       b. XMRig-family CLI invocation flags immediately following the
          URL: `-u <wallet> -p <password>` / `--user`/`--pass` -- the
          exact short/long flag names XMRig's own argument parser
          requires to receive the wallet and worker password (observed
          verbatim in a confirmed KIMBAP coinminer command line:
          `stratum+tcp://xcnpool.1gh.com:7333 -u <wallet> -p x`).

A `stratum://` URL alone could appear in pool documentation, a
monitoring dashboard, or a config template shipped with legitimate
mining software the user intentionally installed. Only the URL paired
with either the wire-protocol RPC call or the miner's own CLI
argument syntax, in the same file, is the active-miner-config shape.

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2URL, DecodedString

_STRATUM_URL_RE = re.compile(rb'(?i)stratum\+(?:tcp|ssl)://[^\s"\'<>\x00]{4,200}')
_STRATUM_RPC_RE = re.compile(rb'"?mining\.(subscribe|authorize)"?')
_XMRIG_CLI_RE = re.compile(
    rb'(?i)(?:-u|--user)[= ]\S{4,120}[ \x00]{1,4}(?:-p|--pass)[= ]\S{1,120}')
_WALLET_RE = re.compile(rb'\b4[0-9AB][0-9A-Za-z]{93}\b')  # Monero base58 address shape


class CryptoMinerConfig(mwcp.Parser):
    """Detect a cryptocurrency miner config: Stratum pool URL + (Stratum
    RPC method OR XMRig-family CLI wallet/pass flags)."""

    DESCRIPTION = "Cryptocurrency Miner (Stratum) Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 24 or not _STRATUM_URL_RE.search(data):
            return False
        return bool(_STRATUM_RPC_RE.search(data)) or bool(_XMRIG_CLI_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        url_m = _STRATUM_URL_RE.search(data)
        if not url_m:
            return
        rpc_m = _STRATUM_RPC_RE.search(data)
        cli_m = _XMRIG_CLI_RE.search(data)
        if not (rpc_m or cli_m):
            return

        url = url_m.group(0).decode('utf-8', 'ignore')
        self.report.add(C2URL(url))
        wallet_m = _WALLET_RE.search(data)
        wallet_note = f'; wallet {wallet_m.group(0).decode("utf-8","ignore")}' if wallet_m else ''
        signal = (f'RPC method ({rpc_m.group(0).decode("utf-8","ignore")})' if rpc_m
                  else f'CLI flags ({cli_m.group(0).decode("utf-8","ignore")[:60]})')
        self.report.add(DecodedString(
            f'[CryptoMiner] Stratum pool URL ({url}) + {signal}{wallet_note} -- '
            f'active miner config shape'))
