"""ESXi encryptor detection -- the cross-family mechanism, not a brand fingerprint.

Since the 2021 Babuk ESXi locker source leak, the large majority of Linux/ESXi
ransomware lockers (independently documented across LockBit, BlackCat/ALPHV, Conti,
Akira, BlackBasta, RansomEXX, Cheerscrypt, Hive, BlackMatter ESXi variants -- SentinelOne,
Trend Micro, and CrowdStrike write-ups on each separately) share the SAME operational
mechanism, because a running VM holds its own .vmdk file open and encrypting it in
place while ESXi still has it locked corrupts the datastore rather than encrypting it
usefully. The locker MUST, before encrypting:
  1. Enumerate running VMs via `esxcli vm process list` (or `vim-cmd vmsvc/getallvms`).
  2. Force-kill each one via `esxcli vm process kill -t force -w <WID>` to release the
     file lock on its .vmdk/.vmx.
  3. Target ESXi's own datastore file-extension set (.vmdk/.vmx/.vmsn/.vswp/.vmss/
     .nvram/.vmem/.log) -- structurally different from a generic document/database
     extension list, since these are VMware-internal formats no generic ransomware
     has any reason to enumerate.

This is a genuine operational requirement of attacking a live ESXi host, not an
artifact any one operator could rename away -- which is exactly why it recurs
identically across otherwise-unrelated ransomware codebases. Never checks for a
specific ransomware brand name."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_KILL_PAIR = (b'esxcli vm process list', b'esxcli vm process kill')
_SNAPSHOT_REMOVE = (b'vim-cmd vmsvc/snapshot.removeall', b'vim-cmd vmsvc/power.off')
_ESXI_EXTENSIONS = (b'.vmdk', b'.vmx', b'.vmsn', b'.vswp', b'.vmss', b'.nvram', b'.vmem')
_KILL_WID_RE = re.compile(rb'esxcli\s+vm\s+process\s+kill\s+-t\s+(?:force|soft|hard)\s+-w\s+\d+')


def _signals(data: bytes) -> Dict[str, bool]:
    kill_pair = all(s in data for s in _KILL_PAIR) or bool(_KILL_WID_RE.search(data))
    snapshot = any(s in data for s in _SNAPSHOT_REMOVE)
    ext_hits = [e for e in _ESXI_EXTENSIONS if e in data]
    ext_cluster = len(ext_hits) >= 4
    return {'kill_pair': kill_pair, 'snapshot_removal': snapshot, 'ext_cluster': ext_cluster,
            'ext_hits': ext_hits}


def identify(data: bytes) -> bool:
    s = _signals(data)
    return sum(bool(v) for k, v in s.items() if k != 'ext_hits') >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    s = _signals(data)
    return {
        'family': 'Ransomware: ESXi Encryptor (Babuk-lineage mechanism)',
        'vm_kill_sequence': s['kill_pair'],
        'snapshot_removal_command': s['snapshot_removal'],
        'esxi_extensions_targeted': sorted(e.decode() for e in s['ext_hits']),
        'note': ('Detected via the operational MECHANISM every ESXi locker needs (enumerate + '
                 'force-kill running VMs to release the .vmdk file lock before encrypting, '
                 'targeting VMware-internal file extensions), not a brand name or CLI-flag '
                 'guess -- this pattern recurs across LockBit/BlackCat/Conti/Akira/BlackBasta/'
                 'RansomEXX ESXi variants because they share Babuk-leaked lineage, not because '
                 'this check identifies any one of them specifically.'),
    }
