"""Recovery-inhibition command detection -- the Linux/Unix analog of Windows'
vssadmin/VSS-disable ransomware precursor (T1490, Inhibit System Recovery).

Before or during encryption, Linux ransomware needs to destroy the LOCAL backup/
snapshot mechanisms an admin could otherwise restore from -- LVM snapshots, Btrfs
subvolume snapshots, and ZFS snapshots are the three mechanisms an unencrypted rollback
could come from on a Linux server. A single `lvremove`/`btrfs subvolume delete`/
`zfs destroy` reference, even with a `-f`/`-y` non-interactive flag, is routine in
scripted backup-rotation/cron housekeeping (nobody wants an interactive prompt hanging
in an unattended job) and is not a signal on its own. What distinguishes a destroyer
from routine housekeeping is either: (a) co-occurrence with an encryption-shaped
signal (an embedded crypto pubkey, or explicit backup-service shutdown), or (b)
referencing 2+ DIFFERENT snapshot technologies together -- a real server is built on
one storage stack, so a script referencing LVM AND Btrfs AND ZFS destroy commands
together is written to work regardless of which one the victim actually has, not
maintenance for a specific known environment."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_SNAPSHOT_DESTROY_CMDS = (
    b'lvremove', b'btrfs subvolume delete', b'zfs destroy',
)
_PUBKEY_RE = re.compile(rb'-----BEGIN (?:RSA )?PUBLIC KEY-----')
_CRON_BACKUP_KILL = (b'crontab -r', b'systemctl stop cron', b'systemctl disable cron')


def _signals(data: bytes) -> Dict[str, Any]:
    destroy_hits = [c for c in _SNAPSHOT_DESTROY_CMDS if c in data]
    has_pubkey = bool(_PUBKEY_RE.search(data))
    backup_service_kill = any(c in data for c in _CRON_BACKUP_KILL)
    return {'destroy_hits': destroy_hits, 'pubkey': has_pubkey,
            'backup_service_kill': backup_service_kill}


def identify(data: bytes) -> bool:
    s = _signals(data)
    if not s['destroy_hits']:
        return False
    multi_technology = len(s['destroy_hits']) >= 2
    return multi_technology or s['pubkey'] or s['backup_service_kill']


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    s = _signals(data)
    return {
        'family': 'Ransomware: Local Snapshot/Backup Destruction',
        'destroy_commands': [c.decode() for c in s['destroy_hits']],
        'multi_technology': len(s['destroy_hits']) >= 2,
        'crypto_pubkey_present': s['pubkey'],
        'backup_service_disabled': s['backup_service_kill'],
        'note': ('LVM/Btrfs/ZFS snapshot-destroy command(s) co-occurring with a crypto pubkey '
                 'block, backup-service shutdown, or 2+ different snapshot technologies '
                 'referenced together (a real server uses one storage stack; targeting all of '
                 'them is written for an unknown victim environment) -- the Linux analog of '
                 'Windows vssadmin/VSS-disable recovery inhibition (T1490). A single destroy '
                 'command with just a non-interactive flag, as in routine backup-rotation '
                 'scripts, does not meet this gate.'),
    }
