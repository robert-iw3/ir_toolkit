"""Known-benign Linux structural facts for the noise filter.

Everything here is a *default expectation*, not an allowlist that suppresses
detection: a known daemon name running from the wrong path is MORE suspicious,
not less (masquerade), and the noise filter uses these sets in both directions.
"""
from __future__ import annotations

# Core system daemons whose presence in a finding set is expected background
# on virtually every distro. Names are comm values (15-char kernel limit applies).
KNOWN_SYSTEM_PROCESSES = frozenset({
    'systemd', 'init', 'systemd-journal', 'systemd-udevd', 'systemd-resolve',
    'systemd-logind', 'systemd-network', 'systemd-timesyn', 'systemd-oomd',
    'dbus-daemon', 'dbus-broker', 'NetworkManager', 'wpa_supplicant',
    'sshd', 'cron', 'crond', 'anacron', 'atd', 'rsyslogd', 'auditd',
    'chronyd', 'ntpd', 'polkitd', 'udisksd', 'accounts-daemon',
    'ModemManager', 'avahi-daemon', 'cupsd', 'cups-browsed',
    'snapd', 'packagekitd', 'unattended-upgr', 'fwupd',
    'containerd', 'dockerd', 'containerd-shim', 'kubelet', 'crio',
    'agetty', 'login', 'irqbalance', 'thermald', 'upowerd',
    'gdm3', 'gdm-session-wor', 'gnome-shell', 'gnome-session-b', 'Xorg',
    'Xwayland', 'pipewire', 'wireplumber', 'pulseaudio',
    'nginx', 'apache2', 'httpd', 'postgres', 'mariadbd', 'mysqld',
    'redis-server', 'memcached', 'php-fpm', 'haproxy',
    # Desktop/hardware daemons commonly hardened with systemd's own
    # PrivateMounts=/ProtectSystem= sandboxing (own mount ns, shares host PID
    # ns by design) -- a common source of "Namespace Escape (memory)" findings
    # ('kdevtmpfs' is a legitimate kernel worker; not to be confused with the
    # Kinsing-class malware masquerade name 'kdevtmpfsi' with a trailing i).
    'kdevtmpfs', 'bluetoothd', 'switcheroo-cont', 'virtlogd', 'boltd',
    'firewalld', 'colord', 'user-session-he', 'snapd-desktop-i', 'rtkit-daemon',
})

# Canonical executable paths for a subset of daemons where a path mismatch is a
# reliable masquerade red flag. Keys are comm values; values are accepted
# path prefixes (symlinked /bin -> /usr/bin means both forms appear in the wild).
EXPECTED_PATH_PREFIXES = {
    'systemd':        ('/usr/lib/systemd/systemd', '/lib/systemd/systemd', '/sbin/init', '/usr/sbin/init'),
    'systemd-journal': ('/usr/lib/systemd/systemd-journald', '/lib/systemd/systemd-journald'),
    'systemd-udevd':  ('/usr/lib/systemd/systemd-udevd', '/lib/systemd/systemd-udevd',
                       '/usr/bin/udevadm', '/bin/udevadm'),
    'sshd':           ('/usr/sbin/sshd', '/usr/bin/sshd', '/sbin/sshd'),
    'cron':           ('/usr/sbin/cron', '/usr/bin/cron'),
    'crond':          ('/usr/sbin/crond', '/usr/bin/crond'),
    'dbus-daemon':    ('/usr/bin/dbus-daemon', '/bin/dbus-daemon'),
    'NetworkManager': ('/usr/sbin/NetworkManager', '/usr/bin/NetworkManager'),
    'rsyslogd':       ('/usr/sbin/rsyslogd', '/usr/bin/rsyslogd'),
    'auditd':         ('/usr/sbin/auditd', '/sbin/auditd'),
    'nginx':          ('/usr/sbin/nginx', '/usr/bin/nginx', '/usr/local/nginx'),
    'apache2':        ('/usr/sbin/apache2',),
    'httpd':          ('/usr/sbin/httpd',),
    'postgres':       ('/usr/lib/postgresql/', '/usr/pgsql', '/usr/bin/postgres', '/usr/local/pgsql'),
    'dockerd':        ('/usr/bin/dockerd', '/usr/local/bin/dockerd'),
    'containerd':     ('/usr/bin/containerd', '/usr/local/bin/containerd'),
}

# Runtimes that legitimately create anonymous executable memory (JIT). A
# malfind-style hit whose owning process is one of these is expected behavior
# unless corroborated by an independent mechanism (YARA in the region, deleted
# binary, untrusted network).
JIT_RUNTIMES = frozenset({
    'java', 'node', 'nodejs', 'deno', 'bun', 'mono', 'dotnet',
    'qemu-system-x86', 'qemu-kvm', 'wine', 'wine64', 'wineserver',
    'firefox', 'firefox-bin', 'chrome', 'chromium', 'chromium-browse',
    'brave', 'msedge', 'electron', 'code', 'slack', 'discord', 'spotify',
    'gjs', 'gnome-shell', 'polkitd', 'luajit', 'julia',
    # Interpreters with ffi/ctypes JIT paths; dual-use, so they suppress the
    # standalone anon-exec dimension but never a corroborated one.
    'python', 'python3', 'ruby', 'perl', 'php',
})

# Observability / security agents that legitimately load kprobe/tracepoint eBPF
# programs and hold bpf fds. An eBPF finding whose loader is one of these is
# expected; one whose loader is unknown is not.
OBSERVABILITY_AGENTS = frozenset({
    'falco', 'cilium-agent', 'cilium', 'datadog-agent', 'system-probe',
    'bpftrace', 'tetragon', 'tracee', 'sysdig', 'osqueryd', 'ebpf_exporter',
    'beyla', 'parca-agent', 'pixie', 'inspektor-gadget', 'aya-tool',
})

# Services with documented legitimate io_uring use -- 'io_uring In Use (verify)'
# on one of these (real binary at its packaged path) is the canonical FP.
IO_URING_EXPECTED = frozenset({
    'nginx', 'postgres', 'mariadbd', 'mysqld', 'redis-server', 'valkey-server',
    'systemd', 'containerd', 'dockerd', 'qemu-system-x86', 'qemu-kvm',
    'ceph-osd', 'glusterfsd', 'rocksdb', 'scylla', 'mongod', 'envoy',
})

# Forced-command values in authorized_keys that are standard tooling, not backdoors.
BENIGN_FORCED_COMMANDS = ('rsync', 'borg', 'restic', 'git-shell', 'git-receive-pack',
                          'git-upload-pack', 'scp', 'sftp', 'internal-sftp',
                          'zfs receive', 'mosh-server')

# Paths an implant typically stages in (world-writable / volatile). Mirrors
# edr_hunt.py's IMPLANT_DIRS plus user-writable staging.
IMPLANT_PATH_PREFIXES = ('/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/', '/home/')

# Distro-managed locations: a binary here is *presumptively* packaged (the
# adjudicator verifies actual ownership; this is the structural prior).
TRUSTED_PATH_PREFIXES = ('/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/lib/',
                         '/lib/', '/lib64/', '/usr/lib64/', '/usr/libexec/',
                         '/opt/', '/snap/', '/usr/local/bin/', '/usr/local/sbin/')
