"""Known-benign Windows system process baselines.

These are used by the ML noise filter and structural rules to identify
background noise with certainty -- system processes doing expected things
that cannot simultaneously be malicious.
"""
from __future__ import annotations
from typing import Dict, FrozenSet, Set, Tuple

# Lowercase process names that are Windows OS infrastructure
KNOWN_SYSTEM_PROCESSES: FrozenSet[str] = frozenset({
    # Core OS
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'dwm.exe',
    # Task / job infrastructure
    'taskhostw.exe', 'taskhost.exe',
    # COM / WMI
    'wmiprvse.exe', 'dllhost.exe', 'msdtc.exe',
    # Security
    'msmpeng.exe', 'mssense.exe', 'securityhealthservice.exe', 'nissrv.exe',
    # Update / installer
    'tiworker.exe', 'wuauclt.exe', 'usoclient.exe',
    # Peripherals
    'fontdrvhost.exe', 'audiodg.exe', 'spoolsv.exe',
    # Indexing
    'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
    # User shell
    'explorer.exe', 'sihost.exe', 'runtimebroker.exe', 'ctfmon.exe',
    'shellexperiencehost.exe', 'startmenuexperiencehost.exe',
    # Common utilities
    'taskmgr.exe', 'notepad.exe',
    # .NET / CLR
    'mscorsvw.exe', 'ngen.exe',
})

# Processes whose parent legitimately exits before a memory snapshot is taken.
# Orphaned children of these parents are expected, not suspicious.
KNOWN_EXIT_EARLY_PARENTS: FrozenSet[str] = frozenset({
    'smss.exe',       # exits after session init (csrss, wininit)
    'userinit.exe',   # exits after launching explorer.exe
    'setup.exe',      # installers spawn children then exit
    'msiexec.exe',    # MSI sub-process launchers
    'wusa.exe',       # Windows Update standalone installer
})

# Expected (parent_lower, child_lower) spawning tuples.
BENIGN_PARENT_CHILD: FrozenSet[Tuple[str, str]] = frozenset({
    ('smss.exe',       'csrss.exe'),
    ('smss.exe',       'winlogon.exe'),
    ('smss.exe',       'wininit.exe'),
    ('wininit.exe',    'services.exe'),
    ('wininit.exe',    'lsass.exe'),
    ('services.exe',   'svchost.exe'),
    ('services.exe',   'spoolsv.exe'),
    ('services.exe',   'msdtc.exe'),
    ('services.exe',   'wmiprvse.exe'),
    ('services.exe',   'tiworker.exe'),
    ('services.exe',   'msmpeng.exe'),
    ('services.exe',   'nissrv.exe'),
    ('svchost.exe',    'dllhost.exe'),
    ('svchost.exe',    'taskhostw.exe'),
    ('svchost.exe',    'wmiprvse.exe'),
    ('svchost.exe',    'searchindexer.exe'),
    ('svchost.exe',    'audiodg.exe'),
    ('svchost.exe',    'runtimebroker.exe'),
    ('svchost.exe',    'tiworker.exe'),
    ('svchost.exe',    'usoclient.exe'),
    ('winlogon.exe',   'dwm.exe'),
    ('winlogon.exe',   'fontdrvhost.exe'),
    ('winlogon.exe',   'userinit.exe'),
    ('explorer.exe',   'runtimebroker.exe'),
    ('explorer.exe',   'sihost.exe'),
    ('explorer.exe',   'shellexperiencehost.exe'),
    ('explorer.exe',   'notepad.exe'),
    ('explorer.exe',   'taskmgr.exe'),
    ('explorer.exe',   'ctfmon.exe'),
    ('lsass.exe',      'lsaiso.exe'),
    ('searchindexer.exe', 'searchprotocolhost.exe'),
    ('searchindexer.exe', 'searchfilterhost.exe'),
})

# Expected disk paths for each process name (lowercase).
# A mismatch (e.g. svchost.exe from AppData) is a strong TP signal.
EXPECTED_PATHS: Dict[str, FrozenSet[str]] = {
    'svchost.exe':      frozenset({'c:\\windows\\system32\\svchost.exe',
                                   'c:\\windows\\syswow64\\svchost.exe'}),
    'taskhostw.exe':    frozenset({'c:\\windows\\system32\\taskhostw.exe'}),
    'wmiprvse.exe':     frozenset({'c:\\windows\\system32\\wbem\\wmiprvse.exe'}),
    'lsass.exe':        frozenset({'c:\\windows\\system32\\lsass.exe'}),
    'csrss.exe':        frozenset({'c:\\windows\\system32\\csrss.exe'}),
    'services.exe':     frozenset({'c:\\windows\\system32\\services.exe'}),
    'wininit.exe':      frozenset({'c:\\windows\\system32\\wininit.exe'}),
    'winlogon.exe':     frozenset({'c:\\windows\\system32\\winlogon.exe'}),
    'explorer.exe':     frozenset({'c:\\windows\\explorer.exe'}),
    'dllhost.exe':      frozenset({'c:\\windows\\system32\\dllhost.exe',
                                   'c:\\windows\\syswow64\\dllhost.exe'}),
    'dwm.exe':          frozenset({'c:\\windows\\system32\\dwm.exe'}),
    'spoolsv.exe':      frozenset({'c:\\windows\\system32\\spoolsv.exe'}),
    'msmpeng.exe':      frozenset({'c:\\programdata\\microsoft\\windows defender\\platform\\',
                                   'c:\\program files\\windows defender\\'}),
    'audiodg.exe':      frozenset({'c:\\windows\\system32\\audiodg.exe'}),
    'searchindexer.exe': frozenset({'c:\\windows\\system32\\searchindexer.exe'}),
    'fontdrvhost.exe':  frozenset({'c:\\windows\\system32\\fontdrvhost.exe'}),
}

# Module 13 signal profiles that are CERTAINLY benign (structural data, not payload).
# Each entry is a minimum-conditions dict; all conditions must hold to match.
M13_BENIGN_PROFILES = [
    {
        'cv_pct_min':   100.0,  # non-uniform byte distribution
        'ascii_pct_min': 30.0,  # high printable ratio (structured data with strings)
        'mz_remnant':   False,
        'adj_anon_exec': False,
        'label': 'Structured system data buffer (task scheduler / COM / audio state)',
    },
    {
        'cv_pct_min':   40.0,
        'ascii_pct_min': 40.0,
        'mz_remnant':   False,
        'adj_anon_exec': False,
        'label': 'High-ASCII moderate-CV buffer (text/config data)',
    },
    {
        # High CV (clearly non-uniform, NOT AES-encrypted) with low ASCII:
        # binary data that just happens not to contain printable chars.
        # Examples: PCM audio (audiodg.exe), binary index databases
        # (searchindexer.exe), font glyph caches (dwm.exe).
        # An adversary encrypted payload has LOW CV (< 15%), not HIGH CV (> 150%).
        'cv_pct_min':   150.0,
        'ascii_pct_min': 0.0,   # no ascii_pct minimum -- low ASCII is expected here
        'mz_remnant':   False,
        'adj_anon_exec': False,
        'label': 'Binary non-ASCII data buffer (PCM audio / index / font data)',
    },
]
