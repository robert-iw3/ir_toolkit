"""
CobaltStrikeConfig -- mwcp parser for CobaltStrike Beacon configuration blocks.

CS beacons store a structured config block in the PE data section or injected
region. The block is XOR-encoded with a single-byte key (commonly 0x69 for HTTP,
0x2e for DNS, but varies). Each entry is a big-endian tuple:
    uint16 id | uint16 datatype | uint16 datalength | bytes data[datalength]

Detection: scan for the XOR-encoded magic of the first config entry (ID=1,
type=short, len=2) across all 256 possible keys. When found, decode the full
block and extract C2, sleep, jitter, user-agent, spawn process, pipe name,
watermark, and license ID.

References:
  - 0x09AL: "In memory of... CobaltStrike"
  - SentinelOne: CobaltStrikeParser
  - Kevin Hodes: "Analyzing CobaltStrike for Fun and Profit"
  - HashiCorp malware reports (CS config structure)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import struct
import mwcp
from mwcp.metadata import C2Address, C2URL, Mutex, DecodedString, Password

# --- CS config setting IDs (public research) ---
_SETTINGS = {
    1:  ('BeaconType',          'short'),
    2:  ('Port',                'short'),
    3:  ('SleepTime',           'int'),
    4:  ('MaxGetSize',          'int'),
    5:  ('Jitter',              'short'),
    6:  ('MaxDNS',              'short'),
    7:  ('C2Server',            'str'),   # "host,/uri" -- primary C2
    8:  ('UserAgent',           'str'),
    9:  ('HttpGet_Header',      'str'),
    10: ('HttpPost_Header',     'str'),
    11: ('SpawnTo32',           'str'),
    12: ('SpawnTo64',           'str'),
    13: ('KillDate_Year',       'short'),
    14: ('KillDate_Month',      'short'),
    15: ('KillDate_Day',        'short'),
    16: ('DNS_Idle',            'int'),
    17: ('DNS_Sleep',           'int'),
    18: ('SSH_Host',            'str'),
    19: ('SSH_Port',            'short'),
    20: ('SSH_Username',        'str'),
    21: ('SSH_Password',        'str'),
    22: ('SSH_Key',             'str'),
    23: ('C2_GetOnly',          'str'),
    24: ('C2_GetPost',          'str'),
    25: ('Hostname',            'str'),
    26: ('PayloadType',         'short'),
    27: ('C2Port',              'short'),
    28: ('Proxy_HostName',      'str'),
    29: ('Proxy_UserName',      'str'),
    30: ('Proxy_Password',      'str'),
    31: ('Proxy_AccessType',    'short'),
    32: ('CreateRemoteThread',  'short'),
    33: ('InjDll32',            'str'),
    34: ('InjDll64',            'str'),
    35: ('UsesCookies',         'short'),
    36: ('HttpPostChunk',       'int'),
    37: ('HostHeader',          'str'),   # Host: for domain fronting / CDN
    38: ('ObfuscateSectName',   'short'),
    39: ('ProcInject_StartRWX', 'short'),
    40: ('ProcInject_UseRWX',   'short'),
    41: ('ProcInject_MinAlloc', 'int'),
    42: ('ProcInject_Xform32',  'str'),
    43: ('ProcInject_Xform64',  'str'),
    44: ('UNUSED_44',           'short'),
    45: ('ProcInject_Stub',     'str'),
    46: ('HostHeader2',         'str'),
    47: ('ExitFunk',            'short'),
    48: ('ProcInject_BoFL',     'short'),
    49: ('ProcInject_Execute',  'str'),
    50: ('PipeName',            'str'),   # SMB named pipe
    51: ('KillDate',            'int'),
    52: ('TextSectionEnd',      'int'),
    53: ('ObfuscateSect2',      'short'),
    54: ('ProcInject_Execute2', 'str'),
    55: ('ProcInject_AllocMeth','short'),
    56: ('ProcInject_Stub2',    'str'),
    57: ('BindHost',            'str'),
    58: ('bStageCleanup',       'short'),
    59: ('bCFGCaution',         'short'),
    60: ('KillDate_Year2',      'short'),
    61: ('KillDate_Month2',     'short'),
    62: ('DNS_Resolved_IP',     'str'),
    63: ('DNS_Resolved_IP2',    'str'),
    70: ('server.publickey',    'str'),   # RSA public key (beacon auth)
    71: ('HttpGet_Verb',        'str'),
    72: ('HttpPost_Verb',       'str'),
}

# Beacon type ID → human label
_BEACON_TYPE = {
    0:  'HTTP',
    1:  'Hybrid-HTTP+DNS',
    8:  'HTTPS',
    16: 'TCP (bind)',
    32: 'TCP (reverse)',
    64: 'SMB (named pipe)',
}

# Minimum valid setting ID range and count for a real config block
_MIN_SETTINGS = 5
_MAX_SETTING_ID = 200
_MAX_DATA_LEN   = 8192
_MAX_CONFIG_SIZE = 8 * 1024  # 8KB max config block size

# Key candidates most common in CS beacons (try first for speed)
_PRIORITY_KEYS = [0x69, 0x2e, 0x00]


def _try_parse_block(data: bytes, offset: int, key: int) -> dict | None:
    """Attempt to parse a CS config block at data[offset:] using XOR key.
    Returns a settings dict keyed by setting ID, or None if invalid."""
    config = {}
    pos = offset

    for _ in range(200):  # max 200 settings
        if pos + 6 > len(data):
            break

        # Decode 6-byte header (big-endian)
        raw6 = data[pos:pos + 6]
        if key:
            raw6 = bytes(b ^ key for b in raw6)

        try:
            setting_id, datatype, datalen = struct.unpack('>HHH', raw6)
        except struct.error:
            return None

        # Sentinel: ID 0 = end of config
        if setting_id == 0:
            break

        # Validity checks
        if setting_id > _MAX_SETTING_ID:
            return None
        if datatype not in (1, 2, 3):
            return None
        if datalen > _MAX_DATA_LEN or datalen < 0:
            return None

        pos += 6
        if pos + datalen > len(data):
            break

        raw_val = data[pos:pos + datalen]
        if key:
            raw_val = bytes(b ^ key for b in raw_val)
        pos += datalen

        # Parse value by type
        if datatype == 1:
            # short (2 bytes)
            val = struct.unpack('>H', raw_val[:2])[0] if len(raw_val) >= 2 else 0
        elif datatype == 2:
            # int (4 bytes)
            val = struct.unpack('>I', raw_val[:4])[0] if len(raw_val) >= 4 else 0
        else:
            # string: strip nulls, decode UTF-8
            val = raw_val.rstrip(b'\x00').decode('utf-8', 'replace').strip()

        config[setting_id] = val

        # Early exit if block is clearly too large (something is wrong)
        if pos - offset > _MAX_CONFIG_SIZE:
            break

    if len(config) < _MIN_SETTINGS:
        return None

    # A real config must have at least a C2 server (ID 7) or a payload type (ID 1)
    if 7 not in config and 1 not in config:
        return None

    return config


def _find_config(data: bytes) -> tuple[dict, int] | tuple[None, None]:
    """Scan data for the CS beacon config block. Returns (config_dict, xor_key) or (None, None).

    Detection: the first config entry is always ID=1 (BeaconType), type=1 (short), len=2.
    Encoded with key k: raw bytes = [k, k^1, k, k^1, k, k^2, ...]
    We search for any 6-byte sequence matching this pattern across all 256 keys.
    """
    # Build all possible 6-byte magic patterns (first entry encoded with each key)
    # Magic decoded = \x00\x01 \x00\x01 \x00\x02
    magic_decoded = b'\x00\x01\x00\x01\x00\x02'

    # Deduplicated offsets to avoid parsing same location multiple times
    checked = set()

    def try_offset(offset, key):
        if (offset, key) in checked:
            return None
        checked.add((offset, key))
        return _try_parse_block(data, offset, key)

    # Strategy 1: try priority keys at all offsets
    for key in _PRIORITY_KEYS:
        magic_encoded = bytes(b ^ key for b in magic_decoded) if key else magic_decoded
        pos = 0
        while True:
            idx = data.find(magic_encoded, pos)
            if idx == -1:
                break
            result = try_offset(idx, key)
            if result:
                return result, key
            pos = idx + 1

    # Strategy 2: brute-force remaining keys at aligned offsets only (performance)
    for key in range(256):
        if key in _PRIORITY_KEYS:
            continue
        magic_encoded = bytes(b ^ key for b in magic_decoded)
        pos = 0
        while True:
            idx = data.find(magic_encoded, pos)
            if idx == -1:
                break
            result = try_offset(idx, key)
            if result:
                return result, key
            pos = idx + 1

    return None, None


def _fmt_c2(c2_str: str, port: int) -> list[str]:
    """Parse CS C2Server field ("host1,/uri1\nhost2,/uri2") into list of URL/host strings."""
    out = []
    for line in c2_str.split('\n'):
        line = line.strip()
        if not line:
            continue
        if ',' in line:
            host, uri = line.split(',', 1)
            host = host.strip()
            uri  = uri.strip()
            if port and port not in (80, 443):
                out.append(f'http://{host}:{port}{uri}')
            else:
                out.append(f'http://{host}{uri}')
        else:
            out.append(line)
    return out


class CobaltStrikeConfig(mwcp.Parser):
    """Extract CobaltStrike beacon configuration from PE or carved memory region."""

    DESCRIPTION = "CobaltStrike Beacon Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        # Quick pre-filter: file must be PE, or large enough to contain a config block.
        # Run on PEs (MZ) and raw binary regions (common from memory carving).
        # Exclude tiny files (< 1KB) and pure text files.
        is_pe = data[:2] == b'MZ'
        is_binary = any(b > 0x7e or (b < 0x20 and b not in (0x09, 0x0a, 0x0d))
                        for b in data[:64])
        return is_pe or is_binary

    def run(self):
        data = self.file_object.data
        if not data or len(data) < 64:
            return

        config, xor_key = _find_config(data)
        if not config:
            return

        self.logger.debug(f'[CS] config found, XOR key=0x{xor_key:02x}, {len(config)} settings')

        # --- C2 Server (ID 7) ---
        c2_str  = config.get(7, '')
        c2_port = config.get(2, 0) or config.get(27, 0)
        beacon_type = config.get(1, 0)
        is_https = beacon_type == 8

        if c2_str:
            for c2 in _fmt_c2(c2_str, c2_port):
                if c2.startswith('http'):
                    url = c2.replace('http://', 'https://') if is_https else c2
                    self.report.add(C2URL(url))
                else:
                    addr = f'{c2}:{c2_port}' if c2_port else c2
                    self.report.add(C2Address(addr))

        # Secondary C2 (ID 23: get-only, ID 24: get+post)
        for sec_id in (23, 24):
            sec = config.get(sec_id, '')
            if sec and sec != c2_str:
                for c2 in _fmt_c2(sec, c2_port):
                    self.report.add(C2URL(c2) if c2.startswith('http') else C2Address(c2))

        # HostHeader (ID 37 / 46) -- domain-fronting front domain
        for hh_id in (37, 46):
            hh = config.get(hh_id, '')
            if hh and hh.strip():
                self.report.add(DecodedString(f'[CS-HostHeader] {hh}'))

        # --- User-Agent (ID 8) ---
        ua = config.get(8, '')
        if ua:
            self.report.add(DecodedString(f'[CS-UserAgent] {ua}'))

        # --- Sleep + Jitter (IDs 3, 5) ---
        sleep_ms = config.get(3, 0)
        jitter_pct = config.get(5, 0)
        if sleep_ms:
            self.report.add(DecodedString(
                f'[CS-Timing] sleep={sleep_ms}ms jitter={jitter_pct}%'))

        # --- Beacon type label ---
        btype_label = _BEACON_TYPE.get(beacon_type, f'type={beacon_type}')
        self.report.add(DecodedString(f'[CS-BeaconType] {btype_label} port={c2_port}'))

        # --- Named pipe (ID 50) -- SMB beacon indicator ---
        pipe = config.get(50, '') or config.get(12, '')
        if pipe:
            self.report.add(DecodedString(f'[CS-PipeName] {pipe}'))

        # --- SpawnTo process (IDs 11, 12 for x86/x64 in older, varies) ---
        spawn32 = config.get(11, '')
        spawn64 = config.get(12, '')
        if spawn32 or spawn64:
            sp = spawn64 or spawn32
            self.report.add(DecodedString(f'[CS-SpawnTo] {sp}'))

        # --- KillDate (ID 51 = int, or 13/14/15 = year/month/day) ---
        killdate_int = config.get(51, 0)
        if killdate_int:
            # YYYYMMDD packed as int
            self.report.add(DecodedString(f'[CS-KillDate] {killdate_int}'))

        # --- SSH credentials (IDs 18-22) ---
        ssh_host = config.get(18, '')
        ssh_user = config.get(20, '')
        ssh_pass = config.get(21, '')
        ssh_port = config.get(19, 0)
        if ssh_host:
            addr = f'{ssh_host}:{ssh_port}' if ssh_port else ssh_host
            self.report.add(C2Address(addr))
        if ssh_user:
            self.report.add(Password(ssh_user))
        if ssh_pass:
            self.report.add(Password(ssh_pass))

        # --- Proxy credentials (IDs 28-30) ---
        proxy_host = config.get(28, '')
        proxy_user = config.get(29, '')
        proxy_pass = config.get(30, '')
        if proxy_host:
            self.report.add(C2Address(proxy_host))
        if proxy_pass:
            self.report.add(Password(proxy_pass))

        # --- Public key (ID 70) -- unique per team server, useful for pivoting ---
        pubkey = config.get(70, '')
        if pubkey and len(pubkey) > 8:
            # Emit first 16 hex chars as a pivot indicator (full key too large for report)
            self.report.add(DecodedString(
                f'[CS-PublicKey] {pubkey[:16].encode().hex() if isinstance(pubkey, str) else pubkey[:16].hex()}...'))

        # --- Summarize full config as a DecodedString for analyst review ---
        lines = ['[CS-Config]']
        for sid, (name, _) in _SETTINGS.items():
            val = config.get(sid)
            if val is not None and val != '' and val != 0:
                lines.append(f'  {sid:3d} {name}: {val}')
        self.report.add(DecodedString('\n'.join(lines)))
