"""
AgentTeslaConfig -- mwcp parser for Agent Tesla keylogger / stealer configuration.

Agent Tesla is a commodity .NET keylogger / credential stealer sold as MaaS.
It supports three exfil methods and always includes keylogger function imports.

DETECTION BASIS (two-of-three scoring):
  +2  "Agent Tesla" / "AgentTesla" product name string embedded in binary
  +2  GetKeyboardState / GetAsyncKeyState -- keylogger Win32 import
  +1  ProductionModeKey / Productionkey  -- licensing field
  +1  SMTP cluster: smtp host + port + from + to + password within 512 bytes
  +1  FTP exfil: ftp:// URL with credentials

Require score >= 2 in identify().

EXFIL METHODS DETECTED:
  SMTP  -- smtp host:port, username/from address, password
  FTP   -- ftp:// URL with credentials
  Telegram -- bot token (handled by TelegramC2Config, cross-ref here)

None of these indicator strings appear in legitimate .NET applications
combined with keylogger imports.  A .NET email client has SMTP but not
GetKeyboardState.

References:
    Agent Tesla malware analysis (multiple AV vendors / malpedia)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Password, DecodedString

# Product name strings
_PRODUCT_RE = re.compile(
    rb'Agent\s*Tesla|AgentTesla|agenttesla',
    re.IGNORECASE
)

# Keylogger Win32 import names
_KEYLOG_RE = re.compile(
    rb'GetKeyboardState|GetAsyncKeyState|SetWindowsHookEx|keylog',
    re.IGNORECASE
)

# Licensing / build marker
_LICENSE_RE = re.compile(
    rb'ProductionMode[Kk]ey|Productionkey',
    re.IGNORECASE
)

# SMTP config extraction
_SMTP_HOST_RE = re.compile(
    rb'(?:smtp[A-Za-z0-9\.\-]*\.(?:[a-z]{2,8})|mail\.[a-zA-Z0-9\-\.]{4,50})',
    re.IGNORECASE
)
_SMTP_PORT_RE = re.compile(
    rb'(?:587|465|25|2525)(?!\d)',
)
_SMTP_USER_RE = re.compile(
    rb'[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]{2,64}\.[a-zA-Z]{2,10}',
)
_SMTP_PASS_RE = re.compile(
    rb'(?:password|pass|pwd)[\s:=]+["\']?([A-Za-z0-9!@#\$%^&\*\-_\.\+]{6,64})',
    re.IGNORECASE
)

# FTP exfil
_FTP_URL_RE = re.compile(
    rb'ftp://[A-Za-z0-9_\-\.@:]{4,200}',
    re.IGNORECASE
)

_SMTP_WINDOW = 512


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _has_exfil_or_product(data: bytes) -> bool:
    """A real exfil channel (SMTP cluster or FTP URL) or the product name
    string -- at least one of these, none of which is a generic Win32 API
    that unrelated software also imports."""
    if _PRODUCT_RE.search(data):
        return True
    if _FTP_URL_RE.search(data):
        return True
    for mh in _SMTP_HOST_RE.finditer(data):
        window = data[max(0, mh.start() - _SMTP_WINDOW):
                      min(len(data), mh.end() + _SMTP_WINDOW)]
        if _SMTP_PORT_RE.search(window) and _SMTP_USER_RE.search(window):
            return True
    return False


class AgentTeslaConfig(mwcp.Parser):
    """Extract Agent Tesla exfil configuration from PE or memory regions."""

    DESCRIPTION = "Agent Tesla Keylogger/Stealer Config Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        # GetKeyboardState/GetAsyncKeyState alone is a routine Win32 API
        # used by countless legitimate hotkey/accessibility/input-handling
        # applications -- it is never sufficient by itself. Require it
        # PLUS a real exfil channel or the product name string.
        return bool(_KEYLOG_RE.search(data)) and _has_exfil_or_product(data)

    def run(self):
        data = self.file_object.data
        if not data or not (_KEYLOG_RE.search(data) and _has_exfil_or_product(data)):
            return

        seen = set()
        exfil_methods = []

        # SMTP exfil
        smtp_host = None
        smtp_port = None
        smtp_user = None

        for mh in _SMTP_HOST_RE.finditer(data):
            host = _clean(mh.group(0))
            lo = max(0, mh.start() - _SMTP_WINDOW)
            hi = min(len(data), mh.end() + _SMTP_WINDOW)
            window = data[lo:hi]

            port_m = _SMTP_PORT_RE.search(window)
            user_m = _SMTP_USER_RE.search(window)

            if port_m and user_m:
                smtp_host = host
                smtp_port = _clean(port_m.group(0))
                smtp_user = _clean(user_m.group(0))
                c2 = f'{host}:{smtp_port}'
                if c2 not in seen:
                    seen.add(c2)
                    self.report.add(C2Address(c2))

                # Password extraction in window
                for pm in _SMTP_PASS_RE.finditer(window):
                    pw = _clean(pm.group(1))
                    if pw and pw not in seen:
                        seen.add(pw)
                        self.report.add(Password(pw))

                exfil_methods.append(f'SMTP:{smtp_host}:{smtp_port}')
                break

        # FTP exfil
        for m in _FTP_URL_RE.finditer(data):
            url = _clean(m.group(0))
            if url not in seen:
                seen.add(url)
                self.report.add(C2Address(url))
                exfil_methods.append(f'FTP:{url[:50]}')

        # Family label
        label = f'[AgentTesla-Config] exfil={",".join(exfil_methods) if exfil_methods else "unknown"}'
        if smtp_user:
            label += f' from={smtp_user}'
        self.report.add(DecodedString(label))

        if _KEYLOG_RE.search(data):
            self.report.add(DecodedString('[AgentTesla-Keylogger] GetKeyboardState/hook confirmed'))
