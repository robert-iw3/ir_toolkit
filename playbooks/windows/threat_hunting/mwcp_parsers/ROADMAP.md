# mwcp Parser Roadmap

Parsers in this directory extend DC3-MWCP beyond its bundled generic parsers.
All parsers in `mwcp_parsers/` are staged into `tools/mwcp/lib/mwcp/parsers/`
by `Build-OfflineToolkit.ps1 -IncludeMWCP`. Each parser runs automatically against
the appropriate file type via the file-type detection in `mwcp_scan.py`.

---

## Implemented

| Parser | File types | Extracts | Status |
|--------|-----------|----------|--------|
| `GenericMutex.py` | ALL | Mutex names: bare hex tokens + API-proximity strings | ✅ |
| `GenericC2.py` | ALL | C2: IP:port, URLs, domains, registry persistence paths | ✅ |
| `PowerShellDecoder.py` | PS1, VBS, HTA, BAT, LNK, PE | Decoded -EncodedCommand payloads, download cradle URLs | ✅ |
| `LNKParser.py` | LNK | Shortcut arguments (payload lives here), embedded URLs | ✅ |
| `CobaltStrikeConfig.py` | PE, UNKNOWN (carved regions) | C2 host/URI, beacon type, sleep+jitter, UserAgent, HostHeader (domain fronting), SpawnTo, PipeName, RSA pubkey — brute-forces XOR key across all 256 values | ✅ |

---

## Tier 1 — Modern C2 Frameworks (highest IR encounter rate)

| Parser | Target | Extracts | Reference |
|--------|--------|----------|-----------|
| `CobaltStrikeConfig.py` | PE (beacon DLL/EXE) | Sleep + jitter, C2 host/port/URI, Malleable C2 User-Agent + headers, spawn process, named pipe, watermark/license ID | XOR-encoded with documented algorithm. SentinelOne CobaltStrikeParser, Didier Stevens cs-decrypt-metadata |
| `SliverConfig.py` | PE (Go binary) | C2 server URL, implant name, reconnect interval, DNS C2 domains, mTLS cert fingerprint | Go binary; config embedded as JSON in const section. SEKOIA Sliver analysis |
| `HavocConfig.py` | PE | C2 host:port, sleep + jitter, User-Agent, injection method, process name, magic bytes | Documented JSON config block prepended to shellcode payload |
| `BruteRatelConfig.py` | PE | C2 URL, profile name, sleep, jitter, process injection config, KillDate | BRc4 config is RC4-encrypted with documented key derivation |
| `MythicConfig.py` | PE/ELF | C2 host:port, callback interval, UUID, encryption key (P2P or server) | Mythic agent configs vary by agent type (Poseidon, Apollo, Athena); each has structured JSON |
| `NightHawkConfig.py` | PE | C2 URL, sleep, jitter, process hollowing target | Commercial C2; limited public research but config structure partially documented |
| `PoshC2Config.py` | PS1 | Server URL, implant name, Kill Date, proxy settings | Plain text PS1 stager with embedded config variables. Parse `$server`, `$payload`, `$kill_date` |
| `MerlinConfig.py` | PE (Go) | C2 URL, PSK, sleep, skew, max retry, padding max | Go-based; config in JSON format embedded in binary |

---

## Tier 1 — Common RATs (commodity malware, high volume)

| Parser | Target | Extracts | Reference |
|--------|--------|----------|-----------|
| `AsyncRATConfig.py` | PE | C2 host:port, mutex, install path, anti-analysis flags, persistence key | Base64-encoded XML in .rsrc section. Public parser by jeFF0Falltrades |
| `NjRATConfig.py` | PE | Host, port, campaign/tag name, mutex, registry run key, folder name | Pipe-delimited plain text. VERY common MENA/SEA threat landscape |
| `QuasarRATConfig.py` | PE | Host:port, mutex, reconnect delay, AES-128 key | AES-encrypted but key derivation documented. GitHub: quasar-parser |
| `DcRATConfig.py` | PE | C2 host:port, mutex, HWID salt, install file name | Config stored as encrypted embedded strings. Variation of AsyncRAT codebase |
| `RemcosConfig.py` | PE | C2 host:port, mutex, license key, campaign tag, keylog path | RC4-encrypted config. CAPE sandbox has reference parser |
| `NanoCoreConfig.py` | PE | C2 host:port, mutex, Group, BuildTime, plugins list | Config in .NET resources as encrypted XML. Documented in MalShare reports |
| `AgentTeslaConfig.py` | PE | Exfil method (SMTP/FTP/Telegram), SMTP host + credentials, keylog path | Common credential stealer. Config varies by exfil method; often plain text in .NET strings |

---

## Tier 1 — Stealers (high volume in initial access incidents)

| Parser | Target | Extracts | Reference |
|--------|--------|----------|-----------|
| `RedlineConfig.py` | PE | C2 host:port, build ID, license ID | Config in XML or base64 embedded resource. Multiple public parsers |
| `VidarConfig.py` | PE | C2 URL, botnet ID, Telegram channel (newer variants) | Config URL embedded in PE overlay or .rsrc. Extracts the config host for OSINT |
| `LummaConfig.py` | PE | C2 host list, build ID | Multiple encrypted C2 URLs in PE overlay. Active development by threat actor |
| `StealcConfig.py` | PE | C2 URL, bot ID | Config URL embedded as plaintext or lightly encoded in PE |
| `RaccoonConfig.py` | PE | C2 URL, build ID | Config fetched from hardcoded C2; embed URL extraction covers pre-fetch analysis |
| `TelegramExfilConfig.py` | ALL | Telegram bot token + chat ID | Cross-family pattern: Redline, Vidar, clipboard stealers increasingly use Telegram. Token is actionable — enumerate bot history |

---

## Tier 2 — Ransomware Indicators

| Parser | Target | Extracts | Reference |
|--------|--------|----------|-----------|
| `RansomwareIndicators.py` | PE | Encrypted file extension list, ransom note filename, embedded RSA/ECC public key block, victim ID format, VSS deletion commands | Generic across families; key signal is RSA public key block (PKCS#1) in PE overlay |
| `LockBitConfig.py` | PE | Config JSON (target process/service kill lists, extension, ransom note name, C2 URL if present) | LockBit stores JSON config in PE overlay after RSA-encrypted region |
| `BlackCatConfig.py` | PE (Rust) | JSON config: extension, kill list, exclusion paths, C2 URL, public key | ALPHV/BlackCat embeds plaintext JSON config inside the binary |
| `REvil_SodinokibiConfig.py` | PE | C2 domain list, public key, campaign ID, exclusion paths | Config is JSON, RC4 encrypted, key derivation documented |
| `ContiConfig.py` | PE | C2 IP:port list, RSA public key, AES key (if present) | Config embedded as RC4-encrypted blob with hardcoded key |

---

## Tier 2 — Living-off-the-Land / Fileless Behavioral Patterns

| Parser | Target | Extracts | Reference |
|--------|--------|----------|-----------|
| `WMIPersistenceConfig.py` | ALL | WMI filter query (EventFilter), consumer command (CommandLineTemplate/ScriptText), event name | Dropper embeds WMI subscription strings before installing them |
| `ScheduledTaskConfig.py` | XML, ALL | Task action (Execute + Arguments), trigger type, author, run-as user | Malicious task XML exported by persistence framework; extract command for IOC |
| `RegistryPersistenceConfig.py` | PE, PS1 | Run/RunOnce paths, AppInit_DLL paths, IFEO debugger paths embedded in dropper | Complements GenericC2; specifically targets persistence registry paths |
| `DefenderExclusionConfig.py` | PE, PS1 | Add-MpPreference -ExclusionPath / -ExclusionProcess strings | Common in loaders that exclude themselves before dropping payload |
| `AMSIPatchConfig.py` | PS1, PE | AmsiScanBuffer patch bytes, amsi.dll load / patch patterns | Identifies AMSI bypass mechanism and target function name |

---

## Tier 2 — Delivery Mechanism Parsers

| Parser | Target | Extracts | Reference |
|--------|--------|----------|-----------|
| `MacroExtractor.py` | DOC, XLS, XLSM, DOCM | VBA source code, embedded URLs, Shell/CreateObject calls | Supplement to olevba; emit as DecodedString with C2URL |
| `ISOLNKChain.py` | ISO/LNK combo | LNK arguments inside ISO image, extract download URL | ISO contains a single LNK; parse both levels |
| `HTMLSmugglingDetector.py` | HTML, HTM | `navigator.msSaveBlob`, `<a download>` with data URI, base64 blob content | HTML smuggling: extract the embedded payload blob and classify |
| `OneNoteEmbedDetector.py` | ONE | Embedded file paths, attachment click-to-run scripts | OneNote EmbeddedFile vector (2023+); extract attachment filename and embedded command |

---

## Tier 3 — Specialized / Post-Compromise

| Parser | Target | Extracts | Reference |
|--------|--------|----------|-----------|
| `CryptoMinerConfig.py` | PE, UNKNOWN | Full mining config: stratum pool URL, wallet, worker, algorithm, thread count | GenericC2 catches stratum URL; this extracts the complete config structure |
| `DiscordWebhookConfig.py` | ALL | Discord webhook URL, server/channel IDs | Cross-family; increasingly used for exfil by Redline, stealers, RATs |
| `SMTPExfilConfig.py` | PE | SMTP host, port, username+password in proximity | Legacy RATs and stealers. Auth credentials are immediately actionable |
| `AntiAnalysisStrings.py` | PE | VM/sandbox names, analyst tool names the binary checks | Not a C2 IOC but confirms malware-awareness; emitted as DecodedString |
| `MetasploitPayload.py` | PE, UNKNOWN | LHOST, LPORT embedded in Metasploit shellcode | Pattern: XOR-encoded shellcode with known offsets for LHOST/LPORT |
| `BitsadminPersistenceConfig.py` | PS1, BAT | BITS job name, download URL, destination path embedded in script | Common BITS-based loader; extract the remote URL and staging path |

---

---

## CRITICAL: Requirements for writing parsers (hard-won — do not skip)

These were discovered through live debugging of mwcp 3.16.1. Violating any of them
produces silent 0-result failures with no error message.

### 1. Register in `parser_config.yml` — MANDATORY

Every custom parser needs an entry in `tools/mwcp/lib/mwcp/parser_config.yml`.
Without it, `mwcp.run('MyParser', ...)` silently rejects the name with debug log
`[dc3] Invalid name MyParser` — no exception, no report.errors, 0 results.

```yaml
MyParser:
  description: Brief description matching DESCRIPTION field
  author: IR_Toolkit
  parsers:
    - .MyParser   # dot + exact Python class name
```

### 2. File data attribute is `.data` not `.file_data`

`self.file_object.file_data` returns None silently. Use `self.file_object.data`.
Same in `identify()`: use `file_object.data`.

### 3. Extract via `report.as_dict()['metadata']` not `report.get(meta.Class)`

`report.metadata` is a dict — iterating yields field name strings, not objects.
`report.get(meta.SomeClass)` can silently return nothing.

Use `report.as_dict()['metadata']` — returns a list of dicts with a `type` key.

| `type` | value field | maps to |
|--------|------------|---------|
| `mutex` | `value` | mutex name |
| `socket` / `c2_socketaddress` | `address` | `ip:port` or domain |
| `url` / `c2_url` | `url` | full URL string |
| `network` | `url.url` | nested url object |
| `decoded_string` | `value` | decoded payload text |
| `filename` / `filepath` | `value` or `path` | file path |
| `password` / `credential` | `password` or `value` | credential |
| `registry` | `value` | registry path |

### 4. Exceptions in `run()` are swallowed silently

`Dispatcher._parse()` catches all exceptions and logs only to Python's logging system.
Without a logging handler (subprocess default), the exception disappears — 0 results, 0 errors.

Debug: `import logging; logging.basicConfig(level=logging.DEBUG)` before `mwcp.run()`.

### 5. `os.path.splitext(path).lower()` kills extension detection

`splitext()` returns a 2-tuple — calling `.lower()` on it raises AttributeError caught silently.
Correct: `os.path.splitext(path)[1].lower()`.

---

## Parser writing guide

```python
import mwcp
from mwcp.metadata import Mutex, C2Address, C2URL, DecodedString, Password

class MyParser(mwcp.Parser):
    DESCRIPTION = "Brief description matching parser_config.yml entry"

    @classmethod
    def identify(cls, file_object):
        data = file_object.data or b''        # CORRECT: .data not .file_data
        return data[:2] == b'MZ'

    def run(self):
        data = self.file_object.data           # CORRECT: .data not .file_data
        if not data:
            return
        self.report.add(Mutex("name"))
        self.report.add(C2URL("https://c2.example.com/gate"))
        self.report.add(C2Address("1.2.3.4:4444"))
        self.report.add(Password("secret"))
        self.report.add(DecodedString("[decoded] iex ..."))
        # Caller reads results via report.as_dict()['metadata'] -- see _extract_metadata() in mwcp_scan.py
```

**To add a new parser:**
1. Write `MyParser.py` in this directory
2. Copy to `tools/mwcp/lib/mwcp/parsers/`
3. **Add entry to `tools/mwcp/lib/mwcp/parser_config.yml`** (required — see §1 above)
4. Add to `mwcp_scan.py` `_select_parsers()` type map for the relevant file type
5. Test: `python mwcp_scan.py <lib> <out> <sample.ps1>` — verify `address`/`decoded` in JSON output
6. Rebuild: `Build-OfflineToolkit.ps1 -IncludeMWCP` stages parsers + updated config to tools/
