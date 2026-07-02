# mwcp Parser Roadmap

Parsers in this directory extend DC3-MWCP beyond its bundled generic parsers.
All parsers in `mwcp_parsers/` are staged into `tools/mwcp/lib/mwcp/parsers/`
by `Build-OfflineToolkit.ps1 -IncludeMWCP`. Each parser runs automatically against
the appropriate file type via the file-type detection in `mwcp_scan.py`.

What is implemented and validated is documented in [README.md](README.md).
This file tracks only what is planned but not yet built.

---

## Tier 1 — Additional C2 Frameworks

Detection strategy: `identify()` uses **wire-protocol field names and binary
structural indicators** — NOT framework name strings that operators strip.

| Parser | Target | Detection basis | Extracts |
|--------|--------|-----------------|----------|
| `DeimosConfig.py` | PE (Go) | Go struct field names (`CallbackURL`, `Interval`, `PubKey`) unique to Deimos | C2 URL, interval, public key |
| `MacroPackConfig.py` | ALL | MacroPack marker strings in macro documents + payload URL pattern | Delivery URL, payload type |
| `IcedIDConfig.py` | PE | RC4-encrypted botnet config in PE overlay with documented key location | Bot ID, campaign ID, C2 domain |
| `QakBotConfig.py` | PE | XOR-encoded config block with `tid`/`campaign_id`/C2 list | Campaign ID, C2 IP list |
| `EmotedConfig.py` | PE | Emotet's multi-layer RSA+AES config with documented structure | C2 IP:port list, public key |

**NightHawk — NOT planned as mwcp parser (intentional):**
MDSec explicitly engineered NightHawk to defeat all file-content and memory-
scanning signatures. Detection requires behavioral telemetry that mwcp cannot provide:
- **Thread context**: hardware breakpoints (DR0-DR7) set without a debugger attached
- **Sleeping beacon**: unbacked private memory in WAIT state (Hunt-Sleeping-Beacons)
- **Network behavioral model**: automated C2 polling vs. human-driven traffic statistics
- **Post-exploitation anomalies**: process spawned with empty command line, unexpected DLL loads

These belong in `memory_enrich.py` (thread context module), the egress monitor
(behavioral network modeling), and the EDR YARA scan (`Hunt-Sleeping-Beacons.yar`).

---

## Tier 1 — Common RATs (commodity malware, high volume)

| Parser | Target | Detection basis | Extracts |
|--------|--------|-----------------|----------|
| `RemcosConfig.py` | PE | `SETTINGS` PE section + RC4-encrypted config with documented key derivation | C2 host:port, mutex, license key, campaign tag, keylog path |
| `NanoCoreConfig.py` | PE | .NET resource named `MANIFEST` containing encrypted XML with documented structure | C2 host:port, mutex, Group, BuildTime, plugin list |
| `AsyncSpyConfig.py` | PE | AsyncRAT variant cluster — same field names but with `AsyncSpy` marker string | C2 host:port, mutex |

---

## Tier 1 — Stealers (high volume in initial access incidents)

| Parser | Target | Detection basis | Extracts |
|--------|--------|-----------------|----------|
| `RedlineConfig.py` | PE | .NET resource named `cfg` containing base64 XML config | C2 host:port, build ID, license ID |
| `VidarConfig.py` | PE | PE overlay URL string after section boundary + Telegram channel in newer variants | C2 URL, botnet ID, Telegram channel |
| `LummaConfig.py` | PE | Multiple base64-encoded C2 URLs in PE overlay separated by null bytes | C2 URL list, build ID |
| `StealcConfig.py` | PE | Plaintext C2 URL adjacent to `Content-Type: application/x-www-form-urlencoded` marker | C2 URL, bot ID |
| `RaccoonConfig.py` | PE | Hardcoded C2 URL string in PE data section (Raccoon v2 uses Telegram for C2 URL delivery) | C2 URL, build ID |

---

## Tier 2 — Ransomware Config Extraction

| Parser | Target | Detection basis | Extracts |
|--------|--------|-----------------|----------|
| `RansomwareIndicators.py` | PE | RSA/ECC PKCS#1 public key block in PE overlay (universal ransomware signal) | File extension list, ransom note filename, embedded public key, victim ID format, VSS commands |
| `LockBitConfig.py` | PE | JSON config after RSA-encrypted region in PE overlay | Process/service kill list, extension, ransom note name, C2 URL |
| `BlackCatConfig.py` | PE (Rust) | Plaintext JSON embedded in Rust binary (Rust doesn't strip string sections) | Extension, kill list, exclusion paths, C2 URL, public key |
| `REvil_SodinokibiConfig.py` | PE | RC4-encrypted JSON with documented key derivation | C2 domain list, public key, campaign ID, exclusion paths |
| `ContiConfig.py` | PE | RC4-encrypted blob with hardcoded key pattern | C2 IP:port list, RSA public key, AES key |
| `AkiraConfig.py` | PE (Go) | Go binary with JSON config — Akira uses documented config structure | File extensions, exclusion paths, ransom note name |
| `BlackBastaConfig.py` | PE | Config in PE overlay after RSA public key block | Kill list, excluded paths, bot ID |

---

## Tier 2 — Living-off-the-Land / Fileless Behavioral Patterns

| Parser | Target | Extracts |
|--------|--------|----------|
| `WMIPersistenceConfig.py` | ALL | WMI filter query (EventFilter), consumer command (CommandLineTemplate/ScriptText), event name |
| `ScheduledTaskConfig.py` | XML, ALL | Task action (Execute + Arguments), trigger type, author, run-as user |
| `RegistryPersistenceConfig.py` | PE, PS1 | Run/RunOnce paths, AppInit_DLL paths, IFEO debugger paths embedded in dropper |
| `DefenderExclusionConfig.py` | PE, PS1 | Add-MpPreference -ExclusionPath / -ExclusionProcess strings |
| `AMSIPatchConfig.py` | PS1, PE | AmsiScanBuffer patch bytes, amsi.dll load / patch patterns |
| `ETWPatchConfig.py` | PS1, PE | ETW patch patterns (NtTraceEvent nulling, EtwEventWrite patching) |
| `COMHijackConfig.py` | PE | COM CLSID registration paths embedded in droppers for persistence |

---

## Tier 2 — Delivery Mechanism Parsers

| Parser | Target | Extracts |
|--------|--------|----------|
| `MacroExtractor.py` | DOC, XLS, XLSM, DOCM | VBA source code, embedded URLs, Shell/CreateObject calls |
| `ISOLNKChain.py` | ISO/LNK combo | LNK arguments inside ISO image, download URL |
| `HTMLSmugglingDetector.py` | HTML, HTM | `navigator.msSaveBlob`, `<a download>` data URI, base64 blob content |
| `OneNoteEmbedDetector.py` | ONE | OneNote EmbeddedFile paths, attachment click-to-run scripts |
| `MSHTAConfig.py` | HTA | Inline VBScript/JScript C2 URLs, download cradle |
| `WSFPolyglotConfig.py` | WSF | Polyglot WSF files embedding PS/VBS with C2 URLs |
| `RegSvrConfig.py` | DLL, PS1 | regsvr32 /s /n /i:URL scrobj.dll patterns (Squiblydoo) |

---

## Tier 2 — Cloud / SaaS C2 Abuse

Modern C2 frameworks increasingly abuse legitimate cloud services to hide traffic.
Detection must focus on the CLIENT-SIDE config (what URL/service is called) not on
the server (which looks like legitimate traffic to network defenders).

| Parser | Target | Extracts |
|--------|--------|----------|
| `SlackC2Config.py` | ALL | Slack webhook URL + token from C2 configs using Slack API for command delivery |
| `TeamsDriveC2Config.py` | ALL | SharePoint/OneDrive API URLs + access tokens used for exfil or C2 |
| `GoogleSheetC2Config.py` | ALL | Google Sheets/Drive API credentials for C2 (e.g., DoH via Google APIs) |
| `DropboxC2Config.py` | ALL | Dropbox API tokens used for file-based C2 (upload tasks, download results) |
| `GitHubC2Config.py` | ALL | GitHub personal access tokens (PAT) used for Gist-based C2 |
| `PastebinC2Config.py` | ALL | Pastebin API keys + paste IDs used as dead-drop C2 staging |

Detection note: these configs are often visible in plaintext (API tokens) even in
compiled binaries — TelegramC2Config.py and DiscordExfilConfig.py demonstrate the
pattern for Telegram and Discord respectively.

---

## Tier 3 — Specialized / Post-Compromise

| Parser | Target | Extracts |
|--------|--------|----------|
| `CryptoMinerConfig.py` | PE, UNKNOWN | Stratum pool URL, wallet, worker name, algorithm, thread count |
| `MetasploitPayload.py` | PE, UNKNOWN | LHOST, LPORT from Metasploit shellcode — XOR-encoded with known offsets |
| `BitsadminPersistenceConfig.py` | PS1, BAT | BITS job name, download URL, destination path |
| `KerberoastConfig.py` | PS1 | SPN targets, ticket requests embedded in PS Kerberoasting scripts |
| `DCsyncConfig.py` | PS1, PE | DRSUAPI replication source DC, target account — DCsync attack config |
| `AntiAnalysisStrings.py` | PE | VM/sandbox names, analyst tool names the binary checks — confirms malware-awareness |

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
3. **Add entry to `parser_config.yml`** here AND in `tools/mwcp/lib/mwcp/parser_config.yml` (required — see §1 above)
4. Add to `mwcp_scan.py` `_select_parsers()` type map and `known_generic` set
5. Add TP/FP samples to `test/windows/lab_mwcp/generate_samples.py` and write tests
6. Run `pytest test/test_53_mwcp_parsers.py` and `Invoke-Pester test/windows/lab_mwcp/` — both must pass
7. Add parser to `README.md` once validated
8. Rebuild: `Build-OfflineToolkit.ps1 -IncludeMWCP` stages parsers + updated config to tools/
