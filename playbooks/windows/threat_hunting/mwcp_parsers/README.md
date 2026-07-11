# IR Toolkit mwcp Parsers

DC3-MWCP 3.x extensions for automated C2 config extraction during Windows incident response.

These parsers run inside `mwcp_scan.py`, which is called by `memory_enrich.py` (carved injected
regions) and `Invoke-MWCPFileScan` (flagged on-disk files).  Each parser uses `identify()` to
quickly reject non-matching files, then `run()` to extract IOCs.

All detection is based on **structural protocol indicators** -- wire-format field names, binary
magic values, and API-required string clusters.  Operators cannot rename protocol-required fields
without breaking compatibility with their own C2 server.

---

## Generic Parsers (run against every file)

### GenericMutex

Scans any file for mutex creation patterns: `CreateMutexA` API name in close proximity to a
hex-format token string (8-32 hex chars).  Captures mutex names that are pivot indicators across
incidents -- the same mutex token in two separate victims links them to the same operator.

**Identifies:** Proximity of `CreateMutexA` + 8-32 hex character string.
**Extracts:** Mutex names.

---

### GenericC2

Extracts C2 infrastructure from any file: non-private IP:port patterns, HTTP/HTTPS/FTP URLs, and
domain names with routable TLDs.  Filters RFC-1918 private ranges and localhost addresses.

**Identifies:** Always runs.
**Extracts:** C2 addresses (IP:port), URLs, domain names.

---

### PowerShellDecoder

Detects and decodes PowerShell `-EncodedCommand` / `-enc` stagers embedded in any file type.
Decodes the UTF-16LE base64 payload and emits the cleartext command, which typically contains
the download cradle URL and stage-2 location.

**Identifies:** `-enc` / `-EncodedCommand` flag + valid base64 UTF-16LE payload.
**Extracts:** Decoded PS command, embedded URLs.

---

### LNKParser

Parses Windows LNK shortcut files (MS-SHLLINK binary format).  The `COMMAND_LINE_ARGUMENTS`
field is where threat actors embed their payload commands -- LNK files used as delivery vectors
always have the actual payload in this field.

**Identifies:** MS-SHLLINK magic bytes (`4C 00 00 00`) + Link CLSID.
**Extracts:** Command-line arguments, embedded URLs.

---

### TelegramC2Config

Extracts Telegram bot tokens (`<8-10 digit ID>:<35 char token>`) from any file type.  The token
format is mandated by the Telegram BotAPI -- all families embedding Telegram C2/exfil must use
this exact format.  Covers Redline, Vidar, Agent Tesla, AsyncRAT variants, and custom stagers.

The extracted token is **directly actionable**: `https://api.telegram.org/bot<TOKEN>/getUpdates`
returns the message history of the C2 channel.

**Identifies:** Always runs.
**Extracts:** Bot token (password), API URL, chat ID.

---

### DiscordExfilConfig

Extracts Discord webhook URLs from any file type.  Discord webhooks follow a fixed API format:
`https://discord.com/api/webhooks/<server_id>/<token>` where the server ID is a Snowflake integer.
Widely used by commodity stealers (Redline, Raccoon, AsyncRAT variants) for screenshot and
credential exfil without requiring a dedicated C2 server.

**Identifies:** Always runs.
**Extracts:** Webhook URL, server ID, token (password).

---

## C2 Framework Parsers

### CobaltStrikeConfig

Decodes CobaltStrike beacon configurations from the XOR-encoded binary config block embedded in
every beacon PE.  The `ID|type|length|value` structure is a wire-protocol requirement: the team
server cannot parse beacon check-ins without it.  Detection does not rely on any "CobaltStrike"
name string that operators strip.

**Identifies:** XOR-encoded config block with valid `ID|type|len|value` tuple structure.
**Extracts:** Sleep time, jitter, C2 host/URI, UserAgent, Host header, SpawnTo path, named pipe,
BeaconType, RSA public key.

---

### SliverConfig

Extracts Sliver C2 agent configuration from compiled Go binaries.  Sliver embeds its config as
JSON.  The wire-protocol field names (`implant_name`, `c2s`, `reconnect_interval`) are required by
the Sliver server gRPC handler -- renaming them breaks session establishment.  The `mtls://` and
`wg://` transport prefixes are unique to Sliver.

**Identifies:** Wire-protocol JSON fields (`implant_name`, `c2s`, `reconnect_interval`) and/or
`mtls://` / `wg://` transport scheme.
**Extracts:** C2 URL, implant name (pivot), reconnect interval, mTLS cert fingerprint.

---

### HavocConfig

Extracts Havoc C2 daemon configuration.  Havoc uses `0xDEADBEEF` as a binary magic value at the
start of its config region, followed by a valid config size field.  This is the frame marker for
the Havoc wire protocol -- the team server uses it to locate the agent's session parameters.

**Identifies:** `0xDEADBEEF` magic + valid config_size, or protocol field names (`DemonID`,
`SleepTime`, `Injection`).
**Extracts:** C2 host, sleep/jitter, injection technique.

---

### BruteRatelConfig

Extracts Brute Ratel C4 (BRc4) badger configuration.  BRc4's SMB C2 uses `\\.\pipe\ratel` as
a named pipe -- this name is hardcoded in the BRc4 SMB transport and cannot be changed without
recompiling the server.  HTTP/S C2 profiles are extracted via URL patterns.

**Identifies:** Named pipe `\pipe\ratel` (SMB transport) or BRc4 internal function names.
**Extracts:** C2 URL, named pipe, sleep time, mutex.

---

### MythicConfig

Extracts Mythic C2 agent configurations from any Mythic agent (Poseidon, Apollo, Athena, Thanatos,
Medusa, etc.).  Mythic's C2 profile specification requires these exact JSON field names -- the
Mythic server refuses agent callbacks missing them.  Uses a brace-counting JSON scanner to handle
nested `c2_profiles` objects that regex cannot.

**Identifies:** 2+ required C2 profile fields (`PayloadUUID`, `callback_interval`, `c2_profiles`,
`AES_PSK`, `encrypted_exchange_check`).
**Extracts:** C2 host, PayloadUUID (pivot via mutex), callback interval, AES PSK.

---

### MerlinConfig

Extracts Merlin C2 agent configurations from Go binaries.  Merlin's JSON config uses
protocol-required field names (`psk`, `skew`, `maxRetry`, `proto`, `padding`) that the Merlin
server validates during agent registration.

**Identifies:** Protocol-required JSON fields (`psk`, `skew`, `maxRetry`, `proto`, `padding`).
**Extracts:** C2 URL, pre-shared key (PSK), protocol, JA3 fingerprint, max retry count.

---

### AdaptixC2Config

Extracts Adaptix C2 agent configurations (framework released 2023+).  Adaptix agents embed their
config as JSON.  The `agent_id` + `callback_url` combination is protocol-required and specific to
Adaptix -- `callback_url` alone is too broad.

**Identifies:** Both `agent_id` AND `callback_url` present in same data region.
**Extracts:** C2 URL, agent ID (pivot via mutex), C2 profile name, callback interval/jitter.

---

## PowerShell C2 Stager Parsers

### PoshC2Config

Extracts PoshC2 stager configurations from PowerShell files.  PoshC2's module API requires the
stager to define specific PowerShell variables (`$server`, `$URLS`, `$Payload`, `$kill_date`) --
the PoshC2 implant code references these by exact name.

**Identifies:** 2+ of the required PoshC2 PS variable names in a PS1 file.
**Extracts:** C2 URL, payload URLs, kill date, proxy settings.

---

### PowGratConfig

Extracts PowGrat stager configurations from PowerShell files.  PowGrat's server-side handler
requires the stager to define `$C2Server`, `$C2Port`, and `$Password` -- the server authenticates
the stager session using these exact variable names.

**Identifies:** `$C2Server` AND `$C2Port` both present in data.
**Extracts:** C2 server URL, port, session password.

---

## RAT Config Parsers

### NjRATConfig

Extracts NjRAT (Bladabindi) configuration from any file type.  NjRAT stores its config as a
pipe-delimited ASCII string: `host|port|key|campaign|mutex|` -- this format is the plaintext
protocol config read by both the builder and the stub at startup.

**Identifies:** Pipe-delimited ASCII with numeric 2nd field (port) and additional pipe-separated
segments.
**Extracts:** C2 host:port, campaign tag (pivot), mutex name, registry key.

---

### AsyncRATConfig

Extracts AsyncRAT (and DcRAT/VenomRAT codebase variant) configuration from .NET PE files.
AsyncRAT stores config as .NET resource strings in a cluster: `Hosts`, `Ports`, `Version`,
`Mutex`, `Certificate`, `BDOS`, `Group`, `Delay`, `Install`, `Anti`.  Any 3+ of these within a
4KB window identifies the config region.

**Identifies:** 3+ AsyncRAT key strings within a 4KB window in a PE or memory region.
**Extracts:** C2 host:port, mutex, version, group/campaign tag.

---

### DcRATConfig

Extracts DcRAT (Dark Crystal RAT) and VenomRAT configurations.  DcRAT is an AsyncRAT fork that
adds two protocol-required fields: `HVNC` (Hidden VNC capability) and `Serversignature` (RSA
server certificate fingerprint used for mutual authentication).  These two fields are absent from
vanilla AsyncRAT and cannot be removed without breaking DcRAT server-side features.

**Identifies:** AsyncRAT-style key cluster + `HVNC` or `Serversignature` present.
**Extracts:** C2 host:port, mutex, version, campaign group, server signature (pivot).

---

### XWormConfig

Extracts XWorm RAT configurations.  XWorm uses a similar structure to AsyncRAT but has distinct
field names: `Ver` (not `Version`), `BSOD` (not `BDOS`), and `Hwid` (not in AsyncRAT).  The
`XWorm` version banner string also appears in the binary.

**Identifies:** `XWorm` marker string AND key cluster with 3+ XWorm-specific fields.
**Extracts:** C2 host:port, mutex, version, group tag.

---

### QuasarRATConfig

Extracts Quasar RAT configurations from .NET PE files.  Key differentiator from AsyncRAT: Quasar
uses `Port` (singular) rather than `Ports`, `Password` (the AES-128 key seed), and `Tag` (campaign
label).  These field names are part of Quasar's .NET resource schema.

**Identifies:** `Port` (singular, not `Ports`) + `Password` + 3+ cluster keys within 4KB.
**Extracts:** C2 host:port, mutex (GUID), AES key seed (password), campaign tag, version.

---

## Stealer / Exfil Config Parsers

### SMTPExfilConfig

Extracts SMTP exfiltration credentials from PE files and memory regions.  Commodity stealers
(Agent Tesla, FormBook, HawkEye) embed SMTP host, port, username, and plaintext password to
exfiltrate keylog/credential data.  Requires `len(data) >= 32`.

**Identifies:** SMTP host pattern (`smtp.*` / `mail.*`) + port (25/465/587/2525) + email address
within 512 bytes.
**Extracts:** SMTP host:port (C2 address), username/from address, plaintext password.

---

### AgentTeslaConfig

Extracts Agent Tesla keylogger/stealer configurations.  Agent Tesla supports SMTP, FTP, and
Telegram exfil.  Detection uses a two-of-three scoring model:

| Indicator | Score |
|-----------|-------|
| `Agent Tesla` / `AgentTesla` product name in binary | +2 |
| `GetKeyboardState` / `GetAsyncKeyState` keylogger import | +2 |
| `ProductionModeKey` licensing field | +1 |
| SMTP cluster (host + port + email within 512 bytes) | +1 |
| FTP URL (`ftp://`) | +1 |

Score >= 2 triggers identification.

**Extracts:** SMTP host:port (C2 address), SMTP/FTP password, family label, keylogger confirmation.

---

### AdaptixC2Config

*(see C2 Framework Parsers above)*

---

### DeimosConfig

Extracts Deimos C2 agent configurations. Deimos's agent registration schema requires specific
JSON field names (`CallbackURL`, `Interval`, `PubKey`, `AgentID`, `UserAgent`) -- these are not
the string "Deimos", which operators can and do strip.

**Identifies:** 2+ of the required JSON field names present in the binary.
**Extracts:** C2 URL, agent ID (pivot via mutex), beacon interval, public key snippet.

---

### IcedIDConfig

Extracts IcedID (BokBot) botnet C2 domains from the PE overlay. IcedID stores its config as a
length-prefixed, high-entropy RC4-encrypted blob appended to the binary; the key is drawn from a
small candidate search over bytes adjacent to the blob rather than assumed.

**Identifies:** Length-prefixed overlay blob that RC4-decrypts (candidate-key search) into 2+
domain-shaped strings.
**Extracts:** C2 domains, blob-size/domain-count summary.

---

### QakBotConfig

Extracts QakBot (Qbot) C2 IP-list configs. QakBot embeds a fixed-record, single-byte-XOR-encoded
fallback IP:port list; the entire candidate is invalidated if any decoded record fails to parse
as a routable IPv4 + plausible port, avoiding the high-FP trap of "any XOR key that produces some
readable bytes."

**Identifies:** Brute-forced single-byte XOR key that decodes 6+ contiguous 8-byte records, each a
valid routable IPv4 + port from a curated plausible-port set.
**Extracts:** C2 IP:port pairs, record-count summary.

---

### EmotedConfig

Extracts Emotet C2 IP-list configs. Same fixed-record XOR mechanism as QakBotConfig, tuned to
Emotet's larger static fallback list (8+ records required instead of 6).

**Identifies:** Brute-forced single-byte XOR key that decodes 8+ contiguous 8-byte
IPv4+port records, all valid.
**Extracts:** C2 IP:port pairs, fallback-list-size summary.

---

### MacroPackConfig

Detects auto-generated obfuscated macro/script loaders (the shape MacroPack and similar
macro-generation frameworks emit), independent of which generator produced the file. Detection
targets the structural fingerprint required for the payload to execute, not any tool watermark.

**Identifies:** Auto-exec entry point + char-code string-reconstruction loop (`Chr()` loop or
delimited `Split()` array) + shell-out primitive, all three in the same file.
**Extracts:** Entry point / reconstruction / shell-out summary, embedded URLs.

---

### RemcosConfig

Extracts Remcos RAT configurations from the `SETTINGS` PE resource. Remcos stores its config as
an RC4-encrypted, semicolon-delimited record inside a resource with this literal name -- the
resource name is part of the Remcos builder's fixed output format.

**Identifies:** `SETTINGS` PE resource decrypts (candidate-key search) into an 8+-field
semicolon-delimited record with a valid TCP port in field 2.
**Extracts:** C2 host:port, config password, mutex/campaign token.

---

### NanoCoreConfig

Extracts NanoCore RAT configurations from .NET PE files. NanoCore's config is a .NET
deserialization object graph with fixed field names required by the client's own deserializer.

**Identifies:** 4+ of the NanoCore .NET field names (`BuildTime`, `Mutex`, `Group`,
`RunOnStartup`, `RequestElevation`, `ConnectionPort`, `PrimaryConnectionHost`,
`KeepAliveTimeout`) clustered within a 4KB window.
**Extracts:** C2 host:port, mutex, campaign/group tag.

---

### RedlineConfig

Extracts Redline Stealer configurations. Redline's config is base64-encoded XML; a decode
producing well-formed XML with 2+ child elements and an embedded IP:port or URL is required --
guessed/partial decodes are rejected.

**Identifies:** Base64 candidate decodes to well-formed XML (2+ child elements) containing an
IP:port or URL.
**Extracts:** C2 address (IP:port or URL), decoded XML content.

---

### VidarConfig

Extracts Vidar Stealer C2 configuration from the PE overlay. Vidar's overlay config region is
low-entropy plaintext (unlike a packed/compressed section) containing either an HTTP(S) C2 URL or
a Telegram fallback channel reference.

**Identifies:** Low-entropy (<=6.5 bits/byte) overlay region containing an HTTP(S) URL or a
Telegram (`t.me`/`telegram.me`) reference.
**Extracts:** C2 URLs, Telegram fallback reference.

---

### LummaConfig

Extracts Lumma Stealer C2 configuration from the PE overlay. Lumma stores multiple NUL-separated
base64 tokens in the overlay; a single decodable token is not sufficient evidence (base64-shaped
noise is common), so 2+ independently-decoding-to-a-URL tokens are required.

**Identifies:** 2+ NUL-separated base64 tokens in the overlay, each independently decoding to a
well-formed http(s) URL.
**Extracts:** C2 URLs, decoded-URL count summary.

---

### StealcConfig

Extracts Stealc Stealer configuration. Requires the HTTP `Content-Type` header used by Stealc's
exfil POST request AND URL proximity, AND a Chromium/Firefox credential-schema signature
(`origin_url`/`username_value`/`password_value` columns, or `moz_logins`) as a second, independent
credential-harvesting mechanism -- neither the header nor the URL alone is exclusive enough.

**Identifies:** Content-Type header + URL proximity + Chromium/Firefox credential-schema regex.
**Extracts:** C2 URL, credential-schema match summary.

---

### RaccoonConfig

Extracts Raccoon Stealer configuration (v1 overlay-URL and v2 Telegram-Bot-API variants). The v2
branch keys on the Telegram Bot API token format (protocol-required, sufficiently specific alone);
the v1 branch additionally requires the same credential-schema corroboration as StealcConfig.

**Identifies:** v2: Telegram Bot API token format. v1: overlay URL + Chromium/Firefox
credential-schema regex.
**Extracts:** C2 URL/Telegram bot token, credential-schema match summary.

---

## Ransomware Parsers

### RansomwareIndicators

Family-agnostic universal ransomware indicator extractor. Requires 2+ of three independent
mechanical signals so that no single common artifact (which could appear in benign software)
triggers on its own.

**Identifies:** 2+ of {RSA public key DER block, VSS/recovery-disable command syntax, dense
file-extension-list cluster}.
**Extracts:** RSA public key, VSS/recovery command, extension-cluster summary.

---

### LockBitConfig

Extracts LockBit 3.0 (Black) builder configuration. The leaked LockBit 3.0 builder continues to
circulate and get reused independent of LockBit's own operational status post-Operation Cronos.

**Identifies:** 4+ of 8 leaked-builder JSON field names (`encrypt_filename`, `kill_processes`,
`local_disks`, `network_disks`, `note_full_paths`, `anti_debug`, `kill_services`, `impers_priv`).
**Extracts:** Builder config field summary.

---

### BlackCatConfig

Extracts BlackCat/ALPHV ransomware configuration.

**Identifies:** 4+ of 10 BlackCat/ALPHV JSON schema fields (`config_id`, `public_key`,
`extension`, `note_file_name`, `kill_services`, `kill_processes`, `exclude_directory_names`,
`exclude_file_names`, `exclude_file_extensions`, `strict_include_paths`).
**Extracts:** Config field summary.

---

### REvil_SodinokibiConfig

Extracts REvil/Sodinokibi ransomware configuration.

**Identifies:** 4+ of 8 short-key JSON fields (`pk`, `pid`, `sub`, `dbg`, `wht`, `nname`, `net`,
`exp`).
**Extracts:** Config field summary.

---

### ContiConfig

Extracts Conti ransomware configuration from its leaked-source argument parser. Conti's code
lineage lives on in Royal and other successor families sharing the same argument schema.

**Identifies:** `-m local|net|all|backups` mode flag AND at least one sibling flag (`-p`, `-size`,
`-nomutex`, `-log`).
**Extracts:** Mode + flag summary.

---

### AkiraConfig

Extracts Akira ransomware configuration.

**Identifies:** `--encryption_percent` AND at least one sibling flag (`--encryption_path`,
`--share_file`, `-p`).
**Extracts:** Flag summary.

---

### BlackBastaConfig

Extracts Black Basta ransomware runtime-key configuration.

**Identifies:** `-key <base64>` runtime argument AND (RSA public key DER block OR VSS command).
**Extracts:** Runtime key, RSA/VSS corroboration summary.

---

## Living-off-the-Land / Fileless Persistence Parsers

Dropper-embedded detectors for persistence/evasion mechanisms that do not require a compiled
payload -- all require 2 independent signals (a Windows-fixed key/API/schema name is never
sufficient alone since it is not, by itself, evidence of malicious intent).

### WMIPersistenceConfig

**Identifies:** WQL trigger clause (`SELECT...FROM __InstanceCreationEvent` etc.) AND a consumer
payload field (`CommandLineTemplate`/`ScriptText`/`ScriptingEngine`).
**Extracts:** WMI persistence command, trigger/consumer summary.

### ScheduledTaskConfig

**Identifies:** `<Exec><Command>` action whose `<Arguments>` contain both a hidden-window flag
(`-WindowStyle Hidden`/`-w hidden`) AND an encoded-command flag (`-EncodedCommand`/`-enc`).
**Extracts:** Command, arguments, stealth-action summary.

### RegistryPersistenceConfig

**Identifies:** Run/RunOnce/AppInit_DLLs/IFEO-Debugger key path string AND a value pointing at a
user-writable staging directory.
**Extracts:** Registry key, staging-path value.

### DefenderExclusionConfig

**Identifies:** `Add-MpPreference -ExclusionPath/-ExclusionProcess/-ExclusionExtension` cmdlet
call AND the exclusion target being a staging-directory path.
**Extracts:** Exclusion target, staging-path summary.

### AMSIPatchConfig

**Identifies:** `E_INVALIDARG` force-return patch bytes (`B8 57 00 07 80 C3`) near an
`AmsiScanBuffer` reference.
**Extracts:** Patch-offset summary.

### ETWPatchConfig

**Identifies:** No-op return patch bytes (`33 C0 C3`) near an `EtwEventWrite`/`NtTraceEvent`
reference.
**Extracts:** Patch-offset summary.

### COMHijackConfig

**Identifies:** `CLSID\{GUID}\InProcServer32` key structure AND its DLL value targeting a staging
directory.
**Extracts:** DLL path, staging-path summary.

---

## Delivery Mechanism Parsers

Initial-access document/container/script detectors -- all require 2 independent signals.

### MacroExtractor

**Identifies:** Auto-exec entry point AND a Win32 API `Declare` statement for a download/execute
primitive (`URLDownloadToFile`/`ShellExecute`/`WinExec`).
**Extracts:** Entry point + API summary, embedded URLs.

### ISOLNKChain

**Identifies:** ISO9660 PVD signature (`CD001` @ offset 32769) AND an embedded MS-SHLLINK (LNK)
structure -- the Mark-of-the-Web bypass delivery chain shape.
**Extracts:** ISO/LNK offset summary.

### HTMLSmugglingDetector

**Identifies:** Blob-construction JS API (`msSaveOrOpenBlob`/`new Blob([...`) AND a payload-sized
(4KB+) inline base64 blob.
**Extracts:** Blob-API + payload-size summary.

### OneNoteEmbedDetector

**Identifies:** OneNote file-format header GUID AND an embedded `FileDataStoreObject` whose
filename has an executable-shaped extension.
**Extracts:** Embedded attachment filename.

### MSHTAConfig

**Identifies:** Network-capable COM ProgID instantiation (`Msxml2.XMLHTTP`/`ServerXMLHTTP`) AND a
URL literal in the same HTA.
**Extracts:** C2 URL, COM ProgID summary.

### WSFPolyglotConfig

**Identifies:** 2+ `<script language="...">` blocks with differing languages AND a
download/execute-capable COM object instantiation (`WScript.Shell`/`Shell.Application`/XMLHTTP).
**Extracts:** Language-count + primitive summary.

### RegSvrConfig

**Identifies:** The Squiblydoo pattern -- `regsvr32 /i:<URL> ... scrobj.dll`.
**Extracts:** C2 URL (the remote scriptlet), pattern summary.

---

## Cloud / SaaS C2 Parsers

Legitimate cloud services abused as a covert C2 channel -- all require the service's own
fixed token format/API endpoint AND actual usage evidence, not just a bare service reference.

### SlackC2Config

**Identifies:** Slack token (`xoxb-`/`xoxp-`/`xoxa-` prefix) AND a Slack API call target
(`slack.com/api/...` or `hooks.slack.com/services/...`).
**Extracts:** Slack token (credential), C2 URL.

### TeamsDriveC2Config

**Identifies:** Teams incoming-webhook URL (`*.webhook.office.com/webhookb2/...`) AND a
MessageCard/Adaptive Card JSON schema field.
**Extracts:** Webhook URL, card-schema summary.

### GoogleSheetC2Config

**Identifies:** Google Sheets API endpoint (`sheets.googleapis.com/v4/spreadsheets/...`) AND a
Google API key (`AIza...` fixed prefix/length format).
**Extracts:** API endpoint, Google API key (credential).

### DropboxC2Config

**Identifies:** Dropbox content API endpoint (`content.dropboxapi.com/2/files/upload|download`)
AND the `Dropbox-API-Arg` protocol-required header.
**Extracts:** API endpoint, header-presence summary.

### GitHubC2Config

**Identifies:** GitHub personal access token (`ghp_`/`github_pat_` fixed prefix format) AND a
GitHub API call target (`api.github.com/gists` or `/repos/...`).
**Extracts:** GitHub PAT (credential), API target.

### PastebinC2Config

**Identifies:** Pastebin raw-paste URL (`pastebin.com/raw/<8-char ID>`) AND an HTTP
fetch-and-consume primitive (`WebClient.DownloadString`, `Invoke-WebRequest`, `Msxml2.XMLHTTP`,
`URLDownloadToFile`).
**Extracts:** C2 URL, fetch-primitive summary.

---

## Tier 3 -- Specialized / Post-Compromise Parsers

### CryptoMinerConfig

**Identifies:** `stratum+tcp://`/`stratum+ssl://` pool URL AND either a Stratum JSON-RPC method
(`mining.subscribe`/`mining.authorize`) or XMRig-family CLI flags (`-u <wallet> -p <pass>`) --
the CLI-flag branch was added after a confirmed real-world coinminer command line
(`stratum+tcp://xcnpool.1gh.com:7333 -u <wallet> -p x`) used CLI syntax, not a JSON-RPC frame.
**Extracts:** Pool URL, wallet address (if present), RPC-method/CLI-flag summary.

### MetasploitPayload

**Identifies:** GetPC-stub-into-PEB-walk shellcode prologue (`FC E8 ... 60 89 E5 31 D2 64 8[AB]`)
AND an embedded `sockaddr_in` structure with a plausible IP/port.
**Extracts:** C2 address (LHOST:LPORT as `tcp://`), prologue/sockaddr summary.

### BitsadminPersistenceConfig

**Identifies:** `/SetNotifyCmdLine` BITS verb AND its target being a script interpreter or a
staging-directory path -- the T1197 persistence primitive, distinct from an ordinary staged
download.
**Extracts:** Notify-command target path.

### KerberoastConfig

**Identifies:** `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` (.NET TGS-request
class) AND an SPN LDAP enumeration filter (`(&(objectClass=user)(servicePrincipalName=*))`).
**Extracts:** Detection summary (collect-then-crack shape).

### DCsyncConfig

**Identifies:** DRSUAPI RPC interface UUID (`e3514235-4b06-11d1-ab04-00c04fc2dcd2`) AND an AD
replication extended-rights GUID (`DS-Replication-Get-Changes[-All]`).
**Extracts:** Detection summary + matched rights GUID.

### AntiAnalysisStrings

**Identifies:** 2+ distinct artifact categories referenced (virtualization platform / sandbox
agent / analyst tool process names) -- a single category match is not evidence (e.g. one benign
VMware-compatibility reference), only a cross-category cluster is.
**Extracts:** Matched category summary.

---

## Tier 4 -- Post-Exploitation / Commodity Crimeware Parsers

### LSASSDumpConfig

**Identifies:** `MiniDumpWriteDump` API reference (or the `comsvcs.dll` LOLBin `MiniDump` export)
AND an `lsass`/`lsass.exe` target-process reference in the same file.
**Extracts:** Detection summary (credential-dump tool shape).

### RubeusTicketConfig

**Identifies:** The `/ptt` (pass-the-ticket) inject flag AND an embedded KRB-CRED ASN.1 structure
(`\x76\x82` APPLICATION-22 tag).
**Extracts:** Detection summary (pass-the-ticket tool shape).

### PsExecServiceConfig

**Identifies:** The `PSEXESVC` named-pipe/service-name marker AND a service binary path targeting
a staging directory.
**Extracts:** Service binary path.

### BloodHoundCollectionConfig

**Identifies:** An LDAP wildcard enumeration filter (`(objectClass=*)`/`(objectCategory=*)`) AND
the AD Security-Descriptor control OID `1.2.840.113556.1.4.801` (LDAP_SERVER_SD_FLAGS).
**Extracts:** Matched filter + control OID summary.

### ClipboardHijackConfig

**Identifies:** `SetClipboardData` AND `GetClipboardData` API pair AND 2+ distinct cryptocurrency
address formats (BTC, ETH, Monero) present -- a single format alone is not sufficient.
**Extracts:** Matched address-format categories.

### DNSTunnelC2Config

**Identifies:** A TXT-record-specific DNS query construction (`Resolve-DnsName -Type TXT`,
`DnsQuery_A`/`DNS_TYPE_TEXT`) AND an oversized (32+ char) subdomain label drawn from the RFC 4648
base32 alphabet (`A-Z2-7`) -- base32 specifically, since DNS's own case-insensitivity is what
forces tunneling tools away from base64.
**Extracts:** Query construction + encoded label summary.

### NgrokTunnelConfig

**Identifies:** An `ngrok.io`/`ngrok-free.app`/`ngrok-free.dev` tunnel domain AND ngrok's own
agent config schema fields (`proto:`/`"proto":` paired with `addr:`/`"addr":`).
**Extracts:** C2 URL (tunnel domain), config-schema summary.

---

## Guidance for Writing a New Parser

See [ROADMAP.md](ROADMAP.md)'s "CRITICAL: Requirements" section for mwcp 3.x API-level gotchas
(`.data` not `.file_data`, `report.as_dict()['metadata']` extraction, parser registration). In
addition:

- Tag a `Credential`/other metadata element via `.add_tag('label')` after construction --
  `tags=` is not a constructor kwarg, and a bad kwarg raises inside `run()`, which mwcp swallows
  silently (0 results, no error).
- `\xNN` byte escapes always need exactly 2 hex digits -- write `[\x8a\x8b]`, not `\x8[ab]`.
- Only one `(?i)` flag per `re.compile()` call, and it must be at position 0 of the pattern.
- When a gap/separator pattern needs to allow a null byte (registry strings, wide-char text), use
  an explicit range that includes it (`[\x00-\x08]{0,8}`) -- `[^\x00]{0,8}` excludes it.
- Don't over-restrict byte ranges when capturing something like an IPv4 octet
  (`[\x01-\xfe]{4}` rejects `10.0.0.5`, a completely ordinary private IP) -- capture broadly
  (`[\x00-\xff]{4}`) and do plausibility filtering in Python after the match.
- Add `\b` word boundaries around exact filenames/tokens (`scrobj\.dll` alone also matches inside
  `notscrobj.dll`).
- If calling `mwcp.run()` directly (not through `mwcp_scan.py`), call
  `mwcp.register_entry_points()` first, or `run()` executes with no error but produces empty
  metadata.
- Wire a container-format parser (e.g. `DOC` macros) into `_PE_C2` too if its content could
  plausibly appear carved/decompressed without the native container header -- memory forensics
  carving frequently produces exactly that.
- Regex applied to the WHOLE file buffer: prefer `data.lower()` once + a case-sensitive
  lowercase-literal pattern over `(?i)` -- markedly faster on multi-MB input.
- Avoid unbounded repeated fixed-width groups (`(?:[A-Za-z0-9+/]{4}){1000,}`) -- use a possessive
  quantifier (`{1000,}+`, Python 3.11+) to prevent backtracking blowup.
- Never XOR-decode with a per-byte Python generator inside a brute-force offset/key search loop --
  precompute a `bytes.translate()` table per key and decode the whole window once per key instead.
- Never rescan all matches for every match to find a dense cluster (O(n^2)) -- use a sorted-offset
  sliding window (two-pointer) instead.
- Order multi-signal `identify()` checks cheapest/rarest first and return `False` immediately on
  the first miss, rather than evaluating every signal unconditionally.
- `test_63_mwcp_parser_performance.py` dynamically covers every parser automatically -- no extra
  step needed, but if `identify()` does anything beyond a single bounded `.search()`, sanity-check
  it against a large input by hand too.

---

## Adding a New Parser

See [ROADMAP.md](ROADMAP.md) for the parser backlog and the critical requirements for mwcp 3.x
compatibility (`.data` not `.file_data`, `report.as_dict()['metadata']` extraction, etc.).

**Workflow:**

1. Write `MyParser.py` in the appropriate category subfolder here (`generic/`, `c2_frameworks/`,
   `stagers/`, `rats/`, `stealers/`, `ransomware/`, `lol_fileless/`, `delivery/`, `cloud_saas/`,
   `specialized/`) -- every `identify()` must require 2+ independent structural/behavioral
   signals, never a single indicator (see the "CRITICAL" section of ROADMAP.md).
2. Add an entry to `parser_config.yml` here (the source of truth) using the full dotted path
   `<subfolder>.<ModuleName>.<ClassName>` -- the leading-dot shorthand does NOT support
   subfolders (see ROADMAP.md item #1).
3. `mwcp_scan.py` auto-resyncs every parser + `parser_config.yml` from this directory over the
   staged `tools/mwcp/lib/mwcp/parsers/` copy before each scan, so a fix here takes effect on the
   next scan without a manual copy or rebuild -- no separate staging step needed for local
   testing.
4. Add the parser name to `mwcp_scan.py` `_select_parsers()`'s relevant `type_specific` entry (or
   `_PE_C2` for PE/UNKNOWN) and to the `known_generic` set.
5. Add TP/FP samples to `test/windows/lab_mwcp/generate_samples.py` (a `_tp_myparser()` function
   returning bytes, wired into `main()`'s write list) and regenerate. Write
   `test_NN_mwcp_<category>_parsers.py` (next free number after the highest existing `test_5x`/
   `test_6x` mwcp file) with this exact class structure -- copy an existing file such as
   `test_58_mwcp_ransomware_parsers.py` as the template:

   | Test class | What it proves |
   |------------|-----------------|
   | `Test<Category>IdentifyTP` | `identify()` returns `True` on the parser's own TP sample |
   | `Test<Category>NoFalsePositives` | `identify()` returns `False` on every file in the shared FP set (`test/windows/lab_mwcp/samples/fp/`) |
   | `Test<Category>SingleIndicatorNotEnough` | Each documented signal held out ALONE still fails `identify()` -- proves the 2-signal requirement is real, not just claimed in the docstring |
   | `Test<Category>EndToEnd` | Full `mwcp_scan.py` subprocess invocation on the TP sample produces the expected `decoded` substring |
   | `Test<Category>EndToEndFP` | Full `mwcp_scan.py` subprocess invocation on FP samples produces no IOC |

   No separate performance test is needed per parser -- `test_63_mwcp_parser_performance.py`
   dynamically discovers every parser class in every category subfolder (via `pkgutil`, not a
   hardcoded list) and asserts `identify()` completes in under 3 seconds against a 10MB
   adversarial stress file (dense base64 runs, thousands of extension-shaped tokens, mixed-case
   text). A new parser is automatically covered the moment it exists; nothing to wire up. This
   test exists because 8 parsers built in one session passed every functional test yet hung a
   real 271-file KIMBAP verification sweep for 2+ hours at ~100% CPU -- root causes were `(?i)`
   case-folding across multi-MB buffers, an O(n^2) nested-loop cluster check, a brute-force XOR
   loop re-decoding the same bytes per offset instead of once per key, and a
   backtracking-prone repeated-group regex. Functional correctness on small synthetic samples
   said nothing about behavior on a realistic multi-MB carved memory region -- if `identify()`
   does anything past a single bounded regex `.search()` (brute-force loops, nested-quantifier
   regexes, per-offset re-decoding, O(n^2) cluster/sliding-window logic), sanity-check it against
   a large input by hand before relying on the perf test to catch it, and prefer `data.lower()` +
   a case-sensitive pattern over `(?i)` for any regex that scans the whole buffer.
6. Run the new pytest file, `test_63_mwcp_parser_performance.py`, and
   `Invoke-Pester test/windows/lab_mwcp/` -- all must pass.
7. Before merging: `Build-OfflineToolkit.ps1 -IncludeMWCP` to rebuild the offline staging bundle
   (preserves subfolder structure) for deployments that ship only `tools/mwcp/lib`, not the
   source tree.
