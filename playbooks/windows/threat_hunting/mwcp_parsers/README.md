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

## Adding a New Parser

See [ROADMAP.md](ROADMAP.md) for the parser backlog and the critical requirements for mwcp 3.x
compatibility (`.data` not `.file_data`, `report.as_dict()['metadata']` extraction, etc.).

**Workflow:**

1. Write `MyParser.py` in this directory
2. Add entry to `parser_config.yml` here (the source of truth)
3. Copy both to `tools/mwcp/lib/mwcp/parsers/` and update `tools/mwcp/lib/mwcp/parser_config.yml`
4. Add parser name to `mwcp_scan.py` `_select_parsers()` type map and `known_generic` set
5. Add TP/FP samples to `test/windows/lab_mwcp/generate_samples.py`, regenerate, and write tests
6. Run `pytest test/test_53_mwcp_parsers.py` and `Invoke-Pester test/windows/lab_mwcp/` -- both must pass
7. Rebuild full toolkit: `Build-OfflineToolkit.ps1 -IncludeMWCP`
