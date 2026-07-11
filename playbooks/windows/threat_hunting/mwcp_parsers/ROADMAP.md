# mwcp Parser Roadmap

Parsers in this directory extend DC3-MWCP beyond its bundled generic parsers.
`mwcp_scan.py` auto-resyncs every parser + `parser_config.yml` from this directory
over the staged `tools/mwcp/lib/mwcp/parsers/` copy before each scan, so changes
here take effect immediately. `Build-OfflineToolkit.ps1 -IncludeMWCP` performs the
same staging for offline-bundle deployments that ship only `tools/mwcp/lib`.

What is implemented and validated is documented in [README.md](README.md).
This file tracks only what is planned but not yet built.

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

## Tier 5 — Backlog (not yet built)

Every entry below requires 2+ independent structural/behavioral signals per
identify() — a single flag/field/string is never sufficient (see CRITICAL
Requirements below and [[feedback-detection-design]]). See the "Guidance for
Writing a New Parser" and "Lessons Learned" sections of [README.md](README.md)
before starting -- syntax/logic pitfalls and performance pitfalls actually
hit while building the current 68 parsers, worth avoiding from the start.

### Credential / identity abuse

| Parser | Target | Detection basis (2+ signals) | Extracts |
|--------|--------|-----------------|----------|
| `PassTheHashConfig.py` | PS1, PE | Mimikatz-style `sekurlsa::pth` invocation (or the `/run:` argument) AND a 32-hex-character NTLM-hash-shaped token in the same argument set -- an NTLM hash string alone is common in unrelated password-audit tooling output; only paired with the pass-the-hash run argument is it the attack shape | Target user, hash value (credential) |
| `AzureADDeviceCodeConfig.py` | PS1, PE | The Azure AD device-code OAuth2 endpoint (`login.microsoftonline.com/*/oauth2/*/devicecode`) AND a `refresh_token` grant-type reference -- device-code phishing tools (TokenTactics-style) request a token then immediately trade it for a long-lived refresh token, a combination ordinary interactive sign-in flows don't exhibit in static config/script form | Tenant/endpoint, grant-type summary |

### GPO / domain-wide abuse

| Parser | Target | Detection basis (2+ signals) | Extracts |
|--------|--------|-----------------|----------|
| `GPOAbuseConfig.py` | PS1, PE | A GPO GUID-path write (`\\<domain>\SYSVOL\...\Policies\{GUID}\...`) AND a scheduled-task or startup-script XML fragment embedded in the same file -- SharpGPOAbuse-style tooling writes both together; a bare SYSVOL path alone appears in benign GPO management scripts | GPO GUID, embedded task/script fragment |

Add new entries here once a genuinely mechanical (non-string, non-name)
detection basis is confirmed from 2+ independent sources (a public IR
writeup with byte/API-level detail, a leaked builder, or a validated
sample) -- per [[feedback-detection-design]], a single dated writeup is not
sufficient grounding on its own. Prefer 3+ corroborating signals over 2
where the technique genuinely offers them; 2 is the floor, not the target.

---

## CRITICAL: Requirements for writing parsers (hard-won — do not skip)

These were discovered through live debugging of mwcp 3.16.1. Violating any of them
produces silent 0-result failures with no error message.

### 1. Register in `parser_config.yml` — MANDATORY

Every custom parser needs an entry in `tools/mwcp/lib/mwcp/parser_config.yml`.
Without it, `mwcp.run('MyParser', ...)` silently rejects the name with debug log
`[dc3] Invalid name MyParser` — no exception, no report.errors, 0 results.

Parsers live in category subfolders (`generic/`, `c2_frameworks/`, `stagers/`,
`rats/`, `stealers/`, `ransomware/`, ...). The `.MyParser` leading-dot shorthand
only resolves to a **flat sibling module** of the top-level key (mwcp's
`registry._generate_parser_aux` does `group_name + parser_name` when it starts
with a dot) — it does **not** support subfolders. Use the full dotted path:

```yaml
MyParser:
  description: Brief description matching DESCRIPTION field
  author: IR_Toolkit
  parsers:
    - <subfolder>.MyParser.MyParser   # <subfolder>.<module>.<ClassName>, no leading dot
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

### 6. `mwcp_scan.py`'s parser-discovery must NOT be a filesystem listing

`mwcp_scan.py` builds its own `available` parser list once per batch, then
`_select_parsers()` filters it per file type. It used to do this via
`pkgutil.iter_modules(mwcp.parsers.__path__)` — a *non-recursive* listing of
`mwcp.parsers`'s immediate children. That broke silently, with zero errors,
the moment parsers moved into category subfolders: `iter_modules()` returned
the **subfolder names themselves** (`c2_frameworks`, `rats`, `stealers`, ...)
instead of the parser names nested inside them, so every subfoldered parser's
name never matched `_select_parsers()`'s lookups and it simply never ran —
`mwcp_scan.py` still exited 0 and returned a well-formed empty result, so
nothing looked wrong until a test asserted on the actual output. Confirmed
via the tailing log: `parsers=c2_frameworks,generic,ransomware,rats,stagers,stealers`
instead of real parser names.

Fixed by sourcing `available` from `mwcp.registry.get_sources()` +
`.config.keys()` instead — this reads the parsed `parser_config.yml` directly
with zero imports, independent of directory layout. Two earlier candidate
fixes were also tried and rejected: `mwcp.get_parser_descriptions()` eagerly
imports every registered parser (including unrelated DC3 built-ins with
unstaged optional deps, e.g. `pycdlib` for the ISO parser), and one such
`ImportError` — not wrapped as `mwcp`'s own `DependencyNotInstalled` — crashes
the whole call instead of being skipped.

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
1. Write `<category>/MyParser.py` in this directory (pick the matching category
   subfolder: `generic/`, `c2_frameworks/`, `stagers/`, `rats/`, `stealers/`,
   `ransomware/`, `lol_fileless/`, `delivery/`, `cloud_saas/`, `specialized/`,
   or a new one if it doesn't fit any existing category — `identify()` must
   require 2+ independent signals, never a single indicator)
2. **Add entry to `parser_config.yml`** here, using the full dotted path
   `<category>.MyParser.MyParser` (required — see §1 above; the `.MyParser`
   leading-dot shorthand does NOT work across subfolders)
3. No manual copy step needed for local testing — `mwcp_scan.py` auto-resyncs
   this directory + `parser_config.yml` over the staged
   `tools/mwcp/lib/mwcp/parsers/` copy before every scan (see the module
   docstring / `_resync_parsers()` in `mwcp_scan.py`)
4. Add the parser name to `mwcp_scan.py` `_select_parsers()`'s relevant
   `type_specific` entry (or `_PE_C2` for PE/UNKNOWN) and to the
   `known_generic` set — `available` is sourced from
   `mwcp.registry.get_sources()` + `.config.keys()`, so no filesystem-layout
   changes are needed there; see §6 above
5. Add TP/FP samples to `test/windows/lab_mwcp/generate_samples.py` and write
   a `test_NN_mwcp_<category>_parsers.py` covering identify(TP), FP-silence,
   single-indicator-insufficiency, and end-to-end extraction (identify()
   unit tests import via the dotted path too, e.g.
   `from c2_frameworks.MyParser import MyParser`)
6. Run the new pytest file and `Invoke-Pester test/windows/lab_mwcp/` — both must pass
7. Add parser to `README.md` once validated; remove it from this file's backlog
8. Before merging: `Build-OfflineToolkit.ps1 -IncludeMWCP` rebuilds the offline
   staging bundle (recursively, preserving subfolders) for deployments that
   ship only `tools/mwcp/lib`, not the source tree
