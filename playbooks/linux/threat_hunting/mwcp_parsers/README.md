# IR Toolkit Linux mwcp_parsers

Family-specific structured config/indicator extraction for Linux carved memory
regions and on-disk binaries. Same directory name and per-family-file organization as
[`playbooks/windows/threat_hunting/mwcp_parsers/`](../../windows/threat_hunting/mwcp_parsers/README.md),
same detection discipline -- but not an mwcp parser: it has no dependency on the mwcp
package, so the Linux offline toolkit carries no extra runtime dependency. Every
parser is a plain `bytes -> dict` function, run by `driver.extract_all()` -- called from
`memory_enrich.py` (carved memory, `source='memory'`) and `edr_hunt.py`'s
`check_mwcp_structural_configs` (on-disk binaries of already-distrusted PIDs,
`source='on-disk'`). `driver.to_findings(hits, where, source=...)` puts that tag in the
finding's `Type` string so a live-host static-pass finding never claims to be a
memory-carve result.

**Detection basis**: 2+ independent structural/mechanical/behavioral signals intrinsic
to how the technique or tooling actually works -- wire-format field names an operator
cannot rename without breaking their own server's compatibility, CLI argument schemas
baked into shared source code, cryptographic capability mismatches, protocol
requirements. Never check for a family/tool's own name or brand string as part of
`identify()` -- a name is only ever an output label describing what the corroborated
mechanism looks like.

---

## Category layout

| Category | What it covers |
|---|---|
| `c2_frameworks/` | Cross-platform red-team/post-ex frameworks with real Linux agent builds (Sliver, Mythic, Merlin, Havoc, AdaptixC2, Pupy, generic Go C2) |
| `native/` | Linux/Unix-native malware families with no Windows equivalent (BPFDoor, Mirai/Gafgyt, Ebury, XMRig-class miners, SMTP-exfil) |
| `ransomware/` | Linux/ESXi ransomware -- cross-family mechanisms (VM-kill-before-encrypt, snapshot/backup destruction, generic indicators) plus named ports where the Linux build shares the same codebase as the corresponding Windows parser |
| `cloud_saas/` | Telegram/Discord/Slack/Dropbox/GitHub/Pastebin/Ngrok as C2/exfil channels -- OS-agnostic protocol-level detection |
| `delivery/` | Linux-native dropper/stager patterns (shell pipelines, base64-ELF) |
| `specialized/` | Narrowly-scoped technique detectors -- only signals a stdlib byte/string scanner can ground without disassembly (anti-analysis, DNS tunneling) |

Not covered here: Windows-registry/AMSI/ETW-specific fileless persistence (Linux's own
persistence/fileless techniques are covered by `edr_hunt.py`/`journal_analysis.py`,
not this catalog), and pure Active-Directory techniques (Kerberoast/DCsync/BloodHound)
that have no Linux-host-side artifact surface.

`parser_manifest.yml` is the full catalog (module, family label, detection basis).
It documents the registry; the actual registration is each category's `MODULES`
tuple in its own `__init__.py`, which `driver.py` imports directly.
`test/linux/lab_mwcp/test_manifest_matches_code.py` asserts the manifest and the code
never drift apart.

---

## Writing a parser

- Require 2+ independent signals in `identify()`. The family name is never one of
  them.
- Decode candidate byte transforms (XOR, etc.) with `bytes.translate()` using a
  precomputed 256-byte table per key, not a per-byte Python generator expression
  inside a brute-force search loop.
- Use one `re.IGNORECASE` per `re.compile()` at most. For a regex scanning a whole
  carved region rather than a small context window, prefer `data.lower()` once plus a
  lowercase-literal pattern.
- Bound every repeated byte-class group explicitly (`{1,200}`); never leave a bare
  `+`/`*` on attacker-controlled-length input.
- If two signals must be *related*, not just both present anywhere in a region, check
  co-occurrence inside a bounded context window (see `native/smtp_exfil.py`,
  `cloud_saas/discord.py`) rather than a bare "both substrings present somewhere"
  check.
- Add `\b` word boundaries around exact tokens where a bare substring could match
  inside a longer, unrelated one.
- When porting a named-family parser from the Windows catalog, only do it when the
  Linux/ESXi build is documented to share the same source or codebase as the Windows
  parser being ported from -- reuse its field/flag list as-is and say so in the
  docstring. Otherwise build a cross-family mechanism detector instead of guessing at
  brand-specific details.

## Adding a new parser

1. Write `my_parser.py` in the right category subfolder
   (`c2_frameworks/`, `native/`, `ransomware/`, `cloud_saas/`, `delivery/`,
   `specialized/`) exposing `identify(data: bytes) -> bool` and
   `extract(data: bytes) -> Optional[Dict[str, Any]]` (or, for a multi-hit family,
   just `extract(data) -> List[Dict[str, Any]]` with no separate `identify`).
2. Add it to that category's `__init__.py` `MODULES` tuple (single-hit) or
   `driver.py`'s `_MULTI_HIT_EXTRACTORS` (multi-hit).
3. Add an entry to `parser_manifest.yml` under the right category.
4. If the finding needs a distinct `Type`/`Severity`/`MITRE` mapping, add it to
   `driver.py`'s `_FAMILY_FINDING_SPEC` or the category-prefix routing in
   `to_findings()`.
5. Add TP/FP samples to `test/linux/lab_mwcp/generate_samples.py` and regenerate.
   Write tests in `test/linux/lab_mwcp/test_mwcp_parsers_lab.py`:

   | Test | What it proves |
   |------|-----------------|
   | `test_<parser>_identifies_tp` | `identify()`/`extract()` fires on the parser's own TP sample |
   | `test_<parser>_no_false_positive_on_fp_set` | `identify()` returns `False` on every file in `samples/fp/` |
   | `test_<parser>_single_signal_alone_not_enough` | Each documented signal held out alone still fails `identify()` |
   | `test_<parser>_end_to_end_via_driver` | `driver.extract_all()` + `to_findings()` produce the expected `Type`/`Severity` |
6. No separate performance test is needed --
   `test/linux/lab_mwcp/test_parser_performance.py` discovers every module in every
   category's `MODULES` tuple automatically and checks `identify()` completes quickly
   against a large adversarial buffer. If `identify()` does anything beyond a single
   bounded `.search()`, sanity-check it against a large input by hand first.
7. Run `pytest test/linux/lab_mwcp/ test/test_28_memory_linux.py` -- all must pass.
8. No build/staging step is required -- this package is plain Python used directly
   from its source location. `Build-OfflineToolkit-Linux.sh` records its presence,
   importability, and parser count in `STAGED_MANIFEST.json` as a build-time check.
