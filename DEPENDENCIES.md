# Dependency Inventory

Every external dependency the toolkit touches, its role, and **how it is satisfied for
offline/air-gapped operation**, across **Windows, Linux, and Cloud**. The live, machine-readable
copies are `tools/STAGED_MANIFEST.json` (Linux/Cloud - `Build-OfflineToolkit-Linux.sh --check-only`)
and the Windows manifest written by `Build-OfflineToolkit.ps1`.

**Key principle:** the toolkit's own code is platform-native with **no first-party package
dependencies** - Linux/Cloud is **Python 3 stdlib + bash only**; Windows is **native PowerShell**
(collection/detection/eradication invoke no Python). The only third-party *runtimes* are the
memory-analysis engines: **Volatility 3** (Linux, vendored as wheels) and **MemProcFS** (Windows,
staged) - plus the **YARA** engine on both.

Satisfaction legend: **bundled** (in repo) · **staged** (fetched by the build script into
`tools/`) · **vendored** (wheels in `tools/vol3_wheels/`) · **assumed** (OS-provided on the
target/analyst host - recorded, not bundled).

---

## Core collection + detection + reporting (Linux/Cloud)

| Dependency | Role | Satisfied by |
|---|---|---|
| `python3` (stdlib only) | every analyzer, adjudicator, report, LLM-review, custody | **assumed** (3.8+; no pip deps) |
| `bash`, coreutils | collection + eradication scripts | **assumed** |

## Memory analysis (analyst host, off-target) - `--include-memory`

| Dependency | Role | Satisfied by |
|---|---|---|
| `avml` | volatile-memory acquisition (LiME) | **staged** `tools/avml` (arch-aware) |
| `avml-convert` | decompress `--compress` (snappy) images before Volatility | **staged** `tools/avml-convert` |
| `volatility3` (+ `pefile`, `yara-python`) | the analyzer engine | **vendored** `tools/vol3_wheels/` → offline venv via `pip install --no-index` |
| `dwarf2json` | build the Volatility 3 Linux **ISF** from a debug `vmlinux` | **staged** `tools/dwarf2json` (arch-aware) |
| kernel **ISF / symbols** | version-EXACT kernel layout (a generic `vmlinux.h`/BTF will not work) | **staged** `tools/symbols/` via `--stage-symbols` (build while connected); else fetched at analysis time |
| YARA rules (Elastic, ReversingLabs, Neo23x0, **abuse.ch yaraify**) | `--yara` in-memory signature scan | **staged** `tools/yara_rules/<pack>/` via `--include-memory`. `linux_yara.py` drops PE/dotnet/macho-bound + Windows-API-only rules **by content** (~9,600 → ~400 Linux-applicable), declares the file-scan externals, and compiles per-file namespaces into one `.yarc` (an ELF canary proves the engine read memory). **Two engines:** `--yara-engine native` = yara-python over the whole image (fast, full physical coverage, no PID); `--yara-engine vol` = `linux_yara_worker.py` drives Volatility 3 **as a library** (init the 25GB layer once, then loop tasks in-process - *not* per-PID CLI, which re-inits ~130s/call) for **per-PID attribution + per-process timeout + rolling resumable JSONL**. |
| `yara-python` | compile + load the ruleset | **vendored** in `tools/vol3_wheels/` |
| `memory_enrich.py` (stdlib) | scan carved true-positive regions' strings (ASCII + UTF-16LE) for C2/Tor/crypto/exfil/cred IOCs → findings → `IOCs.json` + report; also IOC-sweeps FLOSS-deobfuscated strings | **stdlib only** (+ optional capa/FLOSS below) |
| **capa** + **FLOSS** (standalone) | capabilities/ATT&CK + **deobfuscated** strings over each carved injected region (auto-run by `memory_enrich.py`, `-f sc64 -j`) | **staged** `tools/capa/capa`, `tools/floss/floss` via `--include-memory` (Mandiant Linux release zips; capa bundles its rules) |
| **Binary Ninja** (free, containerized) | reverse-engineer carved injected regions (`--carve` keeps them in `tools/binja/data/`) | **built on demand** by `tools/binja/launch.sh` (downloads BN free; auto-handles podman/docker + X11/Wayland + SELinux; `binja/` is the only git-tracked part of `tools/`). Needs `podman`/`docker` + an X server. |
| `python3-venv`, `pip`, `unzip` | analyzer venv + rule-pack / capa-floss extraction | **assumed** |
| `debuginfod-find` (elfutils) | universal ISF fetch by build-id (connected staging) | **assumed** (optional) |
| `dpkg-deb` | extract a dbgsym `vmlinux` without root | **assumed** (Debian) |

### The symbols problem (why it's special)
Windows auto-fetches PDBs; Linux has no such service for arbitrary kernels. The ISF must match
the target kernel's exact build (struct offsets + symbol addresses + banner). Acquisition order
(`Build-LinuxSymbols.sh`): existing debug `vmlinux` → **debuginfod** (any distro, by build-id)
→ distro package manager (`apt`/`dnf`/`zypper`). For air-gapped analysis, run
`--stage-symbols --symbols-kernel <ver>` **while connected** to bake the ISF into `tools/symbols/`.

## Windows - `Build-OfflineToolkit.ps1`

The Windows workflow is **native PowerShell** (no Python for collection/detection/eradication).
Staged tools land in `tools/`; flags: `-IncludeMemory -IncludeMemProcFS -IncludeVolatility
-IncludeYaraRules -IncludeCapa -IncludeFloss -IncludeGeoIP -StageSymbols`.

| Dependency | Role | Satisfied by |
|---|---|---|
| PowerShell 5.1 / 7 | every collector, hunt, adjudication, eradication script | **assumed** (OS-provided) |
| Sysinternals (Autoruns, Sigcheck, Handle, ListDlls, PsTools, TCPView, Strings, ProcDump) | forensic collection | **staged** `tools/` |
| `go-winpmem` / WinPmem | memory acquisition (AFF4 default / RAW) | **staged** `tools/` (`-IncludeMemory`) |
| **MemProcFS** (`memprocfs.exe` + `vmmpyc`) + **Python 3.12 embeddable** | primary memory analysis (AFF4) | **staged** `tools/memprocfs/` (`-IncludeMemProcFS`) |
| Volatility 3 standalone (`vol.exe`) | secondary memory analysis (RAW/DMP) | **staged** `tools/vol.exe` (`-IncludeVolatility`) |
| **YARA** engine (`yara64.exe`, `yarac64.exe`) | file + memory signature scan / **rule compilation** | **staged** `tools/` |
| YARA rules (Elastic, ReversingLabs, Neo23x0, **abuse.ch yaraify**) | file + memory scan | **staged** `tools/yara_rules/<pack>/` (`-IncludeYaraRules`). `memory_yara.py` drops **non-Windows** rules by name, declares externals, and compiles with `yarac64` to one `.yac` (DOS-stub canary proves the scan ran). `Invoke-YaraFileScan` pre-screens rule files for non-ASCII bytes (yara64.exe rejects BOM and non-ASCII at line 1 on PS 5.1) and writes temp files without BOM. |
| `memory_enrich.py` (per-TP footprint) + **capa** + **FLOSS** | handles/persistence/lineage/network footprint, injected-region carve, capabilities/ATT&CK + deobfuscated strings, RAM↔USB first-seen correlation, **structural IOC validation** (recover over-captured domains; keep-and-label unverified TLDs), **confirmed-TP attack timeline** (`Timeline_Correlation.md` with Mermaid ATT&CK phase chain) | **staged** `tools/capa/capa.exe` (`-IncludeCapa`), `tools/floss/floss.exe` (`-IncludeFloss`); the module is PowerShell-invoked Python via the embeddable runtime |
| **DC3-MWCP** (DoD Cyber Crime Center Malware Configuration Parser) + **GenericMutex** + **GenericC2** parsers | binary config extraction from carved injected regions (memory analysis) and flagged on-disk files (`-ScanMWCP`): extracts mutex names, C2 addresses, dropped filenames, passwords/keys. Three-layer mutex detection: (1) runtime handle enumeration, (2) binary string/API-proximity scan, (3) family-specific config. `mwcp-verified` tag when sweep + binary analysis agree. **Hex token** bare mutex names (e.g. `1BA6BD98D9`) = high-confidence implant locks. `SM0:*:WilStaging_*` = APT camouflage; `SM0:*:WilError_*` = benign WIL tracking. | **staged** `tools/mwcp/lib/` (`-IncludeMWCP`); generic parsers copied from `playbooks/windows/threat_hunting/mwcp_parsers/` at staging time; uses bundled MemProcFS Python (`tools/memprocfs/python/python.exe`) — no system Python required |
| **GeoIP country DB** (db-ip.com Country Lite, keyless/CC-BY) | **offline** IP→country for each recovered IP (no DNS/whois/API); tags `IOCs.json` endpoints + the enrichment report | **staged** `tools/geoip/dbip-country-lite.csv.gz` (`-IncludeGeoIP`). A MaxMind GeoLite2-Country.mmdb may be dropped in instead. stdlib-only reader (gzip + bisect). |
| **vad_query.py** | One-shot vmmpyc VAD type lookup for Module 5 (Shellcode Thread) triage: resolves a thread start address to `anon_exec` (TP) / `image` (needs corroboration) / `unmapped` (unloaded DLL FP). Eliminates the need to run full memory_forensic.py for a single address. | **bundled** `playbooks/windows/threat_hunting/vad_query.py`; uses same MemProcFS Python environment |
| Windows debug symbols (PDBs) | Volatility 3 symbol resolution | **auto-fetched** from Microsoft on first run (or pre-staged with `-StageSymbols`) |
| LOLDrivers list | vulnerable-driver catalog | **staged** `tools/loldrivers.json` |
| `Get-NetTCPConnection`, `Register-ScheduledTask`, `Set-NetFirewallProfile` | egress-observation sensor (`Watch-Egress.ps1`) + deferred outbound blackhole (`Enforce-StrictFirewall.ps1 -BlockOutbound`) | **assumed** (OS-provided) |
| **Binary Ninja** (Linux container) | RE of carved regions — Windows **carves only**; analyze the portable `tools/binja/data/` output on a Linux desktop (the container is X11/Linux) | see Linux row + `planning/windows_binja_port.md` |

> Symbols are the inverse of Linux: Windows **auto-fetches PDBs** (no per-kernel ISF problem);
> Linux must build a kernel-exact ISF. YARA design is **twinned** - each platform compiles a
> verified ruleset and filters out the *other* platform's format-bound rules (Windows: PE-name +
> `yarac64`; Linux: `pe`/`dotnet`/`macho` imports by content + `yara-python`).

## Cloud workflow - `--include-cloud`

| Dependency | Role | Satisfied by |
|---|---|---|
| `aws`, `az`, `gcloud` | provider collection / snapshots / GuardDuty-SCC | **assumed** (too large to bundle) - or the **Docker image** bundles them |
| `kubectl` | Kubernetes RBAC / pod hunt | **assumed** / Docker image |
| `terraform` (or `tofu`) | provision WORM evidence storage (S3/Azure/GCS) | **assumed** / Docker image |
| LLM review | provider-native (Bedrock/Vertex/Azure OpenAI) or frontier/local | **stdlib `urllib`** - no SDK dependency |

## Containment / eradication (Linux target) - recorded, capability-gated

| Dependency | Role |
|---|---|
| `ip`, `nft` / `iptables` | network isolation / firewall |
| `ss` / `conntrack`, `cron` (or systemd-timer) | egress-observation sensor (`monitor_egress.sh`): poll outbound flows over a window, then auto-blackhole egress |
| `usbguard` | USB device control |
| `nmcli`, `resolvectl`, `dnsmasq` | network/DNS controls |
| `dpkg` / `rpm`, `debsums`, `getcap` | package verification, changed-file + capability triage |

These are **assumed** OS tools; the workflow degrades gracefully when one is absent, and the
manifest records presence per host so gaps are explicit (never a silent blind spot).

---

## Staging for an air-gapped engagement

```bash
# on a CONNECTED machine, matching the analyst host's arch:
./Build-OfflineToolkit-Linux.sh --include-memory --include-cloud \
    --stage-symbols --symbols-kernel <target-kernel-version>
# review the inventory:
./Build-OfflineToolkit-Linux.sh --check-only --include-memory --include-cloud
cat tools/STAGED_MANIFEST.json
```

Anything reported `MISSING`/`absent` that the engagement needs must be installed on the target
or analyst host before going offline.
