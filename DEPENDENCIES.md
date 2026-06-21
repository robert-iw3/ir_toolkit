# Dependency Inventory

Every external dependency the toolkit touches, its role, and **how it is satisfied for
offline/air-gapped operation**. The live, machine-readable copy is
`tools/STAGED_MANIFEST.json` (regenerate with `Build-OfflineToolkit-Linux.sh --check-only`).

**Key principle:** the toolkit's own code (collection, detection, adjudication, reporting,
LLM review, custody) is **Python 3 standard library + bash only** — verified by audit, there
are **no first-party pip dependencies**. The only third-party runtime is **Volatility 3** for
memory analysis, which is vendored as wheels.

Satisfaction legend: **bundled** (in repo) · **staged** (fetched by the build script into
`tools/`) · **vendored** (wheels in `tools/vol3_wheels/`) · **assumed** (OS-provided on the
target/analyst host — recorded, not bundled).

---

## Core collection + detection + reporting (Linux/Cloud)

| Dependency | Role | Satisfied by |
|---|---|---|
| `python3` (stdlib only) | every analyzer, adjudicator, report, LLM-review, custody | **assumed** (3.8+; no pip deps) |
| `bash`, coreutils | collection + eradication scripts | **assumed** |

## Memory analysis (analyst host, off-target) — `--include-memory`

| Dependency | Role | Satisfied by |
|---|---|---|
| `avml` | volatile-memory acquisition (LiME) | **staged** `tools/avml` (arch-aware) |
| `avml-convert` | decompress `--compress` (snappy) images before Volatility | **staged** `tools/avml-convert` |
| `volatility3` (+ `pefile`, `yara-python`) | the analyzer engine | **vendored** `tools/vol3_wheels/` → offline venv via `pip install --no-index` |
| `dwarf2json` | build the Volatility 3 Linux **ISF** from a debug `vmlinux` | **staged** `tools/dwarf2json` (arch-aware) |
| kernel **ISF / symbols** | version-EXACT kernel layout (a generic `vmlinux.h`/BTF will not work) | **staged** `tools/symbols/` via `--stage-symbols` (build while connected); else fetched at analysis time |
| YARA rules | `--yara` in-memory signature scan | **bundled/staged** `tools/yara_rules/` (1775 rules) |
| `python3-venv`, `pip` | ephemeral analyzer venv | **assumed** |
| `debuginfod-find` (elfutils) | universal ISF fetch by build-id (connected staging) | **assumed** (optional) |
| `dpkg-deb` | extract a dbgsym `vmlinux` without root | **assumed** (Debian) |

### The symbols problem (why it's special)
Windows auto-fetches PDBs; Linux has no such service for arbitrary kernels. The ISF must match
the target kernel's exact build (struct offsets + symbol addresses + banner). Acquisition order
(`Build-LinuxSymbols.sh`): existing debug `vmlinux` → **debuginfod** (any distro, by build-id)
→ distro package manager (`apt`/`dnf`/`zypper`). For air-gapped analysis, run
`--stage-symbols --symbols-kernel <ver>` **while connected** to bake the ISF into `tools/symbols/`.

## Cloud workflow — `--include-cloud`

| Dependency | Role | Satisfied by |
|---|---|---|
| `aws`, `az`, `gcloud` | provider collection / snapshots / GuardDuty-SCC | **assumed** (too large to bundle) — or the **Docker image** bundles them |
| `kubectl` | Kubernetes RBAC / pod hunt | **assumed** / Docker image |
| `terraform` (or `tofu`) | provision WORM evidence storage (S3/Azure/GCS) | **assumed** / Docker image |
| LLM review | provider-native (Bedrock/Vertex/Azure OpenAI) or frontier/local | **stdlib `urllib`** — no SDK dependency |

## Containment / eradication (Linux target) — recorded, capability-gated

| Dependency | Role |
|---|---|
| `ip`, `nft` / `iptables` | network isolation / firewall |
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
