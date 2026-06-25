# Carved memory regions → Binary Ninja

This directory is the drop zone for **memory regions carved out of true-positive YARA hits** during
Linux memory analysis. The analyzer writes here when run with `--carve`:

```
playbooks/linux/threat_hunting/analyze_memory_linux.py --image mem.raw --yara --carve
# or via the orchestrator: Analyze-Memory-Linux.sh --yara --carve
```

Each carved region is a pair (under `data/<incident-stamp>/`):

| File | What it is |
|---|---|
| `pid<PID>_<proc>_0x<addr>.bin` | the **raw bytes** of the matching VMA (inert on disk — never executed) |
| `pid<PID>_<proc>_0x<addr>.json` | sidecar: `base_address`, `size`, `perms`, `region` (anon/file), `backing_path`, `matched_rules`, `arch_hint`, attribution |

By default only **anonymous + executable** regions are carved — injected/unbacked code, the strongest
true-positive signal. (Set `IR_CARVE_ANY=1` to carve any hit's region, e.g. for triage.)

> ⚠️ **These are potentially live malware.** Analyse them **only inside the isolated Binary Ninja
> container** (`../binja.Dockerfile`), never on the host. They are git-ignored — do not commit them.

## Loading a carved region in Binary Ninja

A carved `.bin` is **raw memory**, not a file format — so open it as raw and tell BN how to interpret
it, using the sidecar:

1. `Open` the `.bin` → choose **"Raw"** view.
2. Set **Architecture** = the sidecar's `arch_hint` (e.g. `x86_64`) and the matching platform.
3. Set the **base address** = the sidecar's `base_address` (e.g. `0x7f00…`). This makes BN's addresses
   line up with the original process virtual addresses, so offsets in the YARA finding match.
4. Re-analyze. For shellcode with no obvious entry, mark the matched offset (from the finding) as a
   function start (`P`).

## Plugins that help on carved/injected regions

Staged in `../plugins/` (copied into the container by the Dockerfile):

| Plugin | Why it helps here |
|---|---|
| **obfuscation_detection** | flags packed / encrypted / flattened code — injected regions are usually obfuscated; finds the interesting blocks fast |
| **binaryninja-ollama** | local-LLM function/variable renaming — recovers intent in stripped shellcode without leaking samples to a cloud service |
| **binary_ninja_mcp** | exposes the BNDB to an LLM over MCP for assisted RE / triage Q&A |
| **x64dbgbinja** | round-trips annotations with x64dbg for dynamic confirmation |

Other useful community plugins for this work (see `../plugins.md`): **Call Shellcode** / **Shellcoder**
(execute/disassemble highlighted bytes), **Obfuscation Analysis** (simplify obfuscated code),
**BinAssist** (LLM explain).
