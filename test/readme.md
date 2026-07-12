## Tests

The suite proves every stage section-by-section and end-to-end for all three platforms.
**Testing standard**: unit tests first (prove logic in isolation), then live tests against
`reports/` artifacts on a real host. Both required before closing any item.

Two independent suites:

### pytest (`test/`) — runs on any box with Python 3

Covers the Linux and Cloud playbooks, plus every Windows-side **Python** module (mwcp_parsers,
memory_yara, the investigation engine, etc.) — none of that needs a real Windows host, only
`numpy`/`yara-python`/the DC3-MWCP package staged for full coverage; unstaged pieces skip
cleanly rather than failing.

```bash
test/run_tests.sh                 # everything
test/run_tests.sh linux           # only Linux-relevant tests
test/run_tests.sh windows         # only Windows-python-relevant tests
test/run_tests.sh cloud           # only Cloud-relevant tests
test/run_tests.sh linux -v        # platform selector first; anything after passes to pytest
```

Each invocation builds a fresh temporary venv, installs `requirements.txt`, runs the suite,
tears the venv down, and writes a timestamped log to `test/logs/` (gitignored) in addition to
the console report line.

Use the platform selector, not the bare default, when validating a change scoped to one
platform: a full run mixes in tests that need tooling this box may not have staged (the
DC3-MWCP package, `yara-python`, `pwsh`) — those fail loudly instead of skipping cleanly,
which reads as a regression in an otherwise-clean change. Picking a platform runs exactly the
tests whose target code that platform's work can actually break.

**Test files that used to mix platforms in one module** (e.g. a Windows orchestrator check and
a Linux orchestrator check in the same `test_NN_*.py`) have been split into
`test_NN_*_windows.py` / `_linux.py` / `_cloud.py`, with any platform-agnostic tests staying in
the base `test_NN_*.py` name (auto-included in every platform run). The pre-split originals are
kept for reference under `test/archived/` (excluded from collection via `pytest.ini`'s
`norecursedirs`) — diff against them if a split looks incomplete. When adding a new
`test_*.py` file: if it's single-platform, name it or place it accordingly and add it to the
matching array in `run_tests.sh`; if it's platform-agnostic, no array change needed beyond
`COMMON`; if it genuinely spans platforms, split it rather than leaving it mixed.

`test/linux/` and `test/windows/` are swept wholesale by their respective platform run (own
`lab_mwcp`/`lab_investigation` labs, both with TP/FP coverage). Running `linux` and `windows`
together in one invocation is unsupported — both trees carry same-named `conftest.py` files
that collide under pytest's module caching; `test/run_tests.sh windows` already works around
this by invoking `windows/` and the top-level Windows file list as two separate pytest runs.

### Pester 5 (`test/windows/*.Tests.ps1`) — requires a real Windows host

The PowerShell-native side of the Windows playbooks (orchestrator scripts, `.ps1` hunt logic)
that only runs under real PowerShell — not part of `run_tests.sh`.

```powershell
.\test\windows\Run-Pester-CI.ps1        # runs all *.Tests.ps1, prints pass/fail per file
```
