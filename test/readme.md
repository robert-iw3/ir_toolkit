## Tests

The suite proves every stage section-by-section and end-to-end for all three platforms.
**Testing standard**: unit tests first (prove logic in isolation), then live tests against
`reports/` artifacts on the Windows machine. Both required before closing any item.

### Windows — Pester 5 suite (68 tests, `test/windows/`)

```powershell
.\test\windows\Run-Pester-CI.ps1        # runs all *.Tests.ps1, prints pass/fail per file
```

### Linux / Cloud — pytest suite (`test/`)

```bash
test/run_tests.sh            # creates /tmp/venv, installs pytest, runs everything
test/run_tests.sh -v         # verbose
```