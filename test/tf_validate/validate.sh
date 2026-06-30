#!/usr/bin/env bash
# Validate every IR evidence-storage module with OpenTofu. Runs INSIDE the throwaway
# tf-validate image (see Dockerfile). init uses -backend=false so no remote state /
# credentials are touched; validate is the config-correctness (lint/diff) check.
set -uo pipefail

TF="${TF:-tofu}"                       # override with TF=terraform for a host run
MODULES_DIR="${1:-/work/terraform}"
rc=0
for p in aws azure gcp; do
    d="${MODULES_DIR}/${p}"
    [[ -d "$d" ]] || { echo "MISSING module dir: $d"; rc=1; continue; }
    echo "== terraform/${p}: ${TF} init =="
    if ! "$TF" -chdir="$d" init -backend=false -input=false >/tmp/init.log 2>&1; then
        echo "FAIL ${p}: init"; cat /tmp/init.log; rc=1; continue
    fi
    echo "== terraform/${p}: ${TF} validate =="
    if "$TF" -chdir="$d" validate; then
        echo "OK ${p}"
    else
        echo "FAIL ${p}: validate"; rc=1
    fi
done

[[ $rc -eq 0 ]] && echo "ALL MODULES VALID" || echo "VALIDATION FAILED"
exit $rc
