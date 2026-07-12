#!/usr/bin/env bash
# Build a TEMPORARY venv, install test deps, run the pytest suite (Linux + Windows-python +
# Cloud, all runnable off a Linux box -- the separate Windows Pester suite is invoked on its
# own via test/windows/Run-Pester-CI.ps1, PowerShell-only, not part of this script), then tear
# the venv down and print a pass/fail report line. Every run starts from a clean environment;
# nothing persists across invocations.
#
# Usage:
#   test/run_tests.sh                 # everything (default -- unchanged old behavior)
#   test/run_tests.sh linux           # only Linux-relevant tests, no Windows/Cloud noise
#   test/run_tests.sh windows         # only Windows-python-relevant tests
#   test/run_tests.sh cloud           # only Cloud-relevant tests
#   test/run_tests.sh linux -v        # platform selector always comes first; the rest
#                                      # passes straight through to pytest
#
# Why a platform selector: a full run mixes in tests that are only meaningful with tooling
# this box doesn't have staged (the DC3-MWCP package, yara-python, real PowerShell) -- those
# fail loudly instead of skipping cleanly, which reads as a regression in an otherwise-clean
# Linux-only change. Picking a platform runs exactly the tests whose target code that
# platform's work can actually break, so a real regression is never lost in unrelated noise.
#
# Classification is static (grep-derived from each file's conftest-constant imports +
# filename), not automatic -- when adding a new test_*.py file, add its name to the matching
# list below (or drop it under test/linux/ or test/windows/, which are swept wholesale). A
# file relevant to more than one platform (e.g. it exercises both the Linux and Windows sides
# of the same schema) belongs in more than one list; that's expected, not a bug.
set -uo pipefail   # not -e: a nonzero pytest exit must still reach the report line + cleanup

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="$(command -v python3 || command -v python || true)"
if [[ -z "$PY" ]]; then
    echo "[run_tests] ERROR: no python3 (or python) interpreter found on PATH." >&2
    echo "[run_tests] Install Python 3 and re-run." >&2
    exit 1
fi

VENV="$(mktemp -d -t ir-toolkit-tests.XXXXXX)"
cleanup() { rm -rf "$VENV"; }
trap cleanup EXIT

if ! "$PY" -m venv "$VENV"; then
    echo "[run_tests] ERROR: failed to create a virtualenv at $VENV (is the 'venv' module available?)." >&2
    exit 1
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$TEST_DIR/requirements.txt"

cd "$TEST_DIR"

# Runs in every platform-scoped invocation: platform-agnostic pipeline/reporting logic that
# doesn't import from any one playbooks/<platform>/ tree. Includes the "common" remainder of
# files that used to mix platforms in one module (see test/archived/ for the pre-split
# originals) -- their per-platform halves now live in the matching list below.
COMMON=(
    test_03_reporting.py test_05_restoration.py test_08_ioc_decoupling.py test_10_schema.py
    test_11_status_contract.py test_14_timeline.py test_16_campaign.py
    test_17_offline_toolkit.py test_18_credential_revocation.py test_22_llm_review.py
    test_26_evidence_custody.py test_27_clock_context.py test_29_container_deploy.py
)

LINUX=(
    test_01_collection_linux.py test_02_analysis.py test_05_restoration_linux.py
    test_07_e2e_linux.py test_08_ioc_decoupling_linux.py test_10_schema_linux.py
    test_17_offline_toolkit_linux.py test_18_credential_revocation_linux.py
    test_19_journal_analysis.py test_25_container_hunt.py test_28_memory_linux.py
    test_29_memory_orchestrator.py test_30_symbols_distro.py test_31_linux_eradication.py
    test_33_linux_yara.py test_34_linux_yara_worker.py test_35_egress_monitor.py
    test_37_memory_enrich_linux.py test_38_linux_edr_auth.py test_39_linux_memory_p1.py
    test_40_linux_edr_static.py test_41_linux_memory_p2.py test_46_edr_hidden_modules.py
    test_47_diamorphine_memory.py test_48_edr_kernel_helpers.py test_49_edr_iouring_bpf.py
    test_50_kernel_globals_memory.py test_51_memory_m234.py test_58_thread_inventory.py
    test_66_edr_got_plt_hooks.py test_67_edr_mwcp_structural.py
    test_68_adjudicate_subject_resolution.py
)

WINDOWS=(
    test_01_collection_windows.py test_04_eradication.py test_05_restoration_windows.py
    test_08_ioc_decoupling_windows.py test_12_fw_baseline.py test_15_attack_graph.py
    test_17_offline_toolkit_windows.py test_18_credential_revocation_windows.py
    test_32_memory_yara.py test_36_memory_enrich.py test_37_binja_carve.py
    test_42_mem_forensic_blindspots.py test_43_p2_blindspots.py
    test_44_retro_phase1_enrich.py test_44_retro_phase1_forensic.py
    test_45_retro_phase5_mem_evasion.py test_53_mwcp_parsers.py
    test_54_forensics_collection.py test_55_syscall_decode.py test_56_ttp_batch5.py
    test_57_mwcp_tier1_parsers.py test_57_suspend_thread.py
    test_58_mwcp_ransomware_parsers.py test_59_mwcp_lol_fileless_parsers.py
    test_60_mwcp_delivery_parsers.py test_61_mwcp_cloud_saas_parsers.py
    test_62_mwcp_tier3_specialized_parsers.py test_63_mwcp_parser_performance.py
    test_64_mwcp_tier4_backlog_parsers.py test_65_memory_full_sweep.py
    test_67_edr_mwcp_structural.py test_egress_beacon_classifier.py
)

CLOUD=(
    test_06_cloud.py test_07_e2e_cloud.py test_09_cloud_analysis.py test_10_schema_cloud.py
    test_11_status_contract_cloud.py test_13_mock_and_idempotency.py
    test_18_credential_revocation_cloud.py test_20_disk_snapshot.py test_21_flow_logs.py
    test_23_terraform_storage.py test_24_docker_entrypoint.py test_27_cloud_controlplane.py
    test_28_identity_containment.py test_30_iam_posture.py test_31_blast_radius.py
    test_40_lab_scenarios.py test_41_tf_validate_docker.py test_42_eradication_breadth.py
    test_43_posture.py test_44_cloud_c7_hardening.py test_52_cloud_dataplane.py
    test_61_mwcp_cloud_saas_parsers.py
)

LOG_DIR="${TEST_DIR}/logs"
mkdir -p "$LOG_DIR"
PLATFORM="${1:-all}"
LOG_FILE="${LOG_DIR}/run_${PLATFORM}_$(date +%Y%m%d_%H%M%S).log"
: > "$LOG_FILE"

# Runs one pytest invocation, appending combined stdout+stderr to LOG_FILE. Returns pytest's
# real exit code via PIPESTATUS (not tee's), and never lets the failure abort the script
# (rc is accumulated by the caller so cleanup + the report line still run).
run_pytest_logged() {
    "$VENV/bin/python" -m pytest "$@" 2>&1 | tee -a "$LOG_FILE"
    return "${PIPESTATUS[0]}"
}

rc=0
case "$PLATFORM" in
    linux)
        shift
        run_pytest_logged linux/ "${LINUX[@]}" "${COMMON[@]}" "$@" || rc=$?
        ;;
    windows)
        shift
        # test/windows/ carries its OWN conftest.py files (memory_detection/unit/, etc.) that
        # collide with test/conftest.py under pytest's basename-based module caching when both
        # trees are collected in ONE session (the first "conftest" imported wins for every
        # later `from conftest import ...`, silently handing root-level files the wrong
        # module) -- same class of issue as the linux/windows mwcp_parsers name collision
        # documented in mwcp_parsers/README.md. Two separate invocations sidestep it entirely.
        run_pytest_logged windows/ "$@" || rc=$?
        run_pytest_logged "${WINDOWS[@]}" "${COMMON[@]}" "$@" || rc=$?
        ;;
    cloud)
        shift
        run_pytest_logged "${CLOUD[@]}" "${COMMON[@]}" "$@" || rc=$?
        ;;
    *)
        # "Everything": the three platform buckets run SEQUENTIALLY, never combining
        # test/linux/ and test/windows/ in one pytest process -- both trees carry a
        # same-named lab_investigation/test_investigation_lab.py, and pytest's import
        # system errors out ("import file mismatch") the moment both are collected
        # together. Each bucket already proved itself individually; this just chains them.
        run_pytest_logged linux/ "${LINUX[@]}" "${COMMON[@]}" "$@" || rc=$?
        run_pytest_logged windows/ "$@" || rc=$?
        run_pytest_logged "${WINDOWS[@]}" "${COMMON[@]}" "$@" || rc=$?
        run_pytest_logged "${CLOUD[@]}" "${COMMON[@]}" "$@" || rc=$?
        ;;
esac

echo
if [[ "$rc" -eq 0 ]]; then
    echo "[run_tests] PASS -- ${PLATFORM} suite completed cleanly. Log: ${LOG_FILE}"
else
    echo "[run_tests] FAIL -- ${PLATFORM} suite exited ${rc}. Log: ${LOG_FILE}"
fi
echo "[run_tests] venv torn down: ${VENV}"
exit "$rc"
