"""
Synthetic IR collection fixtures.

These are entirely fabricated finding sets (no real hosts, no live-test data) that
exercise every branch of the pipeline deterministically:

  * a Windows collection with a signed remote-access tool beaconing to a CUSTOM C2
    relay, a disabled Defender, hidden processes, and a spread of false positives —
    so the funnel and the C2/IOC correlation can be asserted exactly;
  * a Linux collection with NO remote-access tool — so the generator's "no RAT,
    MEDIUM severity, empty C2 list" path is covered with a different field shape.

`materialize(dst, platform)` writes the JSON artifacts into `dst` exactly as a real
collection folder would contain them (newest-wins filename stamps included).
"""
import json
import os

# A fabricated custom relay — NOT a vendor-sanctioned *.screenconnect.com endpoint.
C2_HOST = "relay.example-c2.test"
C2_PORT = 9999
C2_SESSION = "11112222-3333-4444-5555-666677778888"
C2_INSTANCE = "deadbeefcafe1234"
RAT_PATH = (r"C:\Program Files (x86)\ScreenConnect Client (deadbeefcafe1234)"
            r"\ScreenConnect.ClientService.exe")
RAT_SHA256 = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666AAAA7777BBBB8888"
RAT_CMDLINE = (f'"{RAT_PATH}" "?e=Access&y=Guest&h={C2_HOST}&p={C2_PORT}'
               f'&s={C2_SESSION}&k=BgIAAACkAAB"')

# ---------------------------------------------------------------- Windows set
# Adjudication funnel target:  FP=4  LFP=2  Indeterminate=1  LTP=3  (total 10)
WINDOWS_ADJUDICATION = [
    {"Verdict": "Likely True Positive", "Confidence": "High", "Type": "Remote Access Tool",
     "Target": "ScreenConnect", "Details": f"Detected service; path: {RAT_CMDLINE}",
     "MITRE": "T1219 (Remote Access Software)", "SubjectPath": RAT_PATH, "SigStatus": "Valid",
     "Signer": 'CN="Connectwise, LLC", O="Connectwise, LLC", C=US', "SHA256": RAT_SHA256},
    {"Verdict": "Likely True Positive", "Confidence": "High", "Type": "Hidden Process",
     "Target": "PID: 4242", "Details": "Hidden from standard API. Name: ScreenConnect.ClientService.exe",
     "MITRE": "T1014 (Rootkit)", "SubjectPath": RAT_PATH, "SigStatus": "Valid",
     "Signer": 'CN="Connectwise, LLC"', "SHA256": RAT_SHA256},
    {"Verdict": "Likely True Positive", "Confidence": "High", "Type": "Defender Disabled",
     "Target": "RealTimeProtection", "Details": "Defender real-time protection is OFF",
     "MITRE": "T1562.001 (Impair Defenses)", "SubjectPath": "", "SigStatus": "", "Signer": "", "SHA256": ""},
    {"Verdict": "Indeterminate", "Confidence": "Medium", "Type": "COM Hijacking",
     "Target": "{E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496}", "Details": "CLSID server points at missing DLL",
     "MITRE": "T1546.015 (COM Hijack)", "SubjectPath": r"C:\ProgramData\x\y.dll",
     "SigStatus": "", "Signer": "", "SHA256": ""},
    {"Verdict": "Likely False Positive", "Confidence": "Medium", "Type": "Registry Persistence",
     "Target": "Teams", "Details": "Run key autostart for signed app",
     "MITRE": "T1547.001", "SubjectPath": r"C:\Users\u\AppData\Local\Microsoft\Teams\Update.exe",
     "SigStatus": "Valid", "Signer": "CN=Microsoft Corporation", "SHA256": "1234"},
    {"Verdict": "Likely False Positive", "Confidence": "Medium", "Type": "LOLBin Execution",
     "Target": "powershell.exe PID 7777", "Details": "Command line: powershell.exe -File collector",
     "MITRE": "T1059, T1218", "SubjectPath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "SigStatus": "Valid", "Signer": "CN=Microsoft Windows", "SHA256": "5678"},
    {"Verdict": "False Positive", "Confidence": "High", "Type": "Hidden Process",
     "Target": "PID: 100", "Details": "Hidden from standard API. Name: MsMpEng.exe",
     "MITRE": "T1014 (Rootkit)", "SubjectPath": r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe",
     "SigStatus": "Valid", "Signer": "CN=Microsoft Corporation", "SHA256": "9abc"},
    {"Verdict": "False Positive", "Confidence": "High", "Type": "Hidden Process",
     "Target": "PID: 200", "Details": "Hidden from standard API. Name: IntelCpHDCPSvc.exe",
     "MITRE": "T1014 (Rootkit)", "SubjectPath": r"C:\Windows\System32\DriverStore\IntelCpHDCPSvc.exe",
     "SigStatus": "Valid", "Signer": "CN=Microsoft Windows Hardware", "SHA256": "def0"},
    {"Verdict": "False Positive", "Confidence": "High", "Type": "Scheduled Task",
     "Target": "Task: \\Microsoft\\Windows\\UpdateOrchestrator\\Scheduled Start",
     "Details": "Default Windows maintenance task", "MITRE": "T1053.005",
     "SubjectPath": r"C:\Windows\System32\svchost.exe", "SigStatus": "Valid",
     "Signer": "CN=Microsoft Windows", "SHA256": "0f0f"},
    {"Verdict": "False Positive", "Confidence": "High", "Type": "Netsh Helper DLL",
     "Target": "ifmon.dll", "Details": "Default Windows netsh helper",
     "MITRE": "T1546.007", "SubjectPath": r"C:\Windows\System32\ifmon.dll",
     "SigStatus": "Valid", "Signer": "CN=Microsoft Windows", "SHA256": "abcd"},
]

WINDOWS_REMOTE = [
    {"Timestamp": "2026-01-01 10:00:00", "Severity": "High", "Type": "Remote Access Tool",
     "Target": "ScreenConnect", "Details": f"Detected running (PID 4242); path: {RAT_PATH}",
     "MITRE": "T1219 (Remote Access Software)"},
    {"Timestamp": "2026-01-01 10:00:00", "Severity": "High", "Type": "Remote Access Tool",
     "Target": "GoToAssist", "Details": f"Detected service: ScreenConnect Client (deadbeefcafe1234); path: {RAT_CMDLINE}",
     "MITRE": "T1219 (Remote Access Software)"},
    {"Timestamp": "2026-01-01 10:00:01", "Severity": "High", "Type": "Defender Disabled",
     "Target": "RealTimeProtection", "Details": "Defender real-time protection is OFF",
     "MITRE": "T1562.001 (Impair Defenses)"},
]

# ------------------------------------------------------------------ Linux set
# No RAT. Funnel: LTP=1 Indeterminate=2 LFP=2 (total 5). Different field names
# (Pid/PkgOwner/Rationale) to prove the generator is field-shape tolerant.
LINUX_ADJUDICATION = [
    {"Timestamp": "2026-01-01 12:00:00", "Severity": "High", "Type": "Hidden Process",
     "Target": "PID: 31337", "Details": "Process hidden from /proc listing",
     "MITRE": "T1014 (Rootkit)", "SubjectPath": "/tmp/.x/payload", "Pid": 31337,
     "PkgOwner": None, "PkgModified": False, "SHA256": "f00dbabe",
     "Verdict": "Likely True Positive", "Confidence": "Medium", "Rationale": "unowned binary in /tmp"},
    {"Timestamp": "2026-01-01 12:00:00", "Severity": "Medium", "Type": "Anonymous Exec Memory",
     "Target": "PID: 1823", "Details": "anonymous rwx mapping", "MITRE": "T1055",
     "SubjectPath": "/usr/bin/foo", "Pid": 1823, "PkgOwner": "coreutils", "PkgModified": False,
     "SHA256": "aa", "Verdict": "Indeterminate", "Confidence": "Low", "Rationale": "jit runtime"},
    {"Timestamp": "2026-01-01 12:00:00", "Severity": "Medium", "Type": "Anonymous Exec Memory",
     "Target": "PID: 2449", "Details": "anonymous rwx mapping", "MITRE": "T1055",
     "SubjectPath": "/usr/bin/bar", "Pid": 2449, "PkgOwner": "bash", "PkgModified": False,
     "SHA256": "bb", "Verdict": "Indeterminate", "Confidence": "Low", "Rationale": "jit runtime"},
    {"Timestamp": "2026-01-01 12:00:00", "Severity": "Low", "Type": "Cron Entry",
     "Target": "/etc/cron.d/backup", "Details": "system backup job", "MITRE": "T1053.003",
     "SubjectPath": "/usr/bin/backup", "Pid": None, "PkgOwner": "backup-tool", "PkgModified": False,
     "SHA256": "cc", "Verdict": "Likely False Positive", "Confidence": "Medium", "Rationale": "packaged"},
    {"Timestamp": "2026-01-01 12:00:00", "Severity": "Low", "Type": "Systemd Unit",
     "Target": "snapd.service", "Details": "vendor unit", "MITRE": "T1543.002",
     "SubjectPath": "/usr/lib/snapd/snapd", "Pid": None, "PkgOwner": "snapd", "PkgModified": False,
     "SHA256": "dd", "Verdict": "Likely False Positive", "Confidence": "Medium", "Rationale": "packaged"},
]

LINUX_REMOTE = []   # the linux fixture has no remote-access tool


def materialize(dst, platform="windows", stamp="20260101_100000"):
    """Write a synthetic collection folder. Returns dst."""
    os.makedirs(dst, exist_ok=True)
    if platform == "windows":
        adj, remote = WINDOWS_ADJUDICATION, WINDOWS_REMOTE
    else:
        adj, remote = LINUX_ADJUDICATION, LINUX_REMOTE
    combined = list(adj)
    _write(os.path.join(dst, f"Adjudication_{stamp}.json"), adj)
    _write(os.path.join(dst, f"RemoteAccess_Findings_{stamp}.json"), remote)
    _write(os.path.join(dst, f"Combined_Findings_{stamp}.json"), combined)
    # Custody record carries the authoritative platform marker (both real collectors write it) —
    # the report generator reads it to reference the correct eradication tooling (.sh vs .ps1).
    _write(os.path.join(dst, f"_custody_{stamp}.json"),
           {"platform": platform, "hostname": os.path.basename(dst)})
    return dst


def _write(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
