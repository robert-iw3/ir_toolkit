"""mwcp_parsers -- Linux family-specific structured config/indicator extraction,
styled after playbooks/windows/threat_hunting/mwcp_parsers/ (same directory name,
same per-family-file organization, same "2+ independent structural/behavioral
signals, never a brand-name string" detection discipline) but deliberately NOT an
mwcp parser: mwcp is only staged by Build-OfflineToolkit.ps1 (Windows) -- the Linux
build never installs it, so the Linux offline toolkit carries no extra runtime
dependency to an air-gapped host. Every parser here is a plain `bytes -> dict`
function.

Categories:
  c2_frameworks/  cross-platform red-team/post-ex frameworks with real Linux agents
  native/         Linux/Unix-native malware families (BPFDoor, Mirai/Gafgyt, Ebury,
                  XMRig-class miners, SMTP-exfil) -- no Windows equivalent
  ransomware/     Linux/ESXi ransomware -- cross-family mechanisms + the two named
                  ports where the Linux build shares the exact same codebase as this
                  toolkit's own Windows parser (Conti, BlackCat/ALPHV)
  cloud_saas/     Telegram/Discord/Slack/Dropbox/GitHub/Pastebin/Ngrok as C2 channels
                  -- OS-agnostic protocol-level detection
  delivery/       Linux-native dropper/stager patterns (shell pipelines, base64-ELF)
  specialized/    narrowly-scoped technique detectors (anti-analysis, DNS tunneling)

Usage:
    from mwcp_parsers.driver import extract_all, to_findings
    hits = extract_all(data)
    findings = to_findings(hits, where)

See README.md for the full parser catalog and "Adding a New Parser" guidance.
"""
from .driver import extract_all, to_findings  # noqa: F401
