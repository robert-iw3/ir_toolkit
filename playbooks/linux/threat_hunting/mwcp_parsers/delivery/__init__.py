"""Linux-native delivery/stager patterns -- NOT ports of Windows' delivery category
(LNK/HTA/macro/OneNote/WSF/regsvr32 are Windows-format-specific and have no Linux
analog); these are genuinely new detectors for how Linux droppers actually stage
payloads via shell composition."""
from . import base64_elf_dropper, shell_pipeline_stager

MODULES = (shell_pipeline_stager, base64_elf_dropper)
