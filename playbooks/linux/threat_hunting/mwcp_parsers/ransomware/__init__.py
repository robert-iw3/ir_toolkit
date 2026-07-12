"""Linux/ESXi ransomware detection. Two tiers:
  - Named-family ports (conti_linux.py, blackcat_linux.py) -- only where the Linux/ESXi
    build is documented to share the same source/codebase as the family's Windows
    build, so the field/flag list is a real structural requirement, not a guess.
  - Cross-family mechanisms (esxi_encryptor.py, recovery_inhibition.py,
    generic_indicators.py) for everything else -- not attributed to a named brand,
    since a brand-specific CLI-flag/field-name claim without solid per-OS-build
    grounding would just be a name-based guess."""
from . import (blackcat_linux, conti_linux, esxi_encryptor, generic_indicators,
              recovery_inhibition)

MODULES = (esxi_encryptor, recovery_inhibition, generic_indicators, conti_linux, blackcat_linux)
