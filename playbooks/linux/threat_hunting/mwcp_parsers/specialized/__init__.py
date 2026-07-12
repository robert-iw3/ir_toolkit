"""Specialized technique detectors kept deliberately narrow: only signals a stdlib
byte/string scanner can ground with real confidence (no disassembly), each 2+
independent structural requirements of the technique itself."""
from . import anti_analysis, dns_tunnel

MODULES = (anti_analysis, dns_tunnel)
