"""Linux/Unix-native malware families -- the actual dominant threats, no Windows
equivalent in mwcp_parsers because they don't target Windows: BPFDoor, Mirai/Gafgyt,
Ebury, XMRig-class miners, SMTP-exfil credential harvesting."""
from . import bpfdoor, ebury, mirai_gafgyt, smtp_exfil, xmrig_miner

# smtp_exfil.extract() returns a list (multiple hits per region) and has no
# identify(), so it's handled separately by the driver -- not in this tuple.
MODULES = (bpfdoor, mirai_gafgyt, ebury, xmrig_miner)
