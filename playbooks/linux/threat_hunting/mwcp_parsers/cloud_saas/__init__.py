"""Cloud SaaS platforms used as C2/exfil/dead-drop channels -- protocol-level detection
(token formats, API endpoints, required headers/payload fields), OS-agnostic by nature
since these are wire-format requirements of the SaaS provider's own API, not anything
tied to the implant's host platform."""
from . import discord, dropbox, github, ngrok, pastebin, slack, telegram

MODULES = (telegram, discord, slack, dropbox, github, pastebin, ngrok)
