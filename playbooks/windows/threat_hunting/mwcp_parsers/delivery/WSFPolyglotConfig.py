"""
WSFPolyglotConfig -- mwcp parser for a polyglot Windows Script File: a
.wsf document with multiple <script language="..."> blocks using
DIFFERENT scripting languages in the same file, combined with a
download/execute primitive in one of them.

Two independent mechanisms, both required:
  1. Two or more <script language="..."> blocks with DIFFERING language
     attribute values (e.g. both "VBScript" and "JScript") -- WSF's own
     XML schema (MS-WSH) is the only Windows script container that lets
     a single file mix multiple scripting engines; this is a structural
     trait of the WSF format itself, not operator-chosen. A single-
     language .wsf file is completely ordinary; multi-language is the
     polyglot evasion shape used to split a payload across engines that
     different AV signatures/sandboxes may only inspect one of.
  2. A download/execute-capable COM object instantiation inside one of the
     script blocks: `CreateObject("WScript.Shell")` / `CreateObject
     ("Shell.Application")` or `CreateObject("Msxml2.XMLHTTP")` -- the exact
     COM ProgID a script must name to gain shell-execution or network
     capability, matched regardless of whether the resulting object is used
     inline (`CreateObject(...).Run(...)`) or via a variable
     (`Set sh = CreateObject(...)` then `sh.Run(...)` on a later line, the
     more common real-world WSF shape).

Detection never checks for a malware family name string.

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import DecodedString

_SCRIPT_LANG_RE = re.compile(rb'(?i)<script[^>]*\blanguage\s*=\s*["\']([^"\']+)["\']')

_PRIMITIVE_RE = re.compile(
    rb'(?i)CreateObject\s*\(\s*["\'](WScript\.Shell|Shell\.Application|'
    rb'Msxml2\.(?:Server)?XMLHTTP)["\']')


class WSFPolyglotConfig(mwcp.Parser):
    """Detect a multi-language polyglot WSF with a download/execute
    primitive."""

    DESCRIPTION = "Polyglot WSF Delivery Detector"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 64:
            return False
        langs = {m.group(1).lower() for m in _SCRIPT_LANG_RE.finditer(data)}
        if len(langs) < 2:
            return False
        return bool(_PRIMITIVE_RE.search(data))

    def run(self):
        data = self.file_object.data
        if not data:
            return
        langs = {m.group(1).lower() for m in _SCRIPT_LANG_RE.finditer(data)}
        if len(langs) < 2:
            return
        prim_m = _PRIMITIVE_RE.search(data)
        if not prim_m:
            return

        lang_list = b', '.join(sorted(langs)).decode('utf-8', 'ignore')
        self.report.add(DecodedString(
            f'[WSF-Polyglot] {len(langs)} distinct script languages ({lang_list}) '
            f'+ execute/download primitive ({prim_m.group(0).decode("utf-8","ignore")}) -- '
            f'polyglot evasion shape'))
