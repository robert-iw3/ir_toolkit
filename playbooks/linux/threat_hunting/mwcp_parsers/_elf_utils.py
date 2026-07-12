"""Minimal ELF dynamic-symbol parser (stdlib-only -- no pyelftools dependency for the
offline Linux toolkit). Distinguishes DEFINED (exported) symbols from UNDEFINED
(imported) ones, which raw substring search over file bytes cannot: a byte string
search can't tell "this object EXPORTS keyctl" from "this object's string table merely
CONTAINS the word keyctl somewhere" (a keyutils test suite, a security scanner auditing
keyutils, a comment).

Tries section headers first (SHT_DYNSYM -- correct for on-disk ELF files, which is the
realistic input here: an analyst-copied /lib*/libX.so* or an adjudicate.py evidence-bundle
"subject_" copy). Falls back to walking the PT_DYNAMIC segment's .dynamic entries
(DT_SYMTAB/DT_STRTAB by virtual address, resolved through PT_LOAD segments) for stripped
binaries or a raw memory-mapped image where section headers aren't resident. Both paths
produce identical symbol sets for the same file.

Shared across every c2_parsers family that needs export/import verification, not just
the Ebury-class detector this was originally built for (see native/ebury.py) --
ransomware/ and specialized/ families reuse it too.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Set, Tuple

_PT_DYNAMIC = 2
_PT_LOAD = 1
_DT_NULL = 0
_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_STRSZ = 10
_DT_SYMENT = 11


def _read_cstr(data: bytes, offset: int) -> str:
    end = data.find(b'\x00', offset)
    if end == -1:
        return ''
    try:
        return data[offset:end].decode('utf-8', 'ignore')
    except UnicodeDecodeError:
        return ''


def elf_header(data: bytes) -> Optional[dict]:
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = '<' if ei_data == 1 else '>'
    is64 = ei_class == 2
    try:
        if is64:
            e_phoff, = struct.unpack_from(endian + 'Q', data, 32)
            e_shoff, = struct.unpack_from(endian + 'Q', data, 40)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(endian + 'HHHHH', data, 54)
        else:
            e_phoff, = struct.unpack_from(endian + 'I', data, 28)
            e_shoff, = struct.unpack_from(endian + 'I', data, 32)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(endian + 'HHHHH', data, 40)
    except struct.error:
        return None
    return {'endian': endian, 'is64': is64, 'e_phoff': e_phoff,
           'e_phentsize': e_phentsize, 'e_phnum': e_phnum, 'e_shoff': e_shoff,
           'e_shentsize': e_shentsize, 'e_shnum': e_shnum}


def _symbols_via_sections(data: bytes, h: dict) -> Optional[Tuple[Set[str], Set[str]]]:
    endian, is64 = h['endian'], h['is64']
    e_shoff, e_shentsize, e_shnum = h['e_shoff'], h['e_shentsize'], h['e_shnum']
    if not e_shoff or not e_shnum or e_shoff + e_shentsize * e_shnum > len(data):
        return None
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        try:
            sh_type, = struct.unpack_from(endian + 'I', data, off + 4)
            if is64:
                sh_link, = struct.unpack_from(endian + 'I', data, off + 40)
                sh_offset, sh_size = struct.unpack_from(endian + 'QQ', data, off + 24)
                sh_entsize, = struct.unpack_from(endian + 'Q', data, off + 56)
            else:
                sh_link, = struct.unpack_from(endian + 'I', data, off + 24)
                sh_offset, sh_size = struct.unpack_from(endian + 'II', data, off + 16)
                sh_entsize, = struct.unpack_from(endian + 'I', data, off + 36)
        except struct.error:
            return None
        sections.append({'type': sh_type, 'link': sh_link, 'offset': sh_offset,
                         'size': sh_size, 'entsize': sh_entsize})
    dynsym = next((s for s in sections if s['type'] == 11), None)  # SHT_DYNSYM
    if dynsym is None or dynsym['link'] >= len(sections):
        return None
    strtab = sections[dynsym['link']]
    entsize = dynsym['entsize'] or (24 if is64 else 16)
    count = dynsym['size'] // entsize if entsize else 0
    return _walk_symtab(data, endian, is64, dynsym['offset'], entsize, count,
                        strtab['offset'], strtab['size'])


def program_headers(data: bytes, h: dict) -> List[dict]:
    endian, is64 = h['endian'], h['is64']
    e_phoff, e_phentsize, e_phnum = h['e_phoff'], h['e_phentsize'], h['e_phnum']
    if not e_phoff or not e_phnum or e_phoff + e_phentsize * e_phnum > len(data):
        return []
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        try:
            if is64:
                p_type, = struct.unpack_from(endian + 'I', data, off)
                p_offset, p_vaddr = struct.unpack_from(endian + 'QQ', data, off + 8)
                p_filesz, p_memsz = struct.unpack_from(endian + 'QQ', data, off + 32)
            else:
                p_type, = struct.unpack_from(endian + 'I', data, off)
                p_offset, p_vaddr = struct.unpack_from(endian + 'II', data, off + 4)
                p_filesz, p_memsz = struct.unpack_from(endian + 'II', data, off + 16)
        except struct.error:
            continue
        phdrs.append({'type': p_type, 'offset': p_offset, 'vaddr': p_vaddr,
                      'filesz': p_filesz, 'memsz': p_memsz})
    return phdrs


def vaddr_to_offset(phdrs: List[dict], vaddr: int) -> Optional[int]:
    for p in phdrs:
        if p['type'] == _PT_LOAD and p['vaddr'] <= vaddr < p['vaddr'] + p['memsz']:
            return p['offset'] + (vaddr - p['vaddr'])
    return None


def _walk_symtab(data: bytes, endian: str, is64: bool, sym_off: int, entsize: int,
                 count: int, str_off: int, str_size: int) -> Tuple[Set[str], Set[str]]:
    defined: Set[str] = set()
    undefined: Set[str] = set()
    for i in range(max(count, 0)):
        off = sym_off + i * entsize
        if off + entsize > len(data):
            break
        try:
            st_name, = struct.unpack_from(endian + 'I', data, off)
            st_shndx, = struct.unpack_from(endian + 'H', data, off + (6 if is64 else 14))
        except struct.error:
            continue
        if not st_name or st_name >= str_size:
            continue
        name = _read_cstr(data, str_off + st_name)
        if name:
            (undefined if st_shndx == 0 else defined).add(name)
    return defined, undefined


def _symbols_via_dynamic_segment(data: bytes, h: dict) -> Optional[Tuple[Set[str], Set[str]]]:
    """Fallback for stripped section headers or a raw memory-mapped image: walk
    PT_DYNAMIC's .dynamic entries to locate DT_SYMTAB/DT_STRTAB by virtual address,
    resolved to a buffer offset via PT_LOAD segments."""
    endian, is64 = h['endian'], h['is64']
    phdrs = program_headers(data, h)
    dyn_seg = next((p for p in phdrs if p['type'] == _PT_DYNAMIC), None)
    if dyn_seg is None:
        return None

    entsize = 16 if is64 else 8
    tags: Dict[int, int] = {}
    off, end = dyn_seg['offset'], dyn_seg['offset'] + dyn_seg['filesz']
    while off + entsize <= end and off + entsize <= len(data):
        try:
            fmt = 'qQ' if is64 else 'iI'
            d_tag, d_val = struct.unpack_from(endian + fmt, data, off)
        except struct.error:
            break
        if d_tag == _DT_NULL:
            break
        tags[d_tag] = d_val
        off += entsize

    if _DT_SYMTAB not in tags or _DT_STRTAB not in tags:
        return None
    symtab_off = vaddr_to_offset(phdrs, tags[_DT_SYMTAB])
    strtab_off = vaddr_to_offset(phdrs, tags[_DT_STRTAB])
    if symtab_off is None or strtab_off is None:
        return None
    strsz = tags.get(_DT_STRSZ, 0)
    syment = tags.get(_DT_SYMENT) or (24 if is64 else 16)
    # .dynamic has no explicit symbol count; bound the walk by the string table's
    # start (symtab always precedes strtab in practice) + a sane cap.
    approx_count = (strtab_off - symtab_off) // syment if strtab_off > symtab_off else 0
    defined, undefined = _walk_symtab(data, endian, is64, symtab_off, syment,
                                      min(approx_count, 100000), strtab_off, strsz)
    return (defined, undefined) if (defined or undefined) else None


def elf_dynamic_symbols(data: bytes) -> Optional[Tuple[Set[str], Set[str]]]:
    """Return (defined_names, undefined/imported_names) for an ELF object's dynamic
    symbol table, or None if data isn't parseable as ELF (absent, truncated, corrupted
    -- callers must fall back to a weaker heuristic rather than treating None as
    "verified clean")."""
    h = elf_header(data)
    if h is None:
        return None
    return _symbols_via_sections(data, h) or _symbols_via_dynamic_segment(data, h)
