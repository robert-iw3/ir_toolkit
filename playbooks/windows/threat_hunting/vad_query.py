#!/usr/bin/env python3
"""One-shot VAD lookup: find which VAD covers a given address in a given PID."""
import sys, os
from pathlib import Path

mpc_dir = str(Path(__file__).parent.parent.parent.parent / 'tools' / 'memprocfs')
py_dir  = os.path.join(mpc_dir, 'python')
import glob as _glob
os.add_dll_directory(mpc_dir)
sys.path.insert(0, mpc_dir)
for z in _glob.glob(os.path.join(py_dir, 'python3*.zip')):
    if z not in sys.path: sys.path.insert(0, z)
if py_dir not in sys.path: sys.path.append(py_dir)

try:
    import vmmpyc
except ImportError as e:
    print(f'ERROR: Cannot import vmmpyc: {e}'); sys.exit(1)

if len(sys.argv) < 4:
    print(f'Usage: vad_query.py <image.aff4> <pid> <hex_address>')
    sys.exit(1)

image   = sys.argv[1]
pid     = int(sys.argv[2])
target  = int(sys.argv[3], 16)

print(f'[*] Opening {image}')
vmm = vmmpyc.Vmm(['-device', image, '-disable-symbolserver', '-disable-python'])

try:
    proc = vmm.process(pid)
except Exception as e:
    print(f'ERROR: PID {pid} not found: {e}'); sys.exit(1)

print(f'[*] PID {pid} = {proc.name}')
print(f'[*] Looking for VAD covering 0x{target:x}')

vads = proc.maps.vad()
match = None
for v in vads:
    start = v.get('start', 0)
    end   = v.get('end', 0)
    if start <= target <= end:
        match = v
        break

if match is None:
    print(f'[-] No VAD covers 0x{target:x} -- address may be in a guard page or unmapped')
    sys.exit(0)

typ  = match.get('type', 'unknown')
prot = match.get('protection', 'unknown')
fn   = match.get('filename', '') or match.get('file', '') or match.get('name', '') or ''
start = match.get('start', 0)
end   = match.get('end', 0)

print(f'[+] Match:')
print(f'    Range : 0x{start:x} - 0x{end:x}  (size {end - start + 1:#x})')
print(f'    Type  : {typ}')
print(f'    Prot  : {prot}')
print(f'    File  : {fn if fn else "<none>"}')
print()

if typ == 'private' or not typ:
    print('[!] ANONYMOUS VAD -- no backing file; check if exec bits are set')
elif typ == 'image':
    print('[+] FILE-BACKED (image) -- this is a loaded PE module (DLL or EXE)')
elif 'file' in typ.lower():
    print('[+] FILE-BACKED -- mapped file; NOT anonymous shellcode exec space')
else:
    print(f'[?] VAD type "{typ}" -- review manually')
