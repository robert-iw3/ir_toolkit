#!/usr/bin/env python3
"""
Generate a large synthetic "stress" file used by test_63_mwcp_parser_performance.py
to catch pathological identify()/run() performance in mwcp parsers before they ship.

This file intentionally combines the specific shapes that have historically triggered
catastrophic-backtracking or O(n^2)/brute-force blowups in this codebase's parsers:
  - Dense runs of base64-like characters (backtracking-prone repeated-group regexes)
  - Thousands of extension-shaped tokens (O(n^2) nested-loop cluster checks)
  - Mixed-case realistic PowerShell/URL text (case-insensitive (?i) regex cost)
  - A large overall size (~10MB) representative of a real carved memory region

Run once; the pytest fixture in test_63 auto-invokes it if the file is absent.
"""
import base64
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'samples', 'perf_stress.bin')


def generate(size_mb: int = 10) -> bytes:
    rng = random.Random(1337)
    chunks = []

    # Dense base64-like runs (no real Blob/smuggling markers -- must stay a TRUE
    # negative for every parser, this file exercises perf only, not detections)
    b64_block = base64.b64encode(rng.randbytes(6000)).decode('ascii')
    chunks.append((b64_block * 200).encode('ascii'))

    # Thousands of extension-shaped tokens interspersed with paths/text
    exts = ['.exe', '.dll', '.ps1', '.txt', '.log', '.json', '.tmp', '.bak', '.cfg', '.ini']
    path_words = ['Users', 'AppData', 'Local', 'Temp', 'ProgramData', 'Roaming', 'System32']
    for _ in range(20000):
        chunks.append(
            f'C:\\{rng.choice(path_words)}\\{rng.choice(path_words)}\\file{rng.randint(1,9999)}'
            f'{rng.choice(exts)} '.encode('ascii'))

    # Mixed-case realistic PowerShell/URL text (stresses (?i) case-folding cost)
    ps_snippets = [
        b'Invoke-WebRequest -Uri "https://Example.COM/Api/V1/Data" -Method Get\n',
        b'$Result = New-Object System.Net.WebClient\n',
        b'Write-Output "Processing Item Number $i Of $Total"\n',
        b'Get-ChildItem -Path C:\\Windows\\System32 -Recurse | Where-Object { $_.Extension -EQ ".DLL" }\n',
        b'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Data))\n',
    ]
    for _ in range(15000):
        chunks.append(rng.choice(ps_snippets))

    data = b''.join(chunks)
    target = size_mb * 1024 * 1024
    if len(data) < target:
        data = data * (target // len(data) + 1)
    return data[:target]


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    data = generate()
    with open(OUT, 'wb') as f:
        f.write(data)
    print(f'{os.path.relpath(OUT, HERE)} ({len(data)} bytes)')


if __name__ == '__main__':
    main()
