"""parser_manifest.yml must never drift from the actual MODULES tuples -- the manifest
is documentation, not a registry, so nothing enforces the two stay in sync except this
test."""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
_WIN_HUNT = os.path.join(_ROOT, "playbooks", "linux", "threat_hunting")
sys.path.insert(0, _WIN_HUNT)

from mwcp_parsers import c2_frameworks, cloud_saas, delivery, native, ransomware, specialized  # noqa: E402

_MANIFEST = os.path.join(_WIN_HUNT, "mwcp_parsers", "parser_manifest.yml")
_CATEGORIES = {
    "c2_frameworks": c2_frameworks, "native": native, "ransomware": ransomware,
    "cloud_saas": cloud_saas, "delivery": delivery, "specialized": specialized,
}


def _parse_manifest_module_names():
    """Minimal YAML reader for this file's specific shape (avoids a PyYAML
    dependency for one small, structurally simple file) -- extracts every
    `module: <name>` value grouped under its top-level category key."""
    out = {}
    current_category = None
    with open(_MANIFEST, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not line.startswith((" ", "\t")) and stripped.endswith(":"):
                current_category = stripped[:-1]
                out.setdefault(current_category, [])
                continue
            if current_category and "module:" in stripped:
                after = stripped.split("module:", 1)[1]
                name = after.split(",", 1)[0].strip().strip("{}").strip()
                out[current_category].append(name)
    return out


def test_manifest_file_exists():
    assert os.path.isfile(_MANIFEST)


# Multi-hit extractors (return a list, not Optional[dict]) documented in the manifest
# under their category but deliberately excluded from that category's single-hit
# MODULES tuple -- driver.py wires them in separately via _MULTI_HIT_EXTRACTORS.
_MULTI_HIT_EXCEPTIONS = {"native": {"smtp_exfil"}}


def test_every_category_in_manifest_matches_modules_tuple():
    manifest = _parse_manifest_module_names()
    for category_name, pkg in _CATEGORIES.items():
        manifest_modules = set(manifest.get(category_name, []))
        manifest_modules -= _MULTI_HIT_EXCEPTIONS.get(category_name, set())
        code_modules = {m.__name__.rsplit(".", 1)[-1] for m in pkg.MODULES}
        assert manifest_modules == code_modules, (
            f"{category_name}: manifest={manifest_modules} vs code={code_modules}")


def test_manifest_has_all_six_categories():
    manifest = _parse_manifest_module_names()
    assert set(manifest.keys()) == set(_CATEGORIES.keys())
